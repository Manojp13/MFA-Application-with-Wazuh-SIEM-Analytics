from flask import render_template, redirect, url_for, flash, request, session,\
    abort, jsonify, send_from_directory, Markup
from io import BytesIO

import uuid
import pyqrcode
from urllib.parse import urlparse as url_parse
from werkzeug.utils import secure_filename
from flask_login import login_user, logout_user, current_user, login_required, AnonymousUserMixin
from app.models import User, File, Note
from app.forms import LoginForm, RegistrationForm, ResetPasswordRequestForm, ResetPasswordForm, FileUploadForm, NoteForm, ResendVerificationForm, PasswordValidationMixin
from app.email import send_password_reset_email, send_email_verification_email, send_login_alert_email, send_failed_login_alert_email, send_unknown_user_login_alert_email
from flask_jwt_extended import JWTManager, create_access_token, get_jwt, get_jwt_identity, jwt_required
from datetime import datetime, timedelta, timezone
import json
from flask_jwt_extended.exceptions import NoAuthorizationError, InvalidHeaderError
from app import app, db
from flask import jsonify as flask_jsonify
from app import jwt
from flask import g, request
import os  # Need to import 'os' for file operations
import telegram
from telegram.utils.helpers import escape_markdown
from app.telegram import send_admin_telegram_alert
# Add error handlers for JWT errors
@jwt.invalid_token_loader
def invalid_token_callback(error_string):
    app.logger.error(f"Invalid token error: {error_string}")
    return flask_jsonify({"msg": "Invalid token"}), 401

@jwt.unauthorized_loader
def missing_token_callback(error_string):
    app.logger.error(f"Missing token error: {error_string}")
    return flask_jsonify({"msg": "Missing token"}), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    identity = jwt_payload.get('sub')
    app.logger.warning(f"Expired token used for identity: {identity}", extra={
        'event': 'jwt_error', 'reason': 'expired_token', 'user_id': identity
    })
    return flask_jsonify({"msg": "Token has expired"}), 401

@jwt.needs_fresh_token_loader
def needs_fresh_token_callback(jwt_header, jwt_payload):
    identity = jwt_payload.get('sub')
    app.logger.info(f"Non-fresh token used for identity: {identity}", extra={
        'event': 'jwt_error', 'reason': 'fresh_token_required', 'user_id': identity
    })
    return flask_jsonify({"msg": "Fresh token required"}), 401

@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    identity = jwt_payload.get('sub')
    app.logger.critical(f"Revoked token used for identity: {identity}", extra={
        'event': 'jwt_error', 'reason': 'revoked_token', 'user_id': identity
    })
    return flask_jsonify({"msg": "Token has been revoked"}), 401

@app.route('/')
@app.route('/home')
@login_required
def home():
    app.logger.info(f"User '{current_user.username}' accessed the home page.", extra={
        'event': 'page_access',
        'status': 'success',
        'page': 'home'
    })
    return render_template('home.html', title='Home', user=current_user)


@app.before_request
def check_blocked_user():
    """Logs out a user if their account has been blocked."""
    if current_user.is_authenticated and hasattr(current_user, 'blocked') and current_user.blocked:
        logout_user()
        flash('Your account has been blocked. Please contact an administrator.', 'danger')
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if not form.validate_on_submit():
        return render_template('login.html', title='Login', form=form)

    def _log_and_flash_failure(reason, username, user=None, flash_message=None):
        user_id_for_log = user.id if user else 'N/A'
        app.logger.warning(f"Failed login attempt: {reason} for username={username}", extra={
            'event': 'login_attempt',
            'status': 'failed',
            'user_identity': username,
            'username': username,
            'reason': reason,
            'user_id': user_id_for_log,
            'session_time': 'N/A'
        })
        flash(flash_message or 'Invalid username or password')

        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        utc_now = datetime.now(timezone.utc)
        ist_now = utc_now + timedelta(hours=5, minutes=30)
        event_time_ist = ist_now.strftime('%Y-%m-%d %H:%M:%S IST')
        event_time_utc = utc_now.strftime('%Y-%m-%d %H:%M:%S %Z')
        reason_escaped = escape_markdown(reason)
        ip_address_escaped = escape_markdown(ip_address)

        # If we have a user object, send an alert to the user and admin.
        if user and user.email:
            send_failed_login_alert_email(user, ip_address, reason)
            # Send Telegram alert for failed login
            username_escaped = escape_markdown(user.username)
            telegram_message = (f"🚨 *Failed Login Attempt*\n\n"
                                f"*Username:* `{username_escaped}`\n"
                                f"*Reason:* {reason_escaped}\n"
                                f"*IP Address:* `{ip_address_escaped}`\n"
                                f"*Time:* `{event_time_ist} ({event_time_utc})`")
            send_admin_telegram_alert(telegram_message)
        # If the user does not exist, send an alert only to the admin.
        elif not user:
            send_unknown_user_login_alert_email(username, ip_address, reason)
            # Send Telegram alert for failed login with an unknown user
            username_escaped = escape_markdown(username)
            telegram_message = (f"🚨 *Failed Login Attempt (Unknown User)*\n\n"
                                f"*Attempted Username:* `{username_escaped}`\n"
                                f"*Reason:* {reason_escaped}\n"
                                f"*IP Address:* `{ip_address_escaped}`\n"
                                f"*Time:* `{event_time_ist} ({event_time_utc})`")
            send_admin_telegram_alert(telegram_message)


    # --- Start of Login Validation ---

    user = User.get_by_username(form.username.data)

    # 1. Check for user existence first. If user does not exist, we log but send no alert.
    if not user:
        _log_and_flash_failure("invalid username", form.username.data)
        return redirect(url_for('login'))

    # From this point on, we have a valid user object, so we can send alerts on subsequent failures.

    # 2. Check password
    if not user.check_password(form.password.data):
        _log_and_flash_failure("invalid password", user.username, user=user)
        return redirect(url_for('login'))

    # 3. Check if the user is blocked.
    if user.blocked:
        _log_and_flash_failure("user is blocked", user.username, user=user, flash_message='Your account has been blocked due to suspicious activity. Please contact support.')
        return redirect(url_for('login'))

    # 4. Check for a valid TOTP token.
    if not user.verify_totp(form.token.data):
        _log_and_flash_failure("invalid TOTP token", user.username, user=user, flash_message='Invalid TOTP token')
        return redirect(url_for('login'))

    # 5. Check for email verification (admins are exempt).
    if not user.email_verified and not user.is_admin:
        resend_url = url_for('resend_verification_request')
        flash_message = Markup(
            'Your email address has not been verified. '
            f'<a href="{resend_url}" class="alert-link">Click here to resend the verification email.</a>'
        )
        _log_and_flash_failure("email not verified", user.username, user=user, flash_message=flash_message)
        return redirect(url_for('login'))

    # --- Success Path ---
    # If all checks pass, log the user in.
    login_user(user, remember=form.remember_me.data)
    login_time_iso = datetime.utcnow().isoformat()
    session['login_time'] = login_time_iso
    app.logger.info(f"Successful login for username={user.username}", extra={
        'event': 'login_attempt',
        'status': 'success',
        'user_id': getattr(user, 'id', 'N/A'),
        'username': user.username,
        'login_time': login_time_iso
    })

    # Send login alert email. Use X-Forwarded-For if behind a proxy.
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    send_login_alert_email(user, ip_address)
    # Send Telegram alert for successful login
    username_escaped = escape_markdown(user.username)
    ip_address_escaped = escape_markdown(ip_address)
    utc_now = datetime.now(timezone.utc)
    ist_now = utc_now + timedelta(hours=5, minutes=30)
    event_time_ist = ist_now.strftime('%Y-%m-%d %H:%M:%S IST')
    event_time_utc = utc_now.strftime('%Y-%m-%d %H:%M:%S %Z')
    telegram_message = (f"✅ *Successful Login*\n\n"
                        f"*Username:* `{username_escaped}`\n"
                        f"*IP Address:* `{ip_address_escaped}`\n"
                        f"*Time:* `{event_time_ist} ({event_time_utc})`")
    send_admin_telegram_alert(telegram_message)

    next_page = request.args.get('next')
    if not next_page or url_parse(next_page).netloc != '':
        next_page = url_for('home')
    return redirect(next_page)

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.get_by_email(form.email.data)
        if user:
            send_password_reset_email(user)
            # Send Telegram alert for password reset request
            username_escaped = escape_markdown(user.username)
            ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
            ip_address_escaped = escape_markdown(ip_address)
            telegram_message = (f"🔑 *Password Reset Requested*\n\n"
                                f"*Username:* `{username_escaped}`\n"
                                f"*IP Address:* `{ip_address_escaped}`")
            send_admin_telegram_alert(telegram_message)

        flash('Check your email for the instructions to reset your password', 'info')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html',
                           title='Reset Password',
                           form=form
                           )
@app.route('/resend_verification_request', methods=['GET', 'POST'])
def resend_verification_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = ResendVerificationForm()
    if form.validate_on_submit():
        user = User.get_by_email(form.email.data)
        # To prevent user enumeration, always show a generic message.
        # Only send an email if the user exists and is not yet verified.
        if user and not user.email_verified and not user.is_admin:
            send_email_verification_email(user)
        flash('If that email address is in our system and requires verification, a new email has been sent.', 'info')
        return redirect(url_for('login'))
    return render_template('resend_verification_request.html',
                           title='Resend Verification',
                           form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('login'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        # Commit the password change to the database
        db.session.commit()
        app.logger.info(f"User successfully reset password: username={user.username}", extra={
            'event': 'password_reset',
            'status': 'success',
            'user_identity': user.username,
            'username': user.username,
            'user_id': user.id,
            'session_time': 'N/A'
        })

        # Send Telegram alert for successful password reset
        username_escaped = escape_markdown(user.username)
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        ip_address_escaped = escape_markdown(ip_address)
        telegram_message = (f"🔑 *Password Reset Successful*\n\n"
                            f"*Username:* `{username_escaped}`\n"
                            f"*IP Address:* `{ip_address_escaped}`")
        send_admin_telegram_alert(telegram_message)
        flash('Your password has been reset.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html',
                           title='Reset Password',
                           form=form
                           )


@app.route('/telegram/webhook/<token>', methods=['POST'])
def telegram_webhook(token):
    """Webhook to receive updates from Telegram."""
    bot_token = app.config.get('TELEGRAM_BOT_TOKEN')
    if not bot_token or token != bot_token:
        app.logger.error("Telegram webhook called with an invalid or missing token.")
        abort(403)
    
    bot = app.telegram_bot
    if not bot:
        app.logger.error("Telegram webhook called but bot is not configured.")
        return "error", 500
        
    update = telegram.Update.de_json(request.get_json(force=True), bot)

    if update and update.message:
        chat_id = update.message.chat.id
        text = (
            "Hello! This bot is for system notifications only.\n\n"
            f"Your Chat ID is: `{chat_id}`\n\n"
            "To receive admin alerts, set this ID in the `TELEGRAM_ADMIN_CHAT_ID` environment variable."
        )
        bot.send_message(chat_id=chat_id, text=text, parse_mode=telegram.ParseMode.MARKDOWN)

    return "ok", 200

@app.route('/verify_email/<token>', methods=['GET'])
def verify_email(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_email_verification_token(token)
    if not user:
        flash('The email verification link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))
    user.email_verified = True
    db.session.commit()

    # Send Telegram alert for email verification
    username_escaped = escape_markdown(user.username)
    telegram_message = (f"📧 *Email Verified*\n\n"
                        f"*Username:* `{username_escaped}`")
    send_admin_telegram_alert(telegram_message)

    flash('Thank you for verifying your email address. You can now log in.', 'success')
    return redirect(url_for('login'))


@app.route('/logout')
def logout():
    if current_user.is_authenticated:
        user_logging_out = current_user
        session_time = 'N/A'
        if 'login_time' in session:
            try:
                login_time = datetime.fromisoformat(session['login_time'])
                session_time = str(datetime.utcnow() - login_time)
            except Exception:
                pass

        # Send Telegram alert for logout
        username_escaped = escape_markdown(user_logging_out.username)
        utc_now = datetime.now(timezone.utc)
        ist_now = utc_now + timedelta(hours=5, minutes=30)
        event_time_ist = ist_now.strftime('%Y-%m-%d %H:%M:%S IST')
        event_time_utc = utc_now.strftime('%Y-%m-%d %H:%M:%S %Z')
        telegram_message = (f"🔒 *User Logout*\n\n*Username:* `{username_escaped}`\n"
                            f"*Time:* `{event_time_ist} ({event_time_utc})`")
        send_admin_telegram_alert(telegram_message)

        app.logger.info(f"User logout: username={user_logging_out.username}", extra={
            'event': 'logout',
            'status': 'success',
            'user_id': user_logging_out.id,
            'username': user_logging_out.username,
            'session_time': session_time,
            'logout_time': datetime.utcnow().isoformat()
        })
        logout_user()
        session.pop('login_time', None)
    return redirect(url_for('login'))
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            username=form.username.data,
            email=form.email.data
        )
        user.set_password(form.password.data)

        # Make the first registered user an admin
        if User.query.count() == 0:
            user.is_admin = True
            app.logger.info(f"First user '{user.username}' automatically promoted to admin.")

        db.session.add(user)
        db.session.commit()

        app.logger.info(f"New user registration: username={user.username}, email={user.email}", extra={
            'event': 'registration',
            'status': 'success',
            'username': user.username,
            'email': user.email,
            'user_id': user.id
        })
        send_email_verification_email(user)

        # Send Telegram alert for new registration
        username_escaped = escape_markdown(user.username)
        email_escaped = escape_markdown(user.email)
        telegram_message = (f"👤 *New User Registration*\n\n"
                            f"*Username:* `{username_escaped}`\n"
                            f"*Email:* `{email_escaped}`")
        send_admin_telegram_alert(telegram_message)

        session['username'] = user.username
        flash('A verification email has been sent to your address. You must also scan the QR code below to set up 2FA.', 'info')
        return redirect(url_for('two_factor_setup'))
    return render_template('register.html',
                           title='Register',
                           form=form
                           )


@app.route('/twofactor')
def two_factor_setup():
    app.logger.info(f"Session contents in two_factor_setup: {dict(session)}")
    if 'username' not in session:
        app.logger.info("Username not found in session, redirecting to home")
        return redirect(url_for('home'))
    user = User.get_by_username(session['username'])
    if user is None:
        app.logger.info("User not found, redirecting to home")
        return redirect(url_for('home'))
    return render_template('two_factor_setup.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
    }


@app.route('/qrcode')
def qrcode():
    if 'username' not in session:
        abort(404)
    user = User.get_by_username(session['username'])
    if user is None:
        abort(404)

    # remove username from session for added security, and also user_id
    del session['username']

    # render qrcode from FreeOTP
    url = pyqrcode.create(user.get_totp_uri())
    stream = BytesIO()


    url.svg(stream, scale=5)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
    }


@app.route('/files', methods=['GET', 'POST'])
@login_required
def files():
    form = FileUploadForm()
    if form.validate_on_submit():
        f = form.file.data
        filename = secure_filename(f.filename)
        
        # Create a unique filename to prevent collisions
        unique_filename = f"{uuid.uuid4()}_{filename}"
        
        # Save the file to the local 'uploads' directory
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        f.save(file_path)

        # Store the relative path (just the unique filename) in the database
        relative_path = unique_filename
        # Save metadata to SQLite
        new_file = File(filename=filename, file_path=relative_path,
                        content_type=f.content_type, owner=current_user)
        db.session.add(new_file)
        db.session.commit()

        app.logger.info(
            f"User '{current_user.username}' uploaded file '{filename}'",
            extra={
                'event': 'file_operation',
                'action': 'upload',
                'status': 'success',
                'file_name': filename,
                'file_id': new_file.id
            }
        )

        # Send Telegram alert for file upload
        username_escaped = escape_markdown(current_user.username)
        filename_escaped = escape_markdown(filename)
        telegram_message = (f"📄 *File Uploaded*\n\n"
                            f"*User:* `{username_escaped}`\n"
                            f"*Filename:* `{filename_escaped}`")
        send_admin_telegram_alert(telegram_message)
        flash('Your file has been uploaded successfully.', 'success')
        return redirect(url_for('files'))

    # Fetch user's files to display on the page
    user_files = current_user.files.order_by(File.upload_timestamp.desc()).all()

    return render_template('files.html', title='My Files', form=form, files=user_files)


@app.route('/files/<file_id>/download')
@login_required
def download_file(file_id):
    file_record = File.query.get_or_404(file_id)

    if not file_record:
        abort(404)
    
    # Authorization check: only the owner or an admin can download
    if file_record.owner.id != current_user.id and not current_user.is_admin:
        abort(403)  # Forbidden

    # Send Telegram alert for file download
    username_escaped = escape_markdown(current_user.username)
    filename_escaped = escape_markdown(file_record.filename)
    telegram_message = (f"📄 *File Downloaded*\n\n"
                        f"*User:* `{username_escaped}`\n"
                        f"*Filename:* `{filename_escaped}`")
    send_admin_telegram_alert(telegram_message)

    # The file_path in the database is now relative to the UPLOAD_FOLDER
    upload_folder = app.config['UPLOAD_FOLDER']
    if not os.path.exists(os.path.join(upload_folder, file_record.file_path)):
        app.logger.error(f"File not found on disk: {os.path.join(upload_folder, file_record.file_path)}")
        abort(404)

    # Use send_from_directory with the UPLOAD_FOLDER and the relative path
    return send_from_directory(upload_folder, file_record.file_path, as_attachment=True)


@app.route('/files/<file_id>/delete', methods=['POST'])
@login_required
def delete_file(file_id):
    file_record = File.query.get_or_404(file_id)

    # Authorization check: only the owner or an admin can delete
    if file_record.owner.id != current_user.id and not current_user.is_admin:
        abort(403)  # Forbidden

    try:
        absolute_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record.file_path)
        # 1. Delete the physical file from the filesystem
        if os.path.exists(absolute_path):
            os.remove(absolute_path)
        else:
            app.logger.warning(
                f"Physical file not found for deletion, but proceeding to delete DB record for file ID {file_id}",
                extra={
                    'event': 'file_operation',
                    'action': 'delete',
                    'status': 'warning',
                    'reason': 'physical_file_not_found',
                    'file_id': file_id
                }
            )

        # 2. Delete the file record from the database
        original_filename = file_record.filename
        db.session.delete(file_record)
        db.session.commit()

        app.logger.info(
            f"User '{current_user.username}' deleted file '{original_filename}'",
            extra={
                'event': 'file_operation',
                'action': 'delete',
                'status': 'success',
                'file_name': original_filename,
                'file_id': file_id
            }
        )

        # Send Telegram alert for file deletion
        username_escaped = escape_markdown(current_user.username)
        filename_escaped = escape_markdown(original_filename)
        telegram_message = (f"🗑️ *File Deleted*\n\n"
                            f"*User:* `{username_escaped}`\n"
                            f"*Filename:* `{filename_escaped}`")
        send_admin_telegram_alert(telegram_message)
        flash(f"File '{original_filename}' has been deleted.", 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting file {file_id}", extra={
            'event': 'file_operation', 'action': 'delete', 'status': 'failed',
            'file_id': file_id, 'reason': str(e)
        })
        flash('Error deleting file. Please try again.', 'danger')

    return redirect(url_for('files'))

@app.route('/notes', methods=['GET', 'POST'])
@login_required
def notes():
    form = NoteForm()
    if form.validate_on_submit():
        # Save the new note to SQLite
        new_note = Note(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(new_note)
        db.session.commit()
        flash('Your note has been saved.', 'success')
        return redirect(url_for('notes'))

    # Fetch user's notes to display
    user_notes = current_user.notes.order_by(Note.timestamp.desc()).all()

    return render_template('notes.html', title='My Notes', form=form, notes=user_notes)


@app.route('/notes/<note_id>')
@login_required
def view_note(note_id):
    note = Note.query.get_or_404(note_id)

    # Authorization check
    if note.user_id != current_user.id and not current_user.is_admin:
        abort(403)

    return render_template('note.html', title=note.title, note=note)


@app.route('/notes/<note_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_note(note_id):
    note = Note.query.get_or_404(note_id)

    # Authorization check
    if note.user_id != current_user.id and not current_user.is_admin:
        abort(403)

    form = NoteForm(obj=note)
    if form.validate_on_submit():
        note.title = form.title.data
        note.content = form.content.data
        note.timestamp = datetime.utcnow()
        db.session.commit()
        flash('Your note has been updated.', 'success')
        return redirect(url_for('view_note', note_id=note_id))

    return render_template('edit_note.html', title='Edit Note', form=form)


@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        abort(403) # Forbidden

    page = request.args.get('page', 1, type=int)
    # Paginate the user query to fetch users page by page
    users_pagination = User.query.order_by(User.id.asc()).paginate(page=page, per_page=10, error_out=False)
    users = users_pagination.items

    return render_template('admin.html', title='Admin Dashboard', users=users, pagination=users_pagination)


@app.route('/admin/verify_email/<user_id>', methods=['POST'])
@login_required
def admin_verify_email(user_id):
    if not current_user.is_admin:
        abort(403)

    user_to_verify = User.get_by_id(user_id)
    if not user_to_verify:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_dashboard'))

    user_to_verify.email_verified = True
    db.session.commit()

    app.logger.info(f"Admin '{current_user.username}' manually verified email for user '{user_to_verify.username}'.", extra={
        'event': 'user_management',
        'action': 'admin_verify_email',
        'target_user': user_to_verify.username
    })

    # Send Telegram alert for admin action
    admin_username_escaped = escape_markdown(current_user.username)
    target_username_escaped = escape_markdown(user_to_verify.username)
    telegram_message = (f"🛡️ *Admin Action: Email Verified*\n\n"
                        f"*Admin:* `{admin_username_escaped}`\n"
                        f"*Target User:* `{target_username_escaped}`")
    send_admin_telegram_alert(telegram_message)

    flash(f"Email for user '{user_to_verify.username}' has been successfully verified.", 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/block_user/<user_id>', methods=['POST'])
@login_required
def block_user(user_id):
    if not current_user.is_admin:
        abort(403)
    user_to_block = User.get_by_id(user_id)
    if not user_to_block:
        flash('User not found.', 'danger')
    elif user_to_block.is_admin:
        flash('Cannot block an admin user.', 'danger')
    else:
        user_to_block.blocked = True
        db.session.commit()
        app.logger.warning(f"Admin '{current_user.username}' blocked user '{user_to_block.username}'.", extra={
            'event': 'user_management',
            'action': 'block_user',
            'status': 'success',
            'target_user': user_to_block.username
        })

        # Send Telegram alert for admin action
        admin_username_escaped = escape_markdown(current_user.username)
        target_username_escaped = escape_markdown(user_to_block.username)
        telegram_message = (f"🛡️ *Admin Action: User Blocked*\n\n"
                            f"*Admin:* `{admin_username_escaped}`\n"
                            f"*Target User:* `{target_username_escaped}`")
        send_admin_telegram_alert(telegram_message)
        flash(f"User '{user_to_block.username}' has been blocked.", 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/unblock_user/<user_id>', methods=['POST'])
@login_required
def unblock_user(user_id):
    if not current_user.is_admin:
        abort(403)
    user_to_unblock = User.get_by_id(user_id)
    if not user_to_unblock:
        flash('User not found.', 'danger')
    else:
        user_to_unblock.blocked = False
        db.session.commit()
        app.logger.info(f"Admin '{current_user.username}' unblocked user '{user_to_unblock.username}'.", extra={
            'event': 'user_management',
            'action': 'unblock_user',
            'status': 'success',
            'target_user': user_to_unblock.username
        })

        # Send Telegram alert for admin action
        admin_username_escaped = escape_markdown(current_user.username)
        target_username_escaped = escape_markdown(user_to_unblock.username)
        telegram_message = (f"🛡️ *Admin Action: User Unblocked*\n\n"
                            f"*Admin:* `{admin_username_escaped}`\n"
                            f"*Target User:* `{target_username_escaped}`")
        send_admin_telegram_alert(telegram_message)
        flash(f"User '{user_to_unblock.username}' has been unblocked.", 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/generate_api_key/<user_id>', methods=['POST'])
@login_required
def generate_api_key(user_id):
    if not current_user.is_admin:
        abort(403)
    user = User.get_by_id(user_id)
    if not user:
        flash('User not found.', 'danger')
    else:
        user.generate_api_key()
        db.session.commit()
        app.logger.info(f"Admin '{current_user.username}' generated a new API key for user '{user.username}'.", extra={
            'event': 'user_management',
            'action': 'generate_api_key',
            'status': 'success',
            'target_user': user.username
        })

        # Send Telegram alert for admin action
        admin_username_escaped = escape_markdown(current_user.username)
        target_username_escaped = escape_markdown(user.username)
        telegram_message = (f"🛡️ *Admin Action: API Key Generated*\n\n"
                            f"*Admin:* `{admin_username_escaped}`\n"
                            f"*Target User:* `{target_username_escaped}`")
        send_admin_telegram_alert(telegram_message)
        flash(f"A new API key has been generated for '{user.username}'.", 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/revoke_api_key/<user_id>', methods=['POST'])
@login_required
def revoke_api_key(user_id):
    if not current_user.is_admin:
        abort(403)
    user = User.get_by_id(user_id)
    if not user:
        flash('User not found.', 'danger')
    else:
        user.revoke_api_key()
        db.session.commit()
        app.logger.warning(f"Admin '{current_user.username}' revoked the API key for user '{user.username}'.", extra={
            'event': 'user_management',
            'action': 'revoke_api_key',
            'status': 'success',
            'target_user': user.username
        })

        # Send Telegram alert for admin action
        admin_username_escaped = escape_markdown(current_user.username)
        target_username_escaped = escape_markdown(user.username)
        telegram_message = (f"🛡️ *Admin Action: API Key Revoked*\n\n"
                            f"*Admin:* `{admin_username_escaped}`\n"
                            f"*Target User:* `{target_username_escaped}`")
        send_admin_telegram_alert(telegram_message)
        flash(f"The API key for '{user.username}' has been revoked.", 'success')
    return redirect(url_for('admin_dashboard'))
@app.route('/admin/delete_user/<user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        abort(403)

    user_to_delete = User.get_by_id(user_id)

    if not user_to_delete:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_dashboard'))

    if user_to_delete.id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin_dashboard'))

    if user_to_delete.is_admin:
        flash('Cannot delete an admin user.', 'danger')
        return redirect(url_for('admin_dashboard'))

    try:
        deleted_username = user_to_delete.username
        
        # Log the critical action before performing it
        app.logger.critical(f"Admin '{current_user.username}' initiated deletion of user '{deleted_username}'.", extra={
            'event': 'user_management',
            'action': 'delete_user',
            'status': 'success', # Log as success since the action is committed
            'target_user': deleted_username
        })

        # Send Telegram alert for admin action
        admin_username_escaped = escape_markdown(current_user.username)
        target_username_escaped = escape_markdown(deleted_username)
        telegram_message = (f"🗑️ *CRITICAL: User Deleted*\n\n"
                            f"*Admin:* `{admin_username_escaped}`\n"
                            f"*Deleted User:* `{target_username_escaped}`")
        send_admin_telegram_alert(telegram_message)

        # Delete associated physical files. The DB records for files and notes
        # are handled by the `cascade="all, delete-orphan"` in the User model.
        for file_record in user_to_delete.files:
            try:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record.file_path)
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception as e:
                app.logger.error(f"Could not delete physical file {file_record.file_path} for user {deleted_username}: {e}")

        db.session.delete(user_to_delete)
        db.session.commit()

        flash(f"User '{deleted_username}' and all associated data have been permanently deleted.", 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Failed to delete user {user_to_delete.username}: {e}", exc_info=True)
        flash('An error occurred while deleting the user.', 'danger')

    return redirect(url_for('admin_dashboard'))

@app.route('/api/qrcode', methods=['GET'])
@jwt_required()
def api_qrcode():
    current_user_id = get_jwt_identity()
    user = User.get_by_id(current_user_id)
    if user is None:
        abort(404)
    url = pyqrcode.create(user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=5)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
    }


@app.route('/api/login', methods=['POST'])
def api_login():
    if not request.is_json:
        app.logger.warning("API login attempt with missing JSON.", extra={
            'event': 'api_login', 'status': 'failed', 'reason': 'missing_json'
        })
        return jsonify({"msg": "Missing JSON in request"}), 400
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    token = request.json.get('token', None)
    if not username or not password or not token:
        app.logger.warning(f"API login attempt with missing credentials for username: {username}", extra={
            'event': 'api_login', 'status': 'failed', 'reason': 'missing_credentials', 'user_identity': username, 'username': username
        })
        return jsonify({"msg": "Missing username, password or token"}), 400
    user = User.get_by_username(username)
    if not user or not user.check_password(password) or not user.verify_totp(token):
        app.logger.warning(f"Failed API login attempt for username: {username}", extra={
            'event': 'api_login', 'status': 'failed', 'reason': 'invalid_credentials', 'user_identity': username, 'username': username
        })

        # Send Telegram alert for failed API login
        username_escaped = escape_markdown(username)
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        ip_address_escaped = escape_markdown(ip_address)
        telegram_message = (f"🚨 *Failed API Login Attempt*\n\n"
                            f"*Username:* `{username_escaped}`\n"
                            f"*IP Address:* `{ip_address_escaped}`")
        send_admin_telegram_alert(telegram_message)
        return jsonify({"msg": "Bad username, password or token"}), 401

    # If all checks pass, create and return the token
    access_token = create_access_token(identity=str(user.id), expires_delta=timedelta(minutes=30), fresh=True)
    app.logger.info(f"Successful API login for username: {user.username}", extra={
        'event': 'api_login', 'status': 'success', 'user_id': user.id, 'username': user.username
    })
    # Send Telegram alert for successful API login
    username_escaped = escape_markdown(user.username)
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    ip_address_escaped = escape_markdown(ip_address)
    telegram_message = (f"✅ *Successful API Login*\n\n"
                        f"*Username:* `{username_escaped}`\n"
                        f"*IP Address:* `{ip_address_escaped}`")
    send_admin_telegram_alert(telegram_message)
    return jsonify(access_token=access_token), 200


@app.route('/api/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    app.logger.debug(f"API access: JWT identity is {current_user_id}")
    claims = get_jwt()
    app.logger.debug(f"API access: JWT claims are {claims}")
    user = User.get_by_id(current_user_id)
    if not user:
        app.logger.warning(f"API access: User not found for JWT identity {current_user_id}")
        return jsonify({"msg": "User not found"}), 404
    return jsonify(logged_in_as=user.username), 200
