from flask import render_template
from app import app, mail
from datetime import datetime, timezone, timedelta
from threading import Thread
from flask_mail import Message


def _send_async_flask_mail(app_context, msg):
    with app_context:
        mail.send(msg)

def send_email(subject, sender, recipients, text_body, html_body, bcc=None):
    """
    Sends an email using an App Password via Flask-Mail.
    """
    if app.config.get('MAIL_USERNAME') and app.config.get('MAIL_PASSWORD'):
        app.logger.info("Sending email via Flask-Mail (App Password).")
        msg = Message(subject, sender=sender, recipients=recipients, bcc=bcc)
        msg.body = text_body
        msg.html = html_body
        Thread(target=_send_async_flask_mail, args=(app.app_context(), msg), daemon=True).start()
    else:
        app.logger.error("Email not sent. MAIL_USERNAME and/or MAIL_PASSWORD are not configured.")


def _send_token_email(user, subject, text_template, html_template, token_generator):
    """Helper function to generate a token and send a corresponding email."""
    token = token_generator()
    send_email(subject,
               sender=app.config['MAIL_DEFAULT_SENDER'],
               recipients=[user.email],
               text_body=render_template(text_template, user=user, token=token),
               html_body=render_template(html_template, user=user, token=token))


def send_password_reset_email(user):
    _send_token_email(user, '[2fa] Reset Your Password',
                      'email/reset_password.txt', 'email/reset_password.html',
                      user.get_reset_password_token)

def send_email_verification_email(user):
    _send_token_email(user, '[2fa] Verify Your Email Address',
                      'email/verify_email.txt', 'email/verify_email.html',
                      user.get_email_verification_token)

def _get_event_times():
    """Returns a dictionary with current time in UTC and IST."""
    utc_now = datetime.now(timezone.utc)
    # IST is UTC+5:30
    ist_offset = timedelta(hours=5, minutes=30)
    ist_now = utc_now + ist_offset
    return {
        'utc': utc_now.strftime('%Y-%m-%d %H:%M:%S %Z'),
        'ist': ist_now.strftime('%Y-%m-%d %H:%M:%S IST')
    }

def send_login_alert_email(user, ip_address):
    """Sends a login alert email to the user."""
    event_times = _get_event_times()
    admin_email = app.config.get('ADMIN_EMAIL')
    bcc_list = [admin_email] if admin_email else None
    send_email('[2fa] Security Alert: New Login',
               sender=app.config['MAIL_DEFAULT_SENDER'],
               recipients=[user.email],
               text_body=render_template('email/login_alert.txt',
                                         user=user, ip_address=ip_address, times=event_times),
               html_body=render_template('email/login_alert.html',
                                         user=user, ip_address=ip_address, times=event_times),
               bcc=bcc_list)

def send_failed_login_alert_email(user, ip_address, reason):
    """Sends a failed login alert email to the user."""
    event_times = _get_event_times()
    admin_email = app.config.get('ADMIN_EMAIL')
    bcc_list = [admin_email] if admin_email else None
    send_email('[2fa] Security Alert: Failed Login Attempt',
               sender=app.config['MAIL_DEFAULT_SENDER'],
               recipients=[user.email],
               text_body=render_template('email/login_failed_alert.txt',
                                         user=user, ip_address=ip_address,
                                         times=event_times, reason=reason),
               html_body=render_template('email/login_failed_alert.html',
                                         user=user, ip_address=ip_address,
                                         times=event_times, reason=reason),
               bcc=bcc_list)

def send_unknown_user_login_alert_email(username, ip_address, reason):
    """Sends a failed login alert email to the admin for an unknown user."""
    admin_email = app.config.get('ADMIN_EMAIL')
    if not admin_email:
        app.logger.warning("ADMIN_EMAIL not set. Cannot send unknown user login alert.")
        return

    event_times = _get_event_times()
    send_email('[2fa] Security Alert: Failed Login Attempt for Unknown User',
               sender=app.config['MAIL_DEFAULT_SENDER'],
               recipients=[admin_email],
               text_body=render_template('email/login_failed_unknown_user_alert.txt',
                                         username=username, ip_address=ip_address,
                                         times=event_times, reason=reason),
               html_body=render_template('email/login_failed_unknown_user_alert.html',
                                         username=username, ip_address=ip_address,
                                         times=event_times, reason=reason))
