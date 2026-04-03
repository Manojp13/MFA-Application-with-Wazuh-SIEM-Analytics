from app import login, app, db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
import os
import secrets
from datetime import datetime, timezone
import base64
import onetimepass
from time import time
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(64), nullable=False)
    last_name = db.Column(db.String(64), nullable=False)
    username = db.Column(db.String(64), index=True, unique=True, nullable=False)
    email = db.Column(db.String(120), index=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    email_verified = db.Column(db.Boolean, default=False)
    blocked = db.Column(db.Boolean, default=False)
    api_key = db.Column(db.String(128), unique=True, nullable=True)
    api_key_generation_time = db.Column(db.DateTime, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    otp_secret = db.Column(db.String(32), nullable=False, default=lambda: base64.b32encode(os.urandom(10)).decode('utf-8'))

    # Relationships
    notes = db.relationship('Note', backref='author', lazy='dynamic', cascade="all, delete-orphan")
    files = db.relationship('File', backref='owner', lazy='dynamic', cascade="all, delete-orphan")

    @staticmethod
    def get_by_id(user_id):
        return db.session.get(User, int(user_id))

    @staticmethod
    def get_by_username(username):
        return User.query.filter_by(username=username).first()

    @staticmethod
    def get_by_email(email):
        return User.query.filter_by(email=email).first()

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_totp_uri(self):
        return 'otpauth://totp/2FA-Demo:{0}?secret={1}&issuer=2FA-Demo' \
            .format(self.username, self.otp_secret)

    def verify_totp(self, token):
        # The 'window' parameter allows for a greater time drift between the
        # server and the client's authenticator app. A window of 1 allows for
        # a tolerance of 1 * 30 seconds. We use a window of 2 for a 60-second
        # tolerance to be more resilient to minor clock skew.
        is_valid = onetimepass.valid_totp(token, self.otp_secret, window=2)

        # Add detailed logging for debugging time-skew issues
        if not is_valid and app.debug:
            server_token = onetimepass.get_totp(self.otp_secret)
            app.logger.debug(f"TOTP verification failed for user '{self.username}'.")
            app.logger.debug(f"  - Token provided by user: {token}")
            app.logger.debug(f"  - Token expected by server: {server_token}")
            app.logger.debug(f"  - Server time (UTC): {datetime.now(timezone.utc)}")
            app.logger.debug("  - Tip: Ensure the server's clock is synchronized with a time server (NTP).")

        return is_valid

    def _generate_token(self, payload_key, expires_in):
        """Generates a JWT token for a specific purpose."""
        return jwt.encode(
            {payload_key: self.id, 'exp': time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256'
        )

    @staticmethod
    def _verify_token(token, payload_key):
        """Verifies a JWT token and returns a user if valid."""
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'],
                                 algorithms=['HS256'])
            user_id = payload.get(payload_key)
            if not user_id:
                return None
        except (ExpiredSignatureError, InvalidTokenError, KeyError):
            return None
        return User.get_by_id(user_id)

    def get_reset_password_token(self, expires_in=600):
        return self._generate_token('reset_password', expires_in)

    @staticmethod
    def verify_reset_password_token(token):
        return User._verify_token(token, 'reset_password')

    def get_email_verification_token(self, expires_in=3600):
        return self._generate_token('verify_email', expires_in)

    @staticmethod
    def verify_email_verification_token(token):
        return User._verify_token(token, 'verify_email')

    def generate_api_key(self):
        """Generates a new API key for the user."""
        self.api_key = secrets.token_urlsafe(32)
        self.api_key_generation_time = datetime.now(timezone.utc)

    def revoke_api_key(self):
        """Revokes the user's API key."""
        self.api_key = None
        self.api_key_generation_time = None

    @staticmethod
    def check_api_key(api_key):
        """Finds a user by their API key."""
        return User.query.filter_by(api_key=api_key).first() if api_key else None

@login.user_loader
def load_user(id):
    return User.get_by_id(id)


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(140))
    content = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return f'<Note {self.title}>'


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256))
    file_path = db.Column(db.String(512), unique=True)  # Changed from storage_path to file_path
    content_type = db.Column(db.String(128))
    upload_timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return f'<File {self.filename}>'
