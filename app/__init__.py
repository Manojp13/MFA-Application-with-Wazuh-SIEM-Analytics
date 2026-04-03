from flask import Flask
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_migrate import Migrate
import logging
import telegram
from config import Config
import warnings

warnings.filterwarnings("ignore", category=UserWarning, module='telegram.utils.request')

import logging
import os
import platform
from logging.handlers import RotatingFileHandler, SysLogHandler
from pythonjsonlogger import jsonlogger
from flask_jwt_extended import JWTManager

# --- Logging Configuration ---

# Determine the absolute path for the log directory to avoid issues with the working directory.
# This ensures logs are always written to the same place.
basedir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
log_dir = os.path.join(basedir, 'logs')

# Configure logging to file for Wazuh monitoring
if not os.path.exists(log_dir):
    os.mkdir(log_dir)
log_file_path = os.path.join(log_dir, '2fa_flask.ndjson')
file_handler = RotatingFileHandler(log_file_path, maxBytes=10485760, backupCount=30)
class ContextFilter(logging.Filter):
    def filter(self, record):
        from flask import has_request_context, request, session
        from flask_login import current_user
        from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
        from app.models import User
        from datetime import datetime

        # Set default values only if they haven't been provided in the log call.
        # This prevents overwriting specific context passed in `extra`.
        if not hasattr(record, 'ip_address'):
            record.ip_address = 'N/A'
        if not hasattr(record, 'user_identity'):
            record.user_identity = 'N/A'
        if not hasattr(record, 'username'):
            record.username = 'N/A'
        if not hasattr(record, 'email'):
            record.email = 'N/A'
        if not hasattr(record, 'login_time'):
            record.login_time = 'N/A'
        record.user_active_time = datetime.utcnow().isoformat() # This can always be set.

        if has_request_context():
            record.ip_address = request.remote_addr or 'N/A'
            # Overwrite default login_time if it's available in the session
            record.login_time = session.get('login_time', 'N/A')
            user = None

            # Check for session-based user first
            if current_user and current_user.is_authenticated:
                user = current_user
            else:
                # If no session user, check for JWT
                try:
                    # This is safe to call multiple times
                    verify_jwt_in_request(optional=True)
                    jwt_identity = get_jwt_identity()
                    if jwt_identity:
                        record.user_identity = f"user_id:{jwt_identity}"
                except Exception:
                    pass # No valid JWT

            if user:
                # The logger call can override these with more specific info from 'extra'
                if not hasattr(record, 'user_identity'):
                    record.user_identity = user.username
                if not hasattr(record, 'username'):
                    record.username = user.username
                if not hasattr(record, 'username'):
                    record.username = user.username
                if not hasattr(record, 'email'):
                    record.email = user.email

        return True

json_formatter = jsonlogger.JsonFormatter(
    # The format string defines the base fields for the JSON log.
    # `python-json-logger` automatically includes any extra fields from the log record,
    # such as the ones added by our `ContextFilter`. This keeps the configuration clean.
    '%(name)s %(levelname)s %(message)s',
    rename_fields={'levelname': 'level'}
)

file_handler.setFormatter(json_formatter)
file_handler.addFilter(ContextFilter())
file_handler.setLevel(logging.INFO)

def init_app_logger(app):
    app.logger.addHandler(file_handler)

    # --- Add System Log Handler (Syslog/Windows Event Log) ---
    # This allows a Wazuh agent to monitor system logs directly
    # instead of needing to be configured for a specific file.
    if platform.system() == 'Linux':
        syslog_address = '/dev/log'
    elif platform.system() == 'Darwin':  # macOS
        syslog_address = '/var/run/syslog'
    else:  # Windows
        syslog_address = ('localhost', 514)

    try:
        syslog_handler = SysLogHandler(address=syslog_address)
        syslog_handler.setFormatter(json_formatter)
        syslog_handler.addFilter(ContextFilter())
        app.logger.addHandler(syslog_handler)
    except Exception as e:
        app.logger.warning(f"Could not configure system logger at {syslog_address}: {e}")

    app.logger.setLevel(logging.DEBUG)
    app.logger.info('Flask app startup')

app = Flask(__name__)
app.config.from_object(Config)

# Initialize Telegram Bot and attach to the app object
if app.config.get('TELEGRAM_BOT_TOKEN'):
    app.telegram_bot = telegram.Bot(token=app.config['TELEGRAM_BOT_TOKEN'])
else:
    app.telegram_bot = None
    app.logger.warning("Telegram bot token is not configured. Telegram alerts will be disabled.")

# Define the upload folder, ensuring it's an absolute path
UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login = LoginManager(app)
migrate = Migrate(app, db)
login.login_view = 'login'
login.login_message = None
mail = Mail(app)
# Initialize app logger for Wazuh monitoring
init_app_logger(app)

if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
    app.logger.warning("Email credentials (MAIL_USERNAME, MAIL_PASSWORD) are not set in the environment. Email sending will likely fail.")


jwt = JWTManager(app)

def start_ngrok():
    from pyngrok import ngrok

    url = ngrok.connect(5000)
    print('* Tunnel: ', url)

if app.config.get("ENV") == "development" and app.config["START_NGROK"]:
    start_ngrok()

if not app.debug:
    if app.config['MAIL_SERVER']:
        from logging.handlers import SMTPHandler
        auth = None
        if app.config['MAIL_USERNAME'] or app.config['MAIL_PASSWORD']:
            auth = (app.config['MAIL_USERNAME'],
                    app.config['MAIL_PASSWORD']
                    )
        secure = None
        if app.config['MAIL_USE_TLS']:
            secure = ()
        mail_handler = SMTPHandler(
            mailhost=(app.config['MAIL_SERVER'], app.config['MAIL_PORT']),
            fromaddr='noreply@' + app.config['MAIL_SERVER'],
            toaddrs=app.config['MAIL_DEFAULT_SENDER'],
            subject='Flask 2fa Failure',
            credentials=auth, secure=secure
        )
        mail_handler.setLevel(logging.ERROR)
        app.logger.addHandler(mail_handler)
    if app.config['LOG_TO_STDOUT']:
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(logging.INFO)
        app.logger.addHandler(stream_handler)

from . import models, routes, errors

# The API routes are defined directly in routes.py on the 'app' object,
# so there is no separate API blueprint to register.
