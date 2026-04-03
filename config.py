import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))


class Config(object):
    # Form security
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or SECRET_KEY
    JWT_ALGORITHM = 'HS256'

    # Localhost testing
    START_NGROK = os.environ.get('START_NGROK') is not None and \
        os.environ.get('WERKZEUG_RUN_MAIN') != 'true'

    # Email configurations
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'smtp.gmail.com'
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'false').lower() in ['true', 'on', '1']
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or os.environ.get('MAIL_USERNAME')
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL')

    # Telegram Bot Configuration
    TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN')
    TELEGRAM_ADMIN_CHAT_ID = os.environ.get('TELEGRAM_ADMIN_CHAT_ID')
    TELEGRAM_BOT_NAME = os.environ.get('TELEGRAM_BOT_NAME')

    # Heroku logs requirement
    LOG_TO_STDOUT = os.environ.get('LOG_TO_STDOUT')

    # Wazuh API Configuration (alternative to Syslog)
    WAZUH_API_HOST = os.environ.get('WAZUH_API_HOST')  # e.g., 'wazuh.example.com'
    WAZUH_API_PORT = int(os.environ.get('WAZUH_API_PORT') or 55000)
    WAZUH_API_USER = os.environ.get('WAZUH_API_USER')
    WAZUH_API_PASSWORD = os.environ.get('WAZUH_API_PASSWORD')
    WAZUH_API_KEY = os.environ.get('WAZUH_API_KEY')  # Bearer token is preferred
    WAZUH_API_VERIFY_SSL = os.environ.get('WAZUH_API_VERIFY_SSL', 'true').lower() in ['true', 'on', '1']

    # SQLAlchemy Database Configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False