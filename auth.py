import click
from app import app, db
from app.models import User, Note, File
import telegram


@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'Note': Note, 'File': File}


@app.cli.command("set-telegram-webhook")
@click.argument("url")
def set_telegram_webhook(url):
    """
    Sets the Telegram webhook URL.
    The URL should be the public HTTPS URL of your application (e.g., from ngrok).
    Example: flask set-telegram-webhook https://<your-ngrok-id>.ngrok.io
    """
    bot_token = app.config.get('TELEGRAM_BOT_TOKEN')
    if not bot_token:
        print("Error: TELEGRAM_BOT_TOKEN is not set in your .env file.")
        return

    try:
        bot = telegram.Bot(token=bot_token)
        webhook_url = f"{url}/telegram/webhook/{bot_token}"
        bot.set_webhook(webhook_url)
        print(f"Success! Telegram webhook set to: {webhook_url}")
    except Exception as e:
        print(f"Error setting Telegram webhook: {e}")