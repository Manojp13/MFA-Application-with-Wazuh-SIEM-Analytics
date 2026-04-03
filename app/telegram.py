import telegram
from app import app
from threading import Thread

def _send_async_telegram(bot, chat_id, text):
    """Helper function to send messages in a background thread."""
    if not bot:
        return
    try: 
        bot.send_message(chat_id=chat_id, text=text, parse_mode=telegram.ParseMode.MARKDOWN)
        app.logger.info(f"Telegram alert sent to chat_id {chat_id}")
    except telegram.error.TelegramError as e:
        app.logger.error(f"Failed to send Telegram message to chat_id {chat_id}. Error: {e}")

def send_admin_telegram_alert(message):
    """Sends a Telegram alert to the admin if configured."""
    admin_chat_id = app.config.get('TELEGRAM_ADMIN_CHAT_ID')
    if not admin_chat_id:
        app.logger.warning("TELEGRAM_ADMIN_CHAT_ID is not set. Cannot send admin alert.")
        return
    if not app.telegram_bot:
        return

    # Prepend a header to distinguish admin alerts
    admin_message = f"*-- ADMIN ALERT --*\n\n{message}"
    Thread(target=_send_async_telegram, args=(app.telegram_bot, admin_chat_id, admin_message), daemon=True).start()