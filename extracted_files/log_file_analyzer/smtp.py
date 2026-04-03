import os
import base64
from email.mime.text import MIMEText
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

# If modifying these SCOPES, delete the file token.json
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

def get_credentials():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    return creds

def create_message(sender, to, subject, message_text):
    message = MIMEText(message_text)
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    raw = base64.urlsafe_b64encode(message.as_bytes())
    return {'raw': raw.decode()}

def send_message(service, user_id, message):
    try:
        sent_message = service.users().messages().send(userId=user_id, body=message).execute()
        print(f"Message sent. Message ID: {sent_message['id']}")
        return sent_message
    except Exception as error:
        print(f"An error occurred: {error}")
        return None

if __name__ == '__main__':
    sender_email = input("Enter your Gmail address: ")
    to_email = input("Enter recipient email address: ")
    subject = input("Enter subject: ")
    body = input("Enter email message: ")

    creds = get_credentials()
    service = build('gmail', 'v1', credentials=creds)

    message = create_message(sender_email, to_email, subject, body)
    send_message(service, 'me', message)
