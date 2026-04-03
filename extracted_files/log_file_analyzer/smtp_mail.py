# flask_app/app/auth/utils.py or tests/smtp.py

import smtplib
import random
import os
import pickle
import base64
from email.mime.text import MIMEText
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials

SCOPES = ['https://mail.google.com/']
TOKEN_FILE = 'token.json'
CLIENT_SECRET_FILE = 'credentials.json'

def get_gmail_service():
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN_FILE, 'w') as token:
            token.write(creds.to_json())
    return creds

def send_otp_email(to_email, otp):
    creds = get_gmail_service()
    access_token = creds.token

    msg = MIMEText(f'Your OTP code is: {otp}')
    msg['to'] = to_email
    msg['from'] = 'your-email@gmail.com'
    msg['subject'] = 'Your MFA OTP Code'

    auth_string = f'user={msg["from"]}\1auth=Bearer {access_token}\1\1'
    auth_bytes = auth_string.encode("utf-8")
    auth_encoded = base64.b64encode(auth_bytes).decode("utf-8")

    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.ehlo()
        server.starttls()
        server.docmd('AUTH', 'XOAUTH2 ' + auth_encoded)
        server.sendmail(msg['from'], [to_email], msg.as_string())
