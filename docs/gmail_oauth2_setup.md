# Gmail OAuth2 Setup for Flask SMTP Email

This document provides step-by-step instructions to set up Gmail OAuth2 authentication for sending emails from a Flask application.

## Step 1: Create a Google Cloud Project

1. Go to the [Google Cloud Console](https://console.cloud.google.com/).
2. Create a new project or select an existing one.
3. Enable the Gmail API for your project:
   - Navigate to "APIs & Services" > "Library".
   - Search for "Gmail API" and enable it.

## Step 2: Create OAuth2 Credentials

1. In the Cloud Console, go to "APIs & Services" > "Credentials".
2. Click "Create Credentials" > "OAuth client ID".
3. Configure the consent screen if prompted.
4. Choose "Web application" as the application type.
5. Add authorized redirect URIs (e.g., `http://localhost:5000/oauth2callback`).
6. Save and note the **Client ID** and **Client Secret**.

## Step 3: Install Required Python Packages

```bash
pip install google-auth google-auth-oauthlib google-auth-httplib2
```

## Step 4: Update Flask App Configuration

Add the following to your `.env` or config file:

```
GOOGLE_CLIENT_ID=your_client_id_here
GOOGLE_CLIENT_SECRET=your_client_secret_here
GOOGLE_REFRESH_TOKEN=your_refresh_token_here
```

## Step 5: Obtain Refresh Token

You need to obtain a refresh token manually by running a script or using OAuth2 playground.

Example script to get refresh token:

```python
from google_auth_oauthlib.flow import InstalledAppFlow

flow = InstalledAppFlow.from_client_secrets_file(
    'client_secret.json',
    scopes=['https://mail.google.com/']
)

creds = flow.run_local_server(port=0)
print('Access Token:', creds.token)
print('Refresh Token:', creds.refresh_token)
```

Save the refresh token securely.

## Step 6: Modify Email Sending Code to Use OAuth2

Use the refresh token to get access tokens and authenticate SMTP.

Example snippet:

```python
import base64
import google.auth.transport.requests
from google.oauth2.credentials import Credentials
import smtplib
from email.mime.text import MIMEText

def get_access_token():
    creds = Credentials(
        None,
        Refresh Token: YOUR_REFRESH_TOKEN_HERE
Client ID: YOUR_CLIENT_ID_HERE
Client Secret: YOUR_CLIENT_SECRET_HERE

    )
    request = google.auth.transport.requests.Request()
    creds.refresh(request)
    return creds.token

def send_email_oauth2(to_email, subject, body):
    access_token = get_access_token()
    auth_string = f'user={os.environ["MAIL_USERNAME"]}\1auth=Bearer {access_token}\1\1'
    msg = MIMEText(body, 'html')
    msg['to'] = manojpoojar0123@gmail.com
    msg['from'] = os.environ['MAIL_DEFAULT_SENDER']
    msg['subject'] = subject

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.docmd('AUTH', 'XOAUTH2 ' + base64.b64encode(auth_string.encode()).decode())
    server.sendmail(os.environ['MAIL_DEFAULT_SENDER'], to_email, msg.as_string())
    server.quit()
```

## Step 7: Test Email Sending

Use the modified function to send test emails and verify the setup.

---

This setup will enable secure OAuth2 authentication for Gmail SMTP in your Flask app, resolving authentication errors.
