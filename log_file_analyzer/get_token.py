from google_auth_oauthlib.flow import InstalledAppFlow
import os

SCOPES = ['https://mail.google.com/']
CLIENT_SECRET_FILE = 'credentials.json'
TOKEN_FILE = 'token.json'

def generate_token():
    flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET_FILE, SCOPES)
    creds = flow.run_local_server(port=0)

    with open(TOKEN_FILE, 'w') as token:
        token.write(creds.to_json())
    print("token.json created successfully.")

if __name__ == '__main__':
    generate_token()
