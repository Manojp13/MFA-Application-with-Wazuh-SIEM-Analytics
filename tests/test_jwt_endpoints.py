import pytest
from app import app
from app.models import User
from flask import json
# Removed db import since db is not used with Firebase integration

import pytest
from app.__init__ import app
from app.models import User
from flask import json
from unittest.mock import patch, MagicMock

@pytest.fixture
def client():
    print("Creating test client fixture")
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['JWT_SECRET_KEY'] = app.config['SECRET_KEY']
    app.config['JWT_TOKEN_LOCATION'] = ['headers']
    app.config['JWT_HEADER_NAME'] = 'Authorization'
    app.config['JWT_HEADER_TYPE'] = 'Bearer'
    app.config['JWT_DECODE_AUDIENCE'] = None
    app.config['JWT_ENCODE_AUDIENCE'] = None
    with app.test_client() as client:
        with app.app_context():
            print("Inside app context in test client fixture")
            # Mock Firebase user retrieval methods
            with patch.object(User, 'get_by_username') as mock_get_by_username, \
                 patch.object(User, 'get_by_id') as mock_get_by_id, \
                 patch.object(User, 'get_by_email') as mock_get_by_email:
                test_user = User(username='testuser', email='test@example.com')
                test_user.set_password('testpassword')
                mock_get_by_username.return_value = test_user
                mock_get_by_id.return_value = test_user
                mock_get_by_email.return_value = test_user
                yield client

def test_root_route(client):
    print("Testing root route '/'")
    response = client.get('/')
    print(f"Root route response status: {response.status_code}")
    assert response.status_code == 200

def test_api_login_success(client, monkeypatch):
    # Mock verify_totp to always return True
    def mock_verify_totp(self, token):
        return True
    monkeypatch.setattr(User, "verify_totp", mock_verify_totp)

    response = client.post('/api/login', json={
        'username': 'testuser',
        'password': 'testpassword',
        'token': '123456'
    })
    data = json.loads(response.data)
    assert response.status_code == 200
    assert 'access_token' in data

def test_api_login_failure(client):
    response = client.post('/api/login', json={
        'username': 'wronguser',
        'password': 'wrongpassword',
        'token': '000000'
    })
    assert response.status_code == 401

def test_protected_endpoint(client, monkeypatch):
    # Mock verify_totp to always return True
    def mock_verify_totp(self, token):
        return True
    monkeypatch.setattr(User, "verify_totp", mock_verify_totp)

    login_response = client.post('/api/login', json={
        'username': 'testuser',
        'password': 'testpassword',
        'token': '123456'
    })
    access_token = json.loads(login_response.data)['access_token']

    # Removed User.query usage, use mocked user instead
    # print(f"Test user id: {User.query.filter_by(username='testuser').first().id}")
    print(f"Access token: {access_token}")

    response = client.get('/api/protected', headers={
        'Authorization': f'Bearer {access_token}'
    })
    data = json.loads(response.data)
    print(f"Response status: {response.status_code}")
    print(f"Response data: {data}")
    assert response.status_code == 200
    assert data['logged_in_as'] == 'testuser'

def test_protected_endpoint_no_token(client):
    response = client.get('/api/protected')
    assert response.status_code == 401

def test_registration(client):
    with patch.object(User, 'get_by_username') as mock_get_by_username, \
         patch.object(User, 'get_by_email') as mock_get_by_email:
        mock_get_by_username.return_value = None
        mock_get_by_email.return_value = None
        response = client.post('/register', data={
            'first_name': 'Test',
            'last_name': 'User',
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'newpassword',
            'confirm_password': 'newpassword',
            'submit': True
        }, follow_redirects=True)
        assert b'You need to scan the QR code below to complete registration' in response.data

def test_reset_password_request(client):
    # Mock User.get_by_email to simulate user exists
    with patch.object(User, 'get_by_email') as mock_get_by_email:
        test_user = User(username='resetuser', email='resetuser@example.com')
        test_user.set_password('resetpassword')
        mock_get_by_email.return_value = test_user

        response = client.post('/reset_password_request', data={
            'email': 'resetuser@example.com',
            'submit': True
        }, follow_redirects=True)
        assert b'Check your email for the instructions to reset your password' in response.data

def test_reset_password(client):
    # Mock User.verify_reset_password_token and User.get_by_id
    with patch.object(User, 'verify_reset_password_token') as mock_verify_token, \
         patch.object(User, 'get_by_id') as mock_get_by_id:
        test_user = User(username='resetuser2', email='resetuser2@example.com')
        test_user.set_password('resetpassword2')
        mock_verify_token.return_value = test_user
        mock_get_by_id.return_value = test_user
        token = test_user.get_reset_password_token()

        response = client.post(f'/reset_password/{token}', data={
            'password': 'newpassword2',
            'password2': 'newpassword2',
            'submit': True
        }, follow_redirects=True)
        assert b'Your password has been reset.' in response.data

def test_web_registration_and_login(client):
    import app.models
    with patch.object(app.models.User, 'get_by_username') as mock_get_by_username, \
         patch.object(app.models.User, 'get_by_email') as mock_get_by_email:
        mock_get_by_username.return_value = None
        mock_get_by_email.return_value = None

        # Test GET registration page
        response = client.get('/register')
        assert response.status_code == 200
        assert b'Register' in response.data

        # Test POST registration with missing fields (edge case)
        response = client.post('/register', data={
            'first_name': '',
            'last_name': '',
            'username': '',
            'email': 'invalidemail',
            'password': 'pass',
            'confirm_password': 'pass',
            'submit': True
        }, follow_redirects=True)
        assert b'Please use a different email address' not in response.data  # Because email format invalid
        assert b'This field is required' in response.data or b'Invalid email address' in response.data

        # Test POST registration with valid data
        response = client.post('/register', data={
            'first_name': 'Web',
            'last_name': 'User',
            'username': 'webuser',
            'email': 'webuser@example.com',
            'password': 'webpassword',
            'confirm_password': 'webpassword',
            'submit': True
        }, follow_redirects=True)
        assert b'You need to scan the QR code below to complete registration' in response.data

    # Test GET login page
    response = client.get('/login')
    assert response.status_code == 200
    assert b'Login' in response.data

    # Test POST login with invalid credentials
    response = client.post('/login', data={
        'username': 'wronguser',
        'password': 'wrongpass',
        'token': '000000',
        'submit': True
    }, follow_redirects=True)
    assert b'Invalid username or password' in response.data

    # Test POST login with valid credentials (mock verify_totp)
    def mock_verify_totp(self, token):
        return True
    from app.models import User
    import pytest
    pytest.MonkeyPatch().setattr(User, "verify_totp", mock_verify_totp)

    # Add user for login
    with app.app_context():
        user = User(username='loginuser', email='loginuser@example.com')
        user.set_password('loginpassword')
        db.session.add(user)
        db.session.commit()

    response = client.post('/login', data={
        'username': 'loginuser',
        'password': 'loginpassword',
        'token': '123456',
        'submit': True
    }, follow_redirects=True)
    assert b'Home' in response.data or b'Logout' in response.data

def test_two_factor_setup_page(client):
    import app.models
    with patch.object(app.models.User, 'get_by_username') as mock_get_by_username:
        mock_get_by_username.return_value = User(username='testuser', email='test@example.com')

        # Access two-factor setup page without session username (should redirect)
        response = client.get('/twofactor', follow_redirects=True)
        assert b'Home' in response.data or b'Login' in response.data

        # Set session username and access two-factor setup page
        with client.session_transaction() as sess:
            sess['username'] = 'testuser'
        response = client.get('/twofactor')
        assert response.status_code == 200
        assert b'QR code' in response.data or b'two_factor_setup' in response.data

def test_qrcode_generation(client):
    # Access qrcode endpoint without session username (should 404)
    response = client.get('/qrcode')
    assert response.status_code == 404

    # Set session username and access qrcode endpoint
    with client.session_transaction() as sess:
        sess['username'] = 'testuser'
    response = client.get('/qrcode')
    assert response.status_code == 200
    assert response.content_type == 'image/svg+xml'
