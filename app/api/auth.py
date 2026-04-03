from flask import g
from flask_httpauth import HTTPBasicAuth
from app.models import User
from app.api.errors import error_response

basic_auth = HTTPBasicAuth()

@basic_auth.verify_password
def verify_password(username, password):
    """
    Verify the API key provided in the HTTP Basic Auth username field.
    The password field is not used.
    """
    user = User.check_api_key(username)
    if user:
        g.current_user = user
        return True
    return False

@basic_auth.error_handler
def basic_auth_error(status):
    return error_response(status)