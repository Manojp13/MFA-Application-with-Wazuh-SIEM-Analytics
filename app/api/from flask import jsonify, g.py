from flask import jsonify, g
from app import app as main_app
from app.api import api
from app.models import User
from app.api.auth import basic_auth
from app.api.errors import bad_request, error_response
from app.firebase import db as firebase_db


@api.route('/users/<username>/block', methods=['POST'])
@basic_auth.login_required
def block_user(username):
    """Blocks a user account. Accessible only via API key."""
    user = User.get_by_username(username)
    if not user:
        return error_response(404, f"User {username} not found.")

    if user.blocked:
        return bad_request(f"User {username} is already blocked.")

    doc_ref = firebase_db.collection('users').document(user.id)
    doc_ref.update({'blocked': True})

    main_app.logger.warning(f"User '{username}' has been blocked via API by '{g.current_user.username}'.", extra={
        'user_identity': username,
        'api_caller': g.current_user.username
    })

    return jsonify({'status': 'success', 'message': f'User {username} has been blocked.'})


@api.route('/users/<username>/unblock', methods=['POST'])
@basic_auth.login_required
def unblock_user(username):
    """Unblocks a user account. Accessible only via API key."""
    user = User.get_by_username(username)
    if not user:
        return error_response(404, f"User {username} not found.")

    if not user.blocked:
        return bad_request(f"User {username} is not currently blocked.")

    doc_ref = firebase_db.collection('users').document(user.id)
    doc_ref.update({'blocked': False})

    main_app.logger.info(f"User '{username}' has been unblocked via API by '{g.current_user.username}'.", extra={
        'user_identity': username,
        'api_caller': g.current_user.username
    })

    return jsonify({'status': 'success', 'message': f'User {username} has been unblocked.'})


@api.route('/users/<username>/generate_api_key', methods=['POST'])
@basic_auth.login_required
def generate_api_key(username):
    """Generates an API key for a user. Requires admin privileges."""
    if not g.current_user.is_admin:
        return error_response(403, "You do not have permission to perform this action.")

    user = User.get_by_username(username)
    if not user:
        return error_response(404, f"User {username} not found.")

    user.generate_api_key()

    doc_ref = firebase_db.collection('users').document(user.id)
    doc_ref.update({
        'api_key': user.api_key,
        'api_key_generation_time': user.api_key_generation_time
    })

    main_app.logger.info(f"API key generated for user '{username}' by admin '{g.current_user.username}'.", extra={
        'user_identity': username,
        'api_caller': g.current_user.username
    })

    return jsonify({'status': 'success', 'message': f'API key generated for {username}.', 'api_key': user.api_key})