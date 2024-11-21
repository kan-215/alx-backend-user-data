#!/usr/bin/env python3
"""API Routes for Authentication Service"""

from auth import Auth
from flask import Flask, jsonify, request, abort, redirect


app = Flask(__name__)
AUTH = Auth()


def get_form_data(*keys):
    """
    Helper function to extract form data or abort with 400.
    Args:
        keys: Keys to extract from the request form.
    Returns:
        A dictionary with extracted values.
    """
    data = {}
    for key in keys:
        value = request.form.get(key)
        if not value:
            abort(400)
        data[key] = value
    return data


@app.route('/', methods=['GET'])
def hello_world() -> str:
    """
    Base route for authentication service API.
    Returns:
        A JSON payload with a welcome message.
    """
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'])
def register_user() -> str:
    """
    Registers a new user if it does not exist.
    Returns:
        A JSON payload with the registration status.
    """
    data = get_form_data('email', 'password')
    email, password = data['email'], data['password']

    try:
        AUTH.register_user(email, password)
    except ValueError:
        return jsonify({"message": "email already registered"}), 400

    return jsonify({"email": email, "message": "user created"}), 200


@app.route('/sessions', methods=['POST'])
def log_in() -> str:
    """
    Logs in a user and returns a session ID.
    Returns:
        A response with session ID set as a secure cookie.
    """
    data = get_form_data('email', 'password')
    email, password = data['email'], data['password']

    if not AUTH.valid_login(email, password):
        abort(401)

    session_id = AUTH.create_session(email)
    response = jsonify({"email": email, "message": "logged in"})
    response.set_cookie(
        "session_id", session_id, httponly=True, samesite="Strict", secure=True
    )

    return response


@app.route('/sessions', methods=['DELETE'])
def log_out() -> str:
    """
    Logs out a user by destroying their session.
    Returns:
        A redirect to the base route or a 403 status if the session is invalid.
    """
    session_id = request.cookies.get("session_id")

    if not session_id or not AUTH.get_user_from_session_id(session_id):
        abort(403)

    AUTH.destroy_session(AUTH.get_user_from_session_id(session_id).id)
    return redirect('/')


@app.route('/profile', methods=['GET'])
def profile() -> str:
    """
    Fetches the profile of the logged-in user.
    Returns:
        A JSON payload with the user's email.
    """
    session_id = request.cookies.get("session_id")

    if not session_id:
        abort(403)

    user = AUTH.get_user_from_session_id(session_id)

    if not user:
        abort(403)

    return jsonify({"email": user.email}), 200


@app.route('/reset_password', methods=['POST'])
def reset_password() -> str:
    """
    Generates a reset password token for the user.
    Returns:
        A JSON payload with the reset token.
    """
    data = get_form_data('email')
    email = data['email']

    try:
        reset_token = AUTH.get_reset_password_token(email)
    except ValueError:
        abort(403)

    return jsonify({"email": email, "reset_token": reset_token}), 200


@app.route('/reset_password', methods=['PUT'])
def update_password() -> str:
    """
    Updates a user's password using a reset token.
    Returns:
        A JSON payload indicating success or an error status.
    """
    data = get_form_data('email', 'reset_token', 'new_password')
    email, reset_token, new_password = (
        data['email'],
        data['reset_token'],
        data['new_password'],
    )

    try:
        AUTH.update_password(reset_token, new_password)
    except ValueError:
        abort(403)

    return jsonify({"email": email, "message": "Password updated"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
