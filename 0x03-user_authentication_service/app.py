#!/usr/bin/env python3
"""
Flask app for handling authentication
"""
from auth import Auth
from flask import Flask, jsonify, request, abort, redirect, url_for
from sqlalchemy.exc import InvalidRequestError

app = Flask(__name__)

AUTH = Auth()


@app.route('/', methods=['GET'], strict_slashes=False)
def hello() -> str:
    """GET /
    Return:
      - welcome message
    """
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def register_user() -> str:
    """POST /users
    JSON body:
      - email
      - password
    Return:
      - user object
    """
    email = request.form.get('email')
    password = request.form.get('password')
    try:
        user = AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login() -> str:
    """POST /sessions
    JSON body:
      - email
      - password
    Return:
      - session_id
    """
    # get email and password from request
    email = request.form.get('email')
    password = request.form.get('password')
    # check if login is valid
    if not AUTH.valid_login(email, password):
        abort(401)
    # create a new session
    session_id = AUTH.create_session(email)
    # return session_id
    response = jsonify({"email": email, "message": "logged in"})
    # set session_id cookie
    response.set_cookie("session_id", session_id)
    # return response
    return response


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout() -> str:
    """DELETE /sessions
    JSON body:
      - session_id
    Return:
      - message
    """
    if request.cookies.get('session_id') is None:
        abort(403)
    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect("/")


@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile() -> str:
    """GET /profile
    Return:
      - user object
    """
    if request.cookies.get('session_id') is None:
        abort(403)
    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    return jsonify({"email": user.email})


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def get_reset_password_token() -> str:
    """POST /reset_password
    JSON body:
      - email
    Return:
      - reset token
    """
    email = request.form.get('email')
    try:
        reset_token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": reset_token})
    except ValueError:
        abort(403)


@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def update_password() -> str:
    """PUT /reset_password
    JSON body:
      - email
      - reset_token
      - new_password
    Return:
      - message
    """
    email = request.form.get('email')
    reset_token = request.form.get('reset_token')
    new_password = request.form.get('new_password')
    try:
        AUTH.update_password(reset_token, new_password)
        return jsonify({"email": email, "message": "Password updated"})
    except ValueError:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
