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
    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect("/"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
