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
    email = request.form.get('email')
    password = request.form.get('password')
    try:
        session_id = AUTH.create_session(email, password)
        if not session_id:
            abort(401)
        return jsonify({"email": email, "message": "logged in"})
    except NoResultFound:
        abort(401)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
