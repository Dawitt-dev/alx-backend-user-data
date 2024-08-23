#!/usr/bin/env python3
"""Module for session-based authentication in the API.
"""

import os
from typing import Tuple
from flask import Flask, abort, jsonify, request
from api.v1.app import auth
from api.v1.views import app_views
from models.user import User

@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def session_auth_login() -> Tuple[str, int]:
    """POST /auth_session/login
    """
    email = request.form.get('email')
    password = request.form.get('password')
    if email is None or password is None:
        return jsonify({"error": "email or password missing"}), 400
    user = User.search({'email': email})
    if not user:
        return jsonify({"error": "no user found for this email"}), 404
    user = user[0]
    if not user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401
    session_id = auth.create_session(user.id)
    response = jsonify(user.to_json())
    response.set_cookie(os.getenv('SESSION_NAME'), session_id)
    return response

@app_views.route('/auth_session/logout', methods=['DELETE'], strict_slashes=False)
def session_auth_logout() -> Tuple[str, int]:
    """DELETE /auth_session/logout
    """
    session_id = request.cookies.get(os.getenv('SESSION_NAME'))
    if session_id is None:
        return jsonify({"error": "session_id missing"}), 403
    if not auth.destroy_session(request):
        return jsonify({"error": "session_id unknown"}), 403
    return jsonify({}), 200
