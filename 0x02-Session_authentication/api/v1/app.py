#!/usr/bin/env python3
"""
API route module
"""

import os
from flask import Flask, abort, jsonify, request
from flask_cors import CORS

from api.v1.auth.auth import Auth
from api.v1.auth.basic_auth import BasicAuth
from api.v1.auth.session_auth import SessionAuth
from api.v1.auth.session_db_auth import SessionDBAuth
from api.v1.auth.session_exp_auth import SessionExpAuth
from api.v1.views import app_views

app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})

# Initialize the auth variable based on the AUTH_TYPE environment variable
auth_type = os.getenv('AUTH_TYPE')
auth = {
    'session_auth': SessionAuth,
    'session_exp_auth': SessionExpAuth,
    'session_db_auth': SessionDBAuth,
    'basic_auth': BasicAuth
}.get(auth_type, Auth)()

@app.errorhandler(404)
def not_found(_error) -> Tuple[jsonify, int]:
    """Handles 404 Not Found errors."""
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(401)
def unauthorized(_error) -> Tuple[jsonify, int]:
    """Handles 401 Unauthorized errors."""
    return jsonify({"error": "Unauthorized"}), 401

@app.errorhandler(403)
def forbidden(_error) -> Tuple[jsonify, int]:
    """Handles 403 Forbidden errors."""
    return jsonify({"error": "Forbidden"}), 403

@app.before_request
def handle_request():
    """
    Processes each request before it's handled by the view.
    """
    if auth is None:
        return

    excluded_paths = [
        '/api/v1/status/',
        '/api/v1/unauthorized/',
        '/api/v1/forbidden/',
        '/api/v1/auth_session/login/'
    ]

    if not auth.require_auth(request.path, excluded_paths):
        return

    if not (auth.authorization_header(request) or auth.session_cookie(request)):
        abort(4
