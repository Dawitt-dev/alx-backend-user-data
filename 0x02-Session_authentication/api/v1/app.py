#!/usr/bin/env python3
"""
API Route Module
"""

import os
from typing import Tuple
from flask import Flask, abort, jsonify, request
from flask_cors import CORS

from api.v1.auth.auth import Auth
from api.v1.auth.basic_auth import BasicAuth
from api.v1.auth.session_auth import SessionAuth
from api.v1.auth.session_db_auth import SessionDBAuth
from api.v1.auth.session_exp_auth import SessionExpAuth
from api.v1.views import app_views

# Initialize the Flask application and register blueprints
app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})

# Determine the authentication type based on the environment variable AUTH_TYPE
auth_type = os.getenv('AUTH_TYPE', 'default')

# Instantiate the appropriate authentication class based on the auth_type
if auth_type == "session_auth":
    auth = SessionAuth()
elif auth_type == 'session_exp_auth':
    auth = SessionExpAuth()
elif auth_type == 'session_db_auth':
    auth = SessionDBAuth()
elif auth_type == "basic_auth":
    auth = BasicAuth()
else:
    auth = Auth()


@app.errorhandler(404)
def not_found(error) -> str:
    """Handler for 404 Not Found errors."""
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(401)
def unauthorized(error: Exception) -> Tuple[jsonify, int]:
    """Handler for 401 Unauthorized errors.

    Args:
        error (Exception): The exception that triggered the error.

    Returns:
        Tuple[jsonify, int]: A JSON response with
         the error message and a 401 status code.
    """
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden(error: Exception) -> Tuple[jsonify, int]:
    """Handler for 403 Forbidden errors.

    Args:
        error (Exception): The exception that triggered the error.

    Returns:
        Tuple[jsonify, int]: A JSON response with the
         error message and a 403 status code.
    """
    return jsonify({"error": "Forbidden"}), 403


@app.before_request
def handle_request():
    """Pre-request handler to manage authentication and authorization."""
    # If no authentication method is set, skip authentication
    if auth is None:
        return

    # Define paths that do not require authentication
    excluded_paths = [
        '/api/v1/status/',
        '/api/v1/unauthorized/',
        '/api/v1/forbidden/',
        '/api/v1/auth_session/login/'
    ]

    # Skip authentication if the requested path is in the excluded paths
    if not auth.require_auth(request.path, excluded_paths):
        return

    # Check for authentication credentials in the header or session cookie
    if auth.authorization_header(request) is None and \
            auth.session_cookie(request) is None:
        abort(401)

    # Verify the user based on the current session or authorization
    if auth.current_user(request) is None:
        abort(403)

    # Set the current user for the request
    request.current_user = auth.current_user(request)


if __name__ == "__main__":
    host = os.getenv("API_HOST", "0.0.0.0")
    port = os.getenv("API_PORT", "5000")
    app.run(host=host, port=port, debug=True)
