#!/usr/bin/env python3
"""
Authentication module.
"""

import os
from typing import List, TypeVar
from flask import request


class Auth:
    """Base class for all authentication systems in this application."""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Determines whether a given path requires authentication.

        Args:
            path (str): The path to be checked.
            excluded_paths (List[str]): A list of paths that are excluded from
            authentication.

        Returns:
            bool: True if authentication is required, False otherwise.
        """
        if not path or not excluded_paths:
            return True

        normalized_path = path.rstrip('/')

        for excluded_path in excluded_paths:
            if excluded_path.endswith('*') and \
             normalized_path.startswith(excluded_path[:-1]):
                return False

            if normalized_path == excluded_path.rstrip('/'):
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """Retrieves the Authorization header from the request.

        Args:
            request (flask.Request, optional): The Flask
             request object. Defaults to None.

        Returns:
            str: The Authorization header value if present, otherwise None.
        """
        if request is None:
            return None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """Retrieves the current user. To be implemented in subclasses.

        Args:
            request (flask.Request, optional): The Flask request object.
             Defaults to None.

        Returns:
            TypeVar('User'): The user object associated with the request.
        """
        return None

    def session_cookie(self, request=None) -> str:
        """Fetches the session cookie from the request.

        Args:
            request (flask.Request, optional): The Flask request object.
             Defaults to None.

        Returns:
            str: The session cookie value if present, otherwise None.
        """
        if request is None:
            return None
        cookie_name = os.getenv('SESSION_NAME')
        return request.cookies.get(cookie_name)
