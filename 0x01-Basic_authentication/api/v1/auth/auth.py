#!/usr/bin/env python3
"""a class to manage the API authentication
"""
from flask import request
from typing import List, TypeVar
from os import getenv


class Auth:
    """Auth class
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Checks if authentication is required for the given path."""
        if path is None or excluded_paths is None or excluded_paths == []:
            return True
        if path[-1] != '/':
            path += '/'
        if path in excluded_paths:
            return False
        return True

    def authorization_header(self, request=None) -> str:
        """Returns the value of the Authorization header."""
        if request is None or request.headers.get('Authorization') is None:
            return None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """Returns None - not implemented."""
        return None

    def require_auth(self, path, excluded_paths):
        """ require auth method """
        if path is None or excluded_paths is None or excluded_paths == []:
            return True

        # Remove trailing slash from path for consistency
        path = path.rstrip('/')

        for ex_path in excluded_paths:
            # Remove trailing slash from excluded path
            ex_path = ex_path.rstrip('/')

            if ex_path.endswith('*'):
                # check if path starts with the excluded path (minus the *)
                if path.startswith(ex_path[:-1]):
                    return False
            elif ex_path == path:
                return False

        return True
