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
        return False

    def authorization_header(self, request=None) -> str:
        """Returns the value of the Authorization header."""
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Returns None - not implemented."""
        return None
