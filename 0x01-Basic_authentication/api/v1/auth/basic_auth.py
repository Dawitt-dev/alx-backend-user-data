#!/usr/bin/env python3
"""a class to manage the API authentication
"""

from api.v1.auth.auth import Auth
from flask import request
from typing import List, TypeVar
from os import getenv


class BasicAuth(Auth):
    """BasicAuth class
    """
    def extract_base64_authorization_header(self, auth_head: str) -> str:
        """ extract base64 authorization header
        """
        if auth_head is None:
            return None
        if not isinstance(auth_head, str):
            return None
        if not auth_head.startswith('Basic '):
            return None
        return auth_head[6:]
