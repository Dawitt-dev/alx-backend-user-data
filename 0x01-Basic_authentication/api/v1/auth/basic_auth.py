#!/usr/bin/env python3
"""a class to manage the API authentication
"""

from api.v1.auth.auth import Auth
import base64
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

    def decode_base64_authorization_header(self, b64_auth: str) -> str:
        """ decode base64 authorization header
        """
        if b64_auth is None:
            return None
        if not isinstance(b64_auth, str):
            return None
        try:
            return b64_auth.encode('utf-8').decode('base64')
        except Exception:
            return None
