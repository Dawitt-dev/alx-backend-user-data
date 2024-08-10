#!/usr/bin/env python3
"""a class to manage the API authentication
"""

from api.v1.auth.auth import Auth
import base64
from flask import request
from models.user import User
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
        try:
            b64_bytes = b64_auth.encode('utf-8')
            res = base64.b64decode(b64_bytes)
            return res.decode('utf-8')
        except Exception:
            return

    def extract_user_credentials(self, b64_auth: str) -> (str, str):
        """ extract user credentials
        """
        if b64_auth is None:
            return None, None
        if not isinstance(b64_auth, str):
            return None, None
        if ':' not in b64_auth:
            return None, None
        creds = b64_auth.split(':', 1)
        return creds[0], creds[1]

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """ user object from credentials
        """
        if (not user_email or
                type(user_email) != str or
                not user_pwd or type(user_pwd) != str):
            return
        user = None
        try:
            user = User.search({"email": user_email})
        except Exception:
            return
        if not user:
            return
        for u in user:
            if u.is_valid_password(user_pwd):
                return u
