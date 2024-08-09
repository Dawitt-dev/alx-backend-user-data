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
    def extract_base64_authorization_header
    (self, authorization_header: str) -> str:
        """ extract base64 authorization header
        """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith('Basic '):
            return None
        return authorization_header[6:]
