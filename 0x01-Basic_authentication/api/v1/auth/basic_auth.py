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
    pass
