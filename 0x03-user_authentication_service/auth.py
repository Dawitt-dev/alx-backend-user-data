#!/usr/bin/env python3
"""
Auth module for handling authentication operations.
"""

import bcrypt
import logging
from typing import Union
from db import DB
from sqlalchemy.orm.exc import NoResultFound
from user import User
from uuid import uuid4

logging.disable(logging.WARNING)


def _hash_password(password: str) -> bytes:
    """Hashes a password using bcrypt and returns the hashed password as bytes.

    Args:
        password (str): The password to hash.

    Returns:
        bytes: The salted, hashed password.
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed


def _generate_uuid() -> str:
    """Generates a unique identifier using uuid4.

    Returns:
        str: A unique identifier.
    """
    return str(uuid4())


class Auth:
    """Auth class to interact
    with the authentication database.
    """
    def __init__(self):
        """Initializes a new Auth instance.
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Registers a new user and returns the User object.

        Args:
            email (str): The email of the user.
            password (str): The unhashed password of the user.

        Returns:
            User: The User object created.
        """
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            hashed_password = _hash_password(password)
            return self._db.add_user(email, hashed_password)

    def valid_login(self, email: str, password: str) -> bool:
        """Validates a login attempt.

        Args:
            email (str): The email of the user.
            password (str): The unhashed password of the user.

        Returns:
            bool: True if the password is correct, False otherwise.
        """
        try:
            user = self._db.find_user_by(email=email)
            return bcrypt.checkpw(password.encode('utf-8'),
                                  user.hashed_password)
        except NoResultFound:
            return False
