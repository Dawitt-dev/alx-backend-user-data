#!/usr/bin/env python3
"""
Auth module for handling authentication operations.
"""

import bcrypt
from db import DB
from user import User


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
        # Check if the user already exists
        existing_user = self._db.query(User).\
            filter_by(email=email).first()
        if existing_user:
            raise ValueError(f"User {email} already exists")

        # Hash the password
        hashed_password = _hash_password(password)

        # Create and save the new user
        new_user = self._db.add_user(email, hashed_password)
        return new_user
