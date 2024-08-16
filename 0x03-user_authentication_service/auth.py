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

    def create_session(self, email: str) -> str:
        """Creates a new session for the user.

        Args:
            email (str): The email of the user.

        Returns:
            str: The new session ID.
        """
        session_id = _generate_uuid()
        try:
            user = self._db.find_user_by(email=email)
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Gets a user from a session ID.

        Args:
            session_id (str): The session ID to search for.

        Returns:
            Union[User, None]: The User object if found, None otherwise.
        """
        try:
            return self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Destroys a session for a user.

        Args:
            user_id (int): The ID of the user.
        """
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Generates a reset password token.

        Args:
            email (str): The email of the user.

        Returns:
            str: The new reset token.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError()
        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token
