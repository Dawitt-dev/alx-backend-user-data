#!/usr/bin/env python3
"""Module for session-based authentication in the API.
"""

from uuid import uuid4
from api.v1.auth.auth import Auth
from models.user import User


class SessionAuth(Auth):
    """Handles session-based authentication, inheriting from Auth."""

    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """Generates a new session ID for a given user.

        Args:
            user_id (str, optional): The ID of the
            user to create a session for.

        Returns:
            str: The generated session ID, or None if user_id is invalid.
        """
        if isinstance(user_id, str):
            session_id = str(uuid4())
            self.user_id_by_session_id[session_id] = user_id
            return session_id
        return None

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Retrieves the user ID associated with a given session ID.

        Args:
            session_id (str, optional): The session ID to look up.

        Returns:
            str: The corresponding user ID, or None if session_id is invalid.
        """
        if isinstance(session_id, str):
            return self.user_id_by_session_id.get(session_id)
        return None

    def current_user(self, request=None) -> User:
        """Fetches the current User instance based on session data.

        Args:
            request (flask.request, optional): The request object containing
            the session cookie.

        Returns:
            User: The User instance if found, otherwise None.
        """
        session_id = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_id)
        return User.get(user_id) if user_id else None

    def destroy_session(self, request=None) -> bool:
        """Logs out the user by deleting the session ID.

        Args:
            request (flask.request, optional): The Flask request object.

        Returns:
            bool: True if the session was successfully destroyed,
            False otherwise.
        """
        session_id = self.session_cookie(request)
        if session_id and session_id in self.user_id_by_session_id:
            del self.user_id_by_session_id[session_id]
            return True
        return False
