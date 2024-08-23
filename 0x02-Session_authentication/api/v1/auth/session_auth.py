#!/usr/bin/env python3
"""Module for session-based authentication in the API.
"""

from uuid import uuid4
from .auth import Auth
from models.user import User
from flask import g


class SessionAuth(Auth):
    """Handles session-based authentication, inheriting from Auth."""
    def create_session(self, user_id: str = None) -> str:
        """Creates a session for a user."""
        if user_id is None:
            return None
        session_id = str(uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Returns the user ID associated with a session ID."""
        if session_id is None:
            return None
        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None) -> TypeVar('User'):
        """Returns a User instance based on a cookie value."""
        session_id = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_id)
        return User.get(user_id)

    def destroy_session(self, request=None) -> bool:
        """Deletes the user session / logout."""
        if request is None:
            return False
        session_id = self.session_cookie(request)
        if session_id is None:
            return False
        user_id = self.user_id_for_session_id(session_id)
        if user_id is None:
            return False
        del self.user_id_by_session_id[session_id]
        return True
