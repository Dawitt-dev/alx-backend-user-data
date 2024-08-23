#!/usr/bin/env python3
"""Module for session authentication"""

import os
from datetime import datetime as dt, timedelta
from .session_auth import SessionAuth


class SessionExpAuth(SessionAuth):
    """Session Exp Auth class"""
    def __init__(self):
        """Init method"""
        session_duration = int(os.getenv('SESSION_DURATION'))
        self.session_duration = timedelta(seconds=session_duration)

    def create_session(self, user_id: str = None) -> str:
        """Create a session"""
        session_id = super().create_session(user_id)
        if session_id is None:
            return None
        session_dictionary = {
            'user_id': user_id,
            'created_at': dt.now()
        }
        self.user_id_by_session_id[session_id] = session_dictionary
        return session_id

    return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Returns the user ID associated with the given session ID.

        Args:
            session_id (str, optional): The session ID. Defaults to None.

        Returns:
            str: The user ID associated with the session ID,
                 or None if the session ID is invalid or expired.
        """
        """User ID for session ID"""
        if session_id is None:
            return None
        # If the user_id_by_session_id dictionary does not contain the
        # session_id, return None
        if session_id not in self.user_id_by_session_id:
            return None
        # Get the session info from the user_id_by_session_id dictionary
        session_dict = self.user_id_by_session_id.get(session_id)
        if session_dict is None:
            return None
        # If the session_duration is 0 or less, return the user_id
        if self.session_duration <= 0:
            return session_dict.get("user_id")
        # Get created_at from session info
        created_at = session_dict.get('created_at')
        # If the created_at key does not exist in the session dictionary,
        # return None
        if created_at is None:
            return None
        # Check if the session has expired
        now = dt.now()
        if created_at + timedelta(seconds=self.session_duration) < now:
            return None
        # Calculate the session expiration date
        expires_at = session_dict["created_at"] + \
            timedelta(seconds=self.session_duration)
        # Return None if the current time is past the expiration date
        if expires_at < dt.now():
            return None
        # Return the user_id from the session dictionary if the session
        # has not expired
        return session_dict.get("user_id", None)
    