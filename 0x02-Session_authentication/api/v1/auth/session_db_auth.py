#!/usr/bin/env python3
"""Module for session db authentication"""

from datetime import datetime, timedelta
from .session_exp_auth import SessionExpAuth
from models.user_session import UserSession


class SessionDBAuth(SessionExpAuth):
    """Session DB Auth class"""
    def create_session(self, user_id: str = None) -> str:
        """Create a session"""

        if isinstance(user_id, str):
            kwargs = {
                'user_id' = user_id
                'session_id' = session_id
            }
            user_session = UserSession(**kwargs)
            user_session.save()
            return user_session.session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """User ID for session ID"""
        if session_id is None:
            return None
        user_session = UserSession.get(session_id)
        if user_session is None:
            return None
        if user_session.expired_at < datetime.now():
            return None
        return user_session.user_id

    def destroy_session(self, user_id: str) -> None:
        """Destroy a session"""
        user_sessions = UserSession.search({'user_id': user_id})
        for user_session in user_sessions:
            user_session.remove()
        return None
