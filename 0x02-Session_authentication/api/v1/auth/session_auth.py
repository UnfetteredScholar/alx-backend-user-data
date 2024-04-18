#!/usr/bin/env python3
"""Defines the SessionAuth class"""
from api.v1.auth.auth import Auth
from uuid import uuid4


class SessionAuth(Auth):
    """The SessionAuth class"""

    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """Creates a Session ID for a User ID"""

        if user_id is None or type(user_id) is not str:
            return None

        session_id = str(uuid4())
        SessionAuth.user_id_by_session_id[session_id] = user_id
        return session_id
