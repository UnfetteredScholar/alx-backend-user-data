#!/usr/bin/env python3
"""Auth Module"""
from bcrypt import hashpw, gensalt, checkpw
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4


def _hash_password(password: str) -> bytes:
    """Returns the hashed password"""
    hashed = hashpw(password.encode("utf-8"), gensalt())

    return hashed


def _generate_uuid() -> str:
    """Generates a uuid"""
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Registers a new user"""
        try:
            if self._db.find_user_by(email=email):
                raise ValueError(f"User {email} already exists")
        except NoResultFound:
            pass

        user = self._db.add_user(
            email=email, hashed_password=_hash_password(password)
        )

        return user

    def valid_login(self, email: str, password: str) -> bool:
        """Checks if a login is valid"""
        user = None
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False

        return checkpw(password.encode("utf-8"), user.hashed_password)

    def create_session(self, email: str) -> str:
        """Creates a session for a user"""

        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None

        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> User:
        """Gets the user by session id"""

        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

        return user

    def destroy_session(self, user_id: int) -> None:
        """Ends a user's session"""

        try:
            self._db.update_user(user_id=user_id, session_id=None)
        except NoResultFound:
            return None
