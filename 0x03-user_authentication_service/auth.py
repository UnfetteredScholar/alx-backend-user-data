#!/usr/bin/env python3
"""Auth Module"""
from bcrypt import hashpw, gensalt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """Returns the hashed password"""
    hashed = hashpw(password.encode("utf-8"), gensalt())

    return hashed


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
