#!/usr/bin/env python3
"""Auth Module"""
from bcrypt import hashpw, gensalt


def _hash_password(password: str) -> bytes:
    """Returns the hashed password"""
    hashed = hashpw(password.encode("utf-8"), gensalt())

    return hashed
