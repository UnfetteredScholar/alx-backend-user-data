#!/usr/bin/env python3
"""A module for encrypting passwords.
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """Converts a plaintext password to a hashed password"""

    bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hash = bcrypt.hashpw(bytes, salt)

    return hash


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Checks if a plaintext password matches a hash"""

    return bcrypt.checkpw(password.encode("utf-8"), hashed_password)
