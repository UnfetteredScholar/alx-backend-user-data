#!/usr/bin/env python3
"""Defines the auth class"""
from flask import request
from typing import List, TypeVar


class Auth:
    """The auth class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Returns true if a path is not in
        the excluded paths else false
        """
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True

        if path[-1] != "/":
            path = path + "/"

        return path not in excluded_paths

    def authorization_header(self, request=None) -> str:
        """authorization_header function"""
        return None

    def current_user(self, request=None) -> TypeVar("User"):
        """Returns the current user"""
        return None
