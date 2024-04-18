#!/usr/bin/env python3
"""Defines the auth class"""
import re
import os
from flask import request
from typing import List, TypeVar


class Auth:
    """The auth class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Checks if a path requires authentication."""
        if path is not None and excluded_paths is not None:
            for exclusion_path in map(lambda x: x.strip(), excluded_paths):
                pattern = ""
                if exclusion_path[-1] == "*":
                    pattern = "{}.*".format(exclusion_path[0:-1])
                elif exclusion_path[-1] == "/":
                    pattern = "{}/*".format(exclusion_path[0:-1])
                else:
                    pattern = "{}/*".format(exclusion_path)
                if re.match(pattern, path):
                    return False
        return True

    def authorization_header(self, request=None) -> str:
        """Returns the value of Authorization header else None"""
        if request is None:
            return None

        return request.headers.get("Authorization", None)

    def current_user(self, request=None) -> TypeVar("User"):
        """Returns the current user"""
        return None

    def session_cookie(self, request=None):
        """Returns the cookie SESSION_NAME value from the request"""

        if request is not None:
            cookie_name = os.getenv("SESSION_NAME")
            return request.cookies.get(cookie_name)
