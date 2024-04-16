#!/usr/bin/env python3
"""Defines the BasicAuth class"""
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """The BasicAuth class"""

    def extract_base64_authorization_header(
        self, authorization_header: str
    ) -> str:
        """Extracts the base64 part of the auth header"""

        if (
            authorization_header is None or
            type(authorization_header) is not str or
            not authorization_header.startswith("Basic ")
        ):
            return None

        value = authorization_header.replace("Basic ", "")
        return value
