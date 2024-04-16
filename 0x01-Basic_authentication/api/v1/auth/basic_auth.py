#!/usr/bin/env python3
"""Defines the BasicAuth class"""
from api.v1.auth.auth import Auth
import base64
from models.user import User
from typing import TypeVar


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

    def decode_base64_authorization_header(
        self, base64_authorization_header: str
    ) -> str:
        """Returns the decoded value of a base64 string"""

        if (
            base64_authorization_header is None or
            type(base64_authorization_header) is not str
        ):
            return None

        try:
            res = base64.b64decode(base64_authorization_header).decode("utf-8")
        except Exception:
            return None
        else:
            return res

    def extract_user_credentials(
        self, decoded_base64_authorization_header: str
    ) -> (str, str):
        """Extracts user credentials from decoded base64 header"""

        if (
            decoded_base64_authorization_header is None or
            type(decoded_base64_authorization_header) is not str or
            decoded_base64_authorization_header.find(":") == -1
        ):
            return (None, None)
        return tuple(decoded_base64_authorization_header.split(":"))

    def user_object_from_credentials(
        self, user_email: str, user_pwd: str
    ) -> TypeVar("User"):
        """Gets a user object from storage that matches the credentials"""

        if user_email is None or type(user_email) is not str:
            return None

        if user_pwd is None or type(user_pwd) is not str:
            return None

        users = User.search({"email": user_email})

        for user in users:
            if user.is_valid_password(user_pwd):
                return user
        return None