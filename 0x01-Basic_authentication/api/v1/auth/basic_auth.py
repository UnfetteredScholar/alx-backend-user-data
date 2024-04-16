#!/usr/bin/env python3
"""Defines the BasicAuth class"""
from api.v1.auth.auth import Auth
import base64
import re
from models.user import User
from typing import TypeVar, Tuple


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
            self,
            decoded_base64_authorization_header: str,
            ) -> Tuple[str, str]:
        """Extracts user credentials from a base64-decoded authorization
        header that uses the Basic authentication flow.
        """
        if type(decoded_base64_authorization_header) is str:
            pattern = r'(?P<user>[^:]+):(?P<password>.+)'
            field_match = re.fullmatch(
                pattern,
                decoded_base64_authorization_header.strip(),
            )
            if field_match is not None:
                user = field_match.group('user')
                password = field_match.group('password')
                return user, password
        return None, None

    def user_object_from_credentials(
        self, user_email: str, user_pwd: str
    ) -> TypeVar("User"):
        """Gets a user object from storage that matches the credentials"""

        if type(user_email) is str and type(user_pwd) is str:
            try:
                users = User.search({"email": user_email})
            except Exception:
                return None
            if len(users) == 0:
                return None
            if users[0].is_valid_password(user_pwd):
                return users[0]
        return None

    def current_user(self, request=None) -> TypeVar("User"):
        """Gets the current user else returns None"""

        auth_header = self.authorization_header(request)
        base64_header = self.extract_base64_authorization_header(auth_header)
        decoded_header = self.decode_base64_authorization_header(base64_header)
        credentials = self.extract_user_credentials(decoded_header)
        user = self.user_object_from_credentials(
            credentials[0], credentials[1]
        )

        return user
