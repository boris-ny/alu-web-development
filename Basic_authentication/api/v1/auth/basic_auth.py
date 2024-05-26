#!/usr/bin/env python3
"""
Basic auth class
"""

from api.v1.auth.auth import Auth
import base64
from typing import TypeVar
from models.user import User


class BasicAuth(Auth):
    """Basic Auth class"""

    def extract_base64_authorization_header(self, authorization_header: str) -> str:
        """Extract base64 Authorization header"""
        if authorization_header is None:
            return None
        if type(authorization_header) is not str:
            return None
        if not authorization_header.startswith("Basic"):
            return None
        return authorization_header[6:]

    def decode_base_64_authorization_header(self, base64_authorization_header: str) -> str:
        """Decode base64 Authorization header"""
        if base64_authorization_header is None:
            return None
        if type(base64_authorization_header) is not str:
            return None
        try:
            return base64.b64decode(base64_authorization_header).decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(self, decoded_base64_authorization_header: str) -> (str, str):
        """Extract user credentials"""
        if decoded_base64_authorization_header is None:
            return None, None
        if type(decoded_base64_authorization_header) is not str:
            return None, None
        if ":" not in decoded_base64_authorization_header:
            return None, None
        return tuple(decoded_base64_authorization_header.split(":", 1))

    def user_object_from_credentials(self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """User object from credentials"""
        if user_email is None or type(user_email) is not str:
            return None
        if user_pwd is None or type(user_pwd) is not str:
            return None
        users = User.search({"email": user_email})

        if not users:
            return None
        if users is None or len(users) == 0:
            return None
        for user in users:
            if user.is_valid_password(user_pwd):
                return user
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Current User"""
        header = self.authorization_header(request)
        if header is None:
            return None
        base64_header = self.extract_base64_authorization_header(header)
        if base64_header is None:
            return None
        decoded_header = self.decode_base_64_authorization_header(
            base64_header)
        if decoded_header is None:
            return None
        user_info = self.extract_user_credentials(decoded_header)
        if user_info is None:
            return None
        user = self.user_object_from_credentials(user_info[0], user_info[1])
        return user
