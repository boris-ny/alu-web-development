#!/usr/bin/env python3
"""
Auth class
"""

from flask import request
from typing import List, TypeVar


class Auth:
    """Auth Class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Require Auth"""
        if path is None:
            return True
        if excluded_paths is None or excluded_paths == []:
            return True
        path = path + '/' if path[-1] != '/' else path
        excluded_paths = [excluded + '/' if excluded[-1] !=
                          '/' else excluded for excluded in excluded_paths]

        if path in excluded_paths:
            return False
        else:
            return True

    def authorization_header(self, request=None) -> str:
        """Authorization header"""
        if request is None:
            return None
        if 'Authorization' not in request.headers:
            return None
        return request.headers['Authorization']

    def current_user(self, request=None) -> TypeVar('User'):
        """Current User"""
        return None
