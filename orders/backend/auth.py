import uuid
from typing import Tuple

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import PermissionDenied

from backend.models import AuthToken, User
from backend.validators import check_uuid_token


class TokenAuthentication(BaseAuthentication):
    """Custom authentication class that uses token-based authentication."""
    def authenticate(self, request) -> Tuple[User, AuthToken]:
        """
        Authenticate the user based on the token provided in the request.

        Args:
            request: The Django request object containing the authorization token.

        Returns:
            Tuple[User, AuthToken]: A tuple containing the authenticated user and
                                     the associated authentication token.

        Raises:
            PermissionDenied: If the token is missing, incorrectly formatted,
                              invalid, or if no corresponding user is found.
        """
        token_str = request.META.get('HTTP_AUTHORIZATION')
        if not token_str:
            raise PermissionDenied('You must log in before proceeding')
        token_list = token_str.split(" ")
        if len(token_list) != 2 or not token_str.startswith('Token '):
            raise PermissionDenied('Incorrect token string')
        token = token_list[1]
        if not check_uuid_token(token):
            raise PermissionDenied('Incorrect token value')
        try:
            token_in_db = AuthToken.objects.get(key=uuid.UUID(token))
        except AuthToken.DoesNotExist:
            raise PermissionDenied('No token found for this user in DB')
        return token_in_db.user, token_in_db
