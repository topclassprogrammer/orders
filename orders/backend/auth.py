import uuid

from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication

from backend.models import AuthToken
from backend.validators import check_uuid_token


class TokenAuthentication(BaseAuthentication):
    def authenticate(self, request):
        token_str = request.META.get('HTTP_AUTHORIZATION')
        if not token_str:
            raise exceptions.AuthenticationFailed('You must log in before proceeding')

        token_list = token_str.split(" ")
        if len(token_list) != 2 or not token_str.startswith('Token '):
            raise exceptions.AuthenticationFailed('Incorrect token string')
        token = token_list[1]
        if not check_uuid_token(token):
            raise exceptions.AuthenticationFailed('Incorrect token value')
        try:
            token_in_db = AuthToken.objects.get(key=uuid.UUID(token))
        except AuthToken.DoesNotExist:
            raise exceptions.AuthenticationFailed('No token found for this user in DB')
        return token_in_db.user, token_in_db
