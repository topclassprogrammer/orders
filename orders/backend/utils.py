import uuid

import bcrypt
from rest_framework.exceptions import ValidationError


def hash_password(value):
    password_bytes = value.encode()
    password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    password = password.decode()
    return password


def check_hashed_passwords(password, stored_hash):
    password = password.encode()
    stored_hash = stored_hash.encode()
    return bcrypt.checkpw(password, stored_hash)


def get_auth_token(request):
    from backend.models import AuthToken
    token_header = request.META.get('HTTP_AUTHORIZATION')
    if not token_header:
        raise ValidationError("No token provided")
    token_list = token_header.split(" ")
    token = token_list[1]
    try:
        auth_token = AuthToken.objects.get(key=uuid.UUID(token))
    except AuthToken.DoesNotExist:
        raise ValidationError("Your token does not exist in DB")
    return auth_token


