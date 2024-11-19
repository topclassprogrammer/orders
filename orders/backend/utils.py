import uuid

import bcrypt
from django.http import Http404
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


def get_object(model, pk=None):
    try:
        obj = model.objects.get(id=pk)
    except model.DoesNotExist:
        raise Http404({"status": False, "message": f"Object of model {model.__name__} with id {pk} does not exist in DB"})
    return obj


def get_success_response(action, serializer=None, pk=None):
    if action in ['list', 'retrieve']:
        return {"status": True, "message": serializer.data}
    if action in ['create', 'partial_update']:
        action = (action.lstrip('partial_') + 'd').capitalize()
        obj = serializer.Meta.model.__name__.lower()
        return {"status": True, "message": f"{action} {obj}: {serializer.data}"}
    if action == 'destroy':
        return {"status": True, "message": f"Deleted object with id {pk}"}


def get_fail_response(action, serializer):
    action = (action.lstrip('partial_').rstrip('e') + 'ing').capitalize()
    obj = serializer.Meta.model.__name__.lower()
    return {"status": False, "message": f"{action} {obj} failed: {serializer.errors}"}

