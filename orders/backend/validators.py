import re
import uuid

from string import ascii_letters, digits, punctuation

import requests
from django.core.exceptions import ValidationError

USERNAME_CHARS = ascii_letters + digits + "-_ "
PASSWORD_CHARS = ascii_letters + digits + punctuation + " "


def check_username(value):
    if len(value) < 8:
        raise ValidationError("Username contains less that 8 chars")
    if any(char not in USERNAME_CHARS for char in value):
        raise ValidationError("Not allowed char(s) in username field")


def check_password(value):
    if len(value) < 8:
        raise ValidationError("Password contains less that 8 chars")
    if any(char not in PASSWORD_CHARS for char in value):
        raise ValidationError("Not allowed char(s) in password field")


def check_email(value):
    pattern = re.compile(r"^[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
    result = re.fullmatch(pattern, value)
    if not result:
        raise ValidationError("Incorrect email address")


def check_phone(value):
    pattern = re.compile(r"^\+[0-9]{11,18}$")
    result = re.fullmatch(pattern, value)
    if not result:
        raise ValidationError("Incorrect phone number. Make sure it starts with +")


def check_url(value: str):
    if not value.startswith("https://"):
        raise ValidationError("URL should start with prefix 'https://'")
    try:
        response = requests.get(value)
        if response.status_code in range(500, 599):
            raise ValidationError(f"Server is down")
    except requests.exceptions.RequestException as err:
        raise ValidationError(f"URL is not reachable: {err}")


def check_shop_role(value: int):
    from backend.models import User
    user = User.objects.get(id=value)
    if user.role.name != 'shop':
        raise ValidationError(f"User {user} does not have shop rights")


def check_uuid_token(value: str):
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    else:
        return True
