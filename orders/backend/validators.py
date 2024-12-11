import re
import uuid

from string import ascii_letters, digits, punctuation

import bcrypt
import requests
from django.core.exceptions import ValidationError

USERNAME_CHARS = ascii_letters + digits + "-_ "
PASSWORD_CHARS = ascii_letters + digits + punctuation + " "


def check_username(value):
    if len(value) < 4:
        raise ValidationError("Username must contain at least 4 chars")
    if any(char not in USERNAME_CHARS for char in value):
        raise ValidationError("Not allowed char(s) in username field")


def check_password(value):
    if len(value) < 8:
        raise ValidationError("Password must contain at least 4 chars")
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
    pattern = re.compile(r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))")
    result = re.fullmatch(pattern, value)
    if not result:
        raise ValidationError("Incorrect shop URL")


def check_uuid_token(value: str):
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    else:
        return True


def check_passwords(password: str, saved_password: str) -> bool:
    password = password.encode()
    saved_password = saved_password.encode()
    return bcrypt.checkpw(password, saved_password)



