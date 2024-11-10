import re
from string import ascii_letters, digits, punctuation

from django.core.exceptions import ValidationError

USERNAME_CHARS = ascii_letters + digits + "-_ "
PASSWORD_CHARS = ascii_letters + digits + punctuation


def check_username(value):
    if len(value) < 8 or any(char not in USERNAME_CHARS for char in value):
        raise ValidationError("Not allowed char(s) in username field")


def check_password(value):
    if len(value) < 8 or any(char not in PASSWORD_CHARS for char in value):
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
        raise ValidationError("Incorrect phone number. Make sure it start with +")
