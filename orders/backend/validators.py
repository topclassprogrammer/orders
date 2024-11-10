from string import ascii_letters, digits, punctuation

from django.core.exceptions import ValidationError

USERNAME_CHARS = ascii_letters + digits + "-_ "


def check_username(value):
    if len(value) < 8 or any(char not in USERNAME_CHARS for char in value):
        raise ValidationError("Not allowed char(s) in username field")
