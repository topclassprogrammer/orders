import re
import uuid
from string import ascii_letters, digits, punctuation
from typing import Type

import bcrypt
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models.base import ModelBase

USERNAME_CHARS = ascii_letters + digits + "-_ "
PASSWORD_CHARS = ascii_letters + digits + punctuation + " "


def check_username(value: str):
    """
    Check if the provided username meets the required length and contains only allowed characters.

    Args:
        value (str): The username to be validated.

    Raises:
        ValidationError: If the username is too short or contains disallowed characters.
    """
    if len(value) < 4:
        raise ValidationError("Username must contain at least 4 chars")
    if any(char not in USERNAME_CHARS for char in value):
        raise ValidationError("Not allowed char(s) in username field")


def check_password(value: str):
    """
    Check if the provided password meets the required length and contains only allowed characters.

    Args:
        value (str): The password to be validated.

    Raises:
        ValidationError: If the password is too short or contains disallowed characters.
    """
    if len(value) < 8:
        raise ValidationError("Password must contain at least 4 chars")
    if any(char not in PASSWORD_CHARS for char in value):
        raise ValidationError("Not allowed char(s) in password field")


def check_email(value: str):
    """
    Check if the provided email address is correctly formatted.

    Args:
        value (str): The email address to be validated.

    Raises:
        ValidationError: If the email address does not match the required format.
    """
    pattern = re.compile(r"^[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
    result = re.fullmatch(pattern, value)
    if not result:
        raise ValidationError("Incorrect email address")


def check_phone(value: str):
    """
    Check if the provided phone number is correctly formatted.

    Args:
        value (str): The phone number to be validated.

    Raises:
        ValidationError: If the phone number is incorrectly formatted.
    """
    pattern = re.compile(r"^\+[0-9]{11,18}$")
    result = re.fullmatch(pattern, value)
    if not result:
        raise ValidationError("Incorrect phone number. Make sure it starts with +")


def check_url(value: str):
    """
    Check if the provided URL is correctly formatted

    Args:
        value (str): The URL to be validated.

    Raises:
        ValidationError: If the URL is incorrectly formatted.
    """
    pattern = re.compile(r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)"
                         r"(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()"
                         r"<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))")
    result = re.fullmatch(pattern, value)
    if not result:
        raise ValidationError("Incorrect shop URL. Make sure it starts with https:// , http:// or www.")


def check_uuid_token(value: str) -> bool:
    """
    Check if the provided string is a valid UUID.

    Args:
        value (str): The UUID token to be validated.

    Returns:
        bool: True if the value is a valid UUID, False otherwise.
    """
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    else:
        return True


def check_passwords(password: str, saved_password: str) -> bool:
    """
    Compare a plaintext password with a saved hashed password stored in the database.

    Args:
        password (str): The plaintext password to be checked.
        saved_password (str): The previously hashed password to compare against.

    Returns:
        bool: True if the passwords match, False otherwise.
    """
    password = password.encode()
    saved_password = saved_password.encode()
    return bcrypt.checkpw(password, saved_password)


def check_request_fields(request, model: Type[models.Model]) -> str:
    """
    Check if each key in the request data is valid for the given model.

    Args:
        request: The Django request object containing the data to be validated.
        model (Type[models.Model]): The model class to validate against.

    Returns:
        str: An error message indicating the first invalid field found or if any field has an empty value.
    """
    for k, v in request.data.items():
        if k not in model.__dict__.keys():
            return k
        elif not v:
            return f"{k} with its empty value"


def check_model_in_brand(brand_model: Type[models.Model], model_model: Type[models.Model], request) \
        -> int | str | Exception:
    """
    Check if the provided model belongs to the specified brand.

    Args:
        brand_model : The brand model class for database operations.
        model_model (Type[models.Model]): The model class for database operations.
        request: The Django request object containing data for validation.

    Returns:
        int | str | Exception: The model ID if it does not belong to the brand, or
                               an error message/exception if an error occurs.
        """
    try:
        brand_id = request.data['brand']
        model_id = request.data['model']
        brand_obj = brand_model.objects.get(id=brand_id)
        model_obj = model_model.objects.get(id=model_id)
    except (KeyError, ValueError, brand_model.DoesNotExist, model_model.DoesNotExist) as err:
        return err
    brand_models = list(brand_obj.models.values())
    brand_models_ids = [x['id'] for x in brand_models]
    model_id = model_obj.id
    if model_id not in brand_models_ids:
        return request.data['model']


def check_item_owner(model: Type[models.Model], request) -> int | str | None | ModelBase:
    """
    Check ownership of the specified item by the current user.

    Args:
        model (Type[models.Model]): The model class for the item being checked.
        request: The Django request object containing data for validation.

    Returns:
        int | str | None | ModelBase: The item's ID if the user does not own it,
                                       or an error message if an error occurs.
    """
    try:
        item_id = request.data.get(model.__name__.lower())
        if not item_id:
            return
        item_obj = model.objects.get(id=item_id)
    except (model.DoesNotExist, ValueError) as err:
        return str(err)
    if item_obj.shop.user != request.user:
        return item_obj.id


def check_quantity(quantity: str | int, item) -> dict | None:
    """
    Check if the provided quantity is a valid integer and falls
    within the acceptable range (0 to 32767). It also ensures that the requested
    quantity does not exceed the available stock.

    Args:
        quantity (str | int): The quantity of items to validate.
        item: The item object against which the quantity is checked.

    Returns:
        dict | None: A dictionary containing status and message if validation fails,
                      None if validation is successful.
    """
    try:
        quantity = int(quantity)
        if not 0 < quantity < 32767:
            return {"status": False, "message": "Incorrect quantity value: you must enter value from 0 to 32767"}
    except TypeError as err:
        return {"status": False, "message": f"Incorrect quantity value: {err}"}
    if quantity > item.quantity:
        return {"status": False, "message": f"You chose more items({quantity}) than "
                                 f"available in stock({item.quantity})"}
