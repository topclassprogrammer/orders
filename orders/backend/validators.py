import re
import uuid

from string import ascii_letters, digits, punctuation
from typing import Type

import bcrypt
import requests
from django.core.exceptions import ValidationError
from django.db.models.base import ModelBase

from backend import models

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


def check_request_fields(request, model: Type[models.Model]) -> str:
    for k, v in request.data.items():
        if k not in model.__dict__.keys():
            return k
        elif not v:
            return f"{k} with its empty value"


def check_model_in_brand(brand_model: Type[models.Model], model_model: Type[models.Model], request) -> int | str | Exception:
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
    try:
        quantity = int(quantity)
        if not 0 < quantity < 32767:
            return {"status": False, "message": "Incorrect quantity value: you must enter value from 0 to 32767"}
    except TypeError as err:
        return {"status": False, "message": f"Incorrect quantity value: {err}"}
    if quantity > item.quantity:
        return {"status": False, "message": f"You chose more items({quantity}) than available in stock({item.quantity})"}


