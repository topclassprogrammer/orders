import os
import uuid
from typing import List, Type

import bcrypt
import django.db.models
from django.conf import settings
from django.db import models as django_models
from django.db.models import ForeignKey, ManyToManyField, OneToOneField, Q
from django.http import Http404
from django.utils.text import slugify
from rest_framework.exceptions import ValidationError
from rest_framework.viewsets import ModelViewSet

from backend import models


def hash_password(value: str) -> str:
    """
    Hash a plaintext password.

    Args:
        value (str): The plaintext password to be hashed.

    Returns:
        str: The hashed password in string format.
    """
    password_bytes = value.encode()
    password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    password = password.decode()
    return password


def get_auth_token(request):
    """
    Retrieve and validate the auth token from the request.

    Args:
        request: The Django request object containing headers for token retrieval.

    Returns:
        models.AuthToken: The AuthToken object corresponding to the provided token.

    Raises:
        ValidationError: If no token is provided or if the token is not found in the database.
    """
    token_header = request.META.get('HTTP_AUTHORIZATION')
    if not token_header:
        raise ValidationError("No token provided")
    token_list = token_header.split(" ")
    token = token_list[1]
    try:
        auth_token = models.AuthToken.objects.get(key=uuid.UUID(token))
    except models.AuthToken.DoesNotExist:
        raise ValidationError("Auth token not found")
    return auth_token


def get_object(model: Type[django_models.Model], pk=None) -> django_models.Model:
    """
    Retrieve an object of the specified model by its primary key.

    Args:
        model (Type[django_models.Model]): The model class from which to retrieve the object.
        pk: The primary key of the object to retrieve.

    Returns:
        django_models.Model: The object retrieved from the database.

    Raises:
        Http404: If the object does not exist in the database or if the provided
                  primary key is invalid.
    """
    try:
        obj = model.objects.get(id=pk)
    except (model.DoesNotExist, ValueError):
        raise Http404({"status": False, "message":
              f"Object of model {model.__name__} with id {pk} does not exist in DB"})
    return obj


def get_success_msg(action: str, serializer=None, pk: int = None, obj=None) -> dict:
    """
    Generate a success message based on the action performed.

    Returns:
        dict: A dictionary containing the status (True) and the corresponding success message.

    """
    from backend.views import ShopView
    if action in [ModelViewSet.list.__name__, ModelViewSet.retrieve.__name__, ShopView.get_active_orders.__name__]:
        return {"status": True, "message": serializer.data}
    elif action in [ModelViewSet.create.__name__, ModelViewSet.update.__name__, ModelViewSet.partial_update.__name__]:
        action_resp = (action.lstrip('partial_') + 'd').capitalize()
        if serializer:
            obj = serializer.Meta.model.__name__.lower()
            return {"status": True, "message": f"{action_resp} {obj}: {serializer.data}"}
        else:
            if action == ModelViewSet.create.__name__:
                obj.__dict__.pop('_state')
                return {"status": True, "message": f"Created object: {obj.__dict__}"}
            elif action in [ModelViewSet.update.__name__, ModelViewSet.partial_update.__name__]:
                return {"status": True, "message": f"Objects updated: {obj}"}
    elif action == ModelViewSet.destroy.__name__:
        return {"status": True, "message": f"Deleted object with id {pk}"}


def get_fail_msg(action: str, serializer=None, err: Exception | django.db.models.Model = None,
                 field: str | dict = None) -> dict:
    """
        Generate a success message based on the action performed.

    Returns:
        dict: A dictionary containing the status (False) and the corresponding failure message.
    """
    action = (action.replace('partial_', '').rstrip('e') + 'ing').capitalize()
    if serializer:
        obj = serializer.Meta.model.__name__.lower()
        return {"status": False, "message": f"{action} {obj} failed: {serializer.errors}"}
    else:
        return {"status": False, "message": f"{action} failed: {err if err else f'not found field/value `{field}`'}"}


def get_request_data(model: Type[django_models.Model], request) -> dict:
    """
    Extract request data and add `_id` suffixes to fields
    that correspond to ForeignKey, ManyToManyField, or OneToOneField relationships
    in the provided model.

    Args:
        model (Type[django_models.Model]): The Django model class.
        request: The Django request object.

    Returns:
        dict: A dictionary containing the formatted request data with `_id` suffixes for relevant fields.
    """
    model_fields = model._meta.get_fields()
    data = {}
    id_fields = [field.name for field in model_fields if isinstance(
        field, (ForeignKey, ManyToManyField, OneToOneField))]
    for k, v in request.data.items():
        if k in id_fields:
            data.setdefault(k + "_id", v)
        else:
            data.setdefault(k, v)
    return data


def get_order(request, model: Type[django_models.Model], state: str) -> django_models.Model:
    """
    Retrieve or create an order for the authenticated user based on its state.

    Args:
        request: The Django request object.
        model (Type[django_models.Model]): The Django model class representing the orders.
        state (str): The state of the order to look for.

    Returns:
        django_models.Model: The retrieved or newly created order object.
    """
    query = Q(user=request.user, state=state)
    try:
        order = model.objects.get(query)
    except model.DoesNotExist:
        order = model.objects.create(user=request.user)
    else:
        if request.data.get('order'):
            request.data.pop('order')
    return order


def slugify_item(brand: Type[django_models.Model], model: Type[django_models.Model], item: Type[django_models.Model], request) -> str:
    """
    Generate a unique slug for an item based on brand and model names.

    Args:
        brand (Type[django_models.Model]): The Django model class representing the brand.
        model (Type[django_models.Model]): The Django model class representing the model.
        item (Type[django_models.Model]): The Django model class for the item being created.
        request: The Django request object.

    Returns:
        str: A unique slug for the item.
    """
    brand_obj = brand.objects.get(id=request.data[brand.__name__.lower()])
    model_obj = model.objects.get(id=request.data[model.__name__.lower()])
    slug = slugify(brand_obj.name + '-' + model_obj.name)
    if item.objects.filter(slug=slug):
        slug += ('-' + str(uuid.uuid4()))
    return slug


def slugify_bulk_item(brand_name: str, model_name: str) -> str:
    """
    Create a slug for bulk items based on brand and model names.

    Args:
        brand_name (str): The name of the brand.
        model_name (str): The name of the model.

    Returns:
        str: A unique slug for bulk items.
    """
    brand_name = brand_name.lower().replace(' ', '-')
    model_name = model_name.lower().replace(' ', '-')
    slug = brand_name + '-' + model_name
    return slug + '-' + str(uuid.uuid4())


def get_url_end_path(request, basename: str) -> str:
    """
    Retrieve the method name from the request URL path.

    Args:
        request: The Django request object.
        basename (str): The base name to strip from the path.

    Returns:
        str: The method name extracted from the URL path.
    """
    from orders.urls import BACKEND_BASE_URL
    path = request.environ.get('PATH_INFO')
    strip_path = path.strip("/")
    replace_path = BACKEND_BASE_URL + basename
    if not strip_path.endswith('user'):
        replace_path += '/'
    method_name = strip_path.replace(replace_path, "")
    return method_name


def get_request_method(request) -> str:
    """
    Retrieve the HTTP request method from the request object.

    Args:
        request: The Django request object.

    Returns:
        str: The HTTP request method.
    """
    return request.environ.get('REQUEST_METHOD')


def get_image_name(request) -> str:
    """
    Generate a unique image name for an uploaded file.

    Args:
        request: The Django request object.

    Returns:
        str: A unique name for the uploaded image.
    """
    uploaded_image_name = request.FILES['image'].name
    image_name_split = uploaded_image_name.split('.')
    image_name = image_name_split[-2]
    ext = image_name_split[-1]
    image_name += ('-' + str(uuid.uuid4())) + '.' + ext
    return image_name


def get_admin_emails() -> List[str]:
    """
    Retrieve a list of email addresses for all admin users.

    Returns:
        List[str]: A list of email addresses of admin users.
    """
    admin_emails = models.User.objects.filter(role__name=models.RoleChoices.ADMIN).values_list('email')
    return list(*admin_emails)


def get_images_list() -> list:
    """
    Retrieve a list of image filenames from the media directory.

    Returns:
        list: A list containing the names of files in the images directory.
    """
    images_path = str(settings.BASE_DIR) + settings.MEDIA_URL
    return os.listdir(images_path)
