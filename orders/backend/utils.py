import uuid

import bcrypt
from django.http import Http404
from django.utils.text import slugify
from rest_framework.exceptions import ValidationError


def hash_password(value):
    password_bytes = value.encode()
    password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    password = password.decode()
    return password


def check_passwords(password, saved_password):
    password = password.encode()
    saved_password = saved_password.encode()
    return bcrypt.checkpw(password, saved_password)


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


def get_success_msg(action, serializer=None, pk=None, obj=None):
    if action in ['list', 'retrieve']:
        return {"status": True, "message": serializer.data}
    elif action in ['create', 'partial_update']:
        action_resp = (action.lstrip('partial_') + 'd').capitalize()
        if serializer:
            obj = serializer.Meta.model.__name__.lower()
            return {"status": True, "message": f"{action_resp} {obj}: {serializer.data}"}
        else:  # Без сериализаторов - там где есть вложенные сериализаторы
            if action == 'create':
                obj.__dict__.pop('_state')  # Без сериализаторов: при create запросе должен выполняться pop, а при update - нет
                return {"status": True, "message": f"Created object: {obj.__dict__}"}
            elif action == 'partial_update':
                return {"status": True, "message": f"Objects updated: {obj}"}
    elif action == 'destroy':
        return {"status": True, "message": f"Deleted object with id {pk}"}


def get_fail_msg(action, serializer=None, err=None, field=None):
    action = (action.lstrip('partial_').rstrip('e') + 'ing').capitalize()
    if serializer:
        obj = serializer.Meta.model.__name__.lower()
        return {"status": False, "message": f"{action} {obj} failed: {serializer.errors}"}
    else:
        return {"status": False, "message": f"{action} failed: "
               f"{err if err else f'field/value `{field}` does not exist in model'}"}


def get_model_fields(serializer, request):
    serializer_fields = serializer.Meta.fields
    serializer_read_only_fields = serializer.Meta.read_only_fields
    nested_serializers_names = serializer.__dict__['_declared_fields']
    nested_serializers_names_with_id = []
    for name in nested_serializers_names:
        name_id = name + '_id'
        nested_serializers_names_with_id.append(name_id)
        if name in serializer_fields:
            serializer_fields.remove(name)
    serializer_fields.extend(nested_serializers_names_with_id)
    res_fields = [x for x in serializer_fields if x not in serializer_read_only_fields]

    param_fields = {}
    for field in res_fields:
        clean_name = field.split('_id')[0]
        if clean_name in request.data.keys():
            param_fields.setdefault(field, request.data[clean_name])
    return param_fields


def check_request_fields(request, model):
    for x in request.data:
        if x not in model.__dict__.keys():
            return x


def check_model_in_brand(brand_model, request):
    brand_obj = brand_model.objects.get(id=request.data['brand'])
    brand_models = list(brand_obj.models.values())
    brand_models_ids = [x['id'] for x in brand_models]
    model_id = request.data.get('model')
    if model_id and model_id not in brand_models_ids:
        return request.data['model']


def check_item_owner(model, request):
    try:
        item_obj = model.objects.get(id=request.data[model.__name__.lower()])
    except model.DoesNotExist as err:
        return err
    if item_obj.shop.user != request.user:
        return item_obj.id


def get_order(request, model, state):
    query = Q(user=request.user, state=state)
    order_id = request.data.get('id')
    if order_id:
        query &= Q(id=order_id)
    try:
        order = model.objects.get(query)
    except model.DoesNotExist as err:
        if order_id:
            return err
        order = model.objects.create(user=request.user)
    return order


def check_quantity(quantity, item):
    try:
        quantity = int(quantity)
        if not 0 < quantity < 32767:
            return {"status": False, "message": f"Incorrect quantity value: you must enter value 0 to 32767"}
    except TypeError as err:
        return {"status": False, "message": f"Incorrect quantity value: {err}"}
    if quantity > item.quantity:
        return {"status": False, "message": "You chose more items than available in stock"}


def slugify_item(brand, model, item, request):
    brand_obj = brand.objects.get(id=request.data[brand.__name__.lower()])
    model_obj = model.objects.get(id=request.data[model.__name__.lower()])
    slug = slugify(brand_obj.name + '-' + model_obj.name)
    if item.objects.filter(slug=slug):
        slug += ('-' + str(uuid.uuid4()))
    request.data['slug'] = slug
    return request



