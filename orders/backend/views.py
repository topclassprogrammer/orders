import datetime
import uuid

from django.db import IntegrityError
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet, ModelViewSet

from backend.auth import TokenAuthentication
from backend.models import ActivationToken, AuthToken, PasswordResetToken, User, RoleChoices, Role, Shop, Address, \
    Brand, Model, Category, Item, PropertyName, PropertyValue
from backend.permissions import IsOwner, IsAdmin, HasShop, IsAuthenticated
from backend.serializers import UserSerializer, ActivationSerializer, PasswordResetSerializer, \
    LogInSerializer, RoleSerializer, ShopSerializer, AddressSerializer, BrandSerializer, ModelSerializer, \
    CategorySerializer, ItemSerializer, PropertyNameSerializer, PropertyValueSerializer
from backend.utils import hash_password, check_passwords, get_auth_token, get_object, get_success_response, \
    get_fail_response, get_model_fields, check_request_fields, check_model_in_brand, slugify_item, check_item_owner


class UserView(ViewSet):
    def list(self, request):
        queryset = User.objects.all()
        serializer = self.get_serializer_class()(queryset, many=True)
        return Response(get_success_response(self.action, serializer), status=status.HTTP_200_OK)

    def retrieve(self, request, pk=None):
        obj = get_object(User, pk)
        serializer = self.get_serializer_class()(obj)
        return Response(get_success_response(self.action, serializer, pk), status=status.HTTP_200_OK)

    def create(self, request):
        serializer = self.get_serializer_class()(data=request.data)
        if serializer.is_valid():
            role = Role.objects.get(name=RoleChoices.CLIENT)
            user = serializer.save(role=role)
            ActivationToken.objects.create(key=uuid.uuid4(), user=user)
            return Response(get_success_response(self.action, serializer), status=status.HTTP_201_CREATED)
        return Response(get_fail_response(self.action, serializer), status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        obj = get_object(User, pk)
        self.check_object_permissions(request, obj)
        serializer = self.get_serializer_class()(obj, request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(get_success_response(self.action, serializer), status=status.HTTP_206_PARTIAL_CONTENT)
        return Response(get_fail_response(self.action, serializer), status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        obj = get_object(User, pk)
        self.check_object_permissions(request, obj)
        obj.delete()
        return Response(get_success_response(self.action, pk=pk), status=status.HTTP_204_NO_CONTENT)

    @action(methods=['POST'], detail=False, url_path="log-in")
    def log_in(self, request):
        serializer = self.get_serializer_class()(data=request.data)
        if serializer.is_valid():
            username = request.data['username']
            password = request.data['password']
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                return Response({"status": False, "message": "Username or/and password not found in DB"}, status=status.HTTP_404_NOT_FOUND)
            user_password = user.password
            if not check_passwords(password, user_password):
                return Response({"status": False, "message": "Username or/and password not found in DB"}, status=status.HTTP_404_NOT_FOUND)
            AuthToken.objects.create(key=uuid.uuid4(), user=user)
            user.last_login = datetime.datetime.now()
            user.save()
            return Response({"status": True, "message": "You just logged in"}, status=status.HTTP_200_OK)
        return Response({"status": False, "message": f"Incorrect username or/and password: {serializer.errors}"}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['POST'], detail=False, url_path='log-out')
    def log_out(self, request):
        auth_token = get_auth_token(request)
        auth_token.delete()
        return Response({"status": True, "message": "You just logged out"}, status=status.HTTP_200_OK)

    @action(methods=['POST'], detail=False, url_path='activate')
    def activate(self, request):
        serializer = self.get_serializer_class()(data=request.data)
        if serializer.is_valid():
            key = request.data['key']
            user = request.user
            if user.is_active:
                return Response({"status": False, "message": "Account is already activated"}, status=status.HTTP_400_BAD_REQUEST)
            try:
                registration_token = ActivationToken.objects.get(key=uuid.UUID(key))
            except ActivationToken.DoesNotExist:
                return Response({"status": False, "message": "Activation token key not found in DB"}, status=status.HTTP_404_NOT_FOUND)
            if registration_token.user != user:
                return Response({"status": False, "message": "You cannot activate account that does not belong to you"}, status=status.HTTP_403_FORBIDDEN)
            user.is_active = True
            user.save()
            registration_token.delete()
            return Response({"status": True, "message": "Account successfully activated"}, status=status.HTTP_200_OK)
        return Response(get_fail_response(self.action, serializer), status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['POST'], detail=False, url_path='password-reset-request')
    def password_reset_request(self, request):
        user = self.request.user
        PasswordResetToken.objects.create(key=uuid.uuid4(), user=user)
        return Response({"status": True, "message": "Password reset request successfully completed"}, status=status.HTTP_200_OK)

    @action(methods=['POST'], detail=False, url_path='password-reset-response')
    def password_reset_response(self, request):
        serializer = self.get_serializer_class()(data=request.data)
        if serializer.is_valid():
            key = request.data['key']
            user = request.user
            password = request.data['password']
            try:
                reset_token = PasswordResetToken.objects.get(key=uuid.UUID(key))
            except PasswordResetToken.DoesNotExist:
                return Response({"status": False, "message": "PasswordResetToken key not found in DB"}, status=status.HTTP_404_NOT_FOUND)
            user.password = hash_password(password)
            user.save()
            reset_token.delete()
            return Response({"status": True, "message": "Password successfully changed"}, status=status.HTTP_200_OK)
        return Response({"status": False, "message": f"Incorrect key or/and password provided: {serializer.errors}"}, status=status.HTTP_400_BAD_REQUEST)

    def get_permissions(self):
        if self.action in ['create', 'log_in']:
            return []
        elif self.action == "list":
            return [IsAuthenticated(), IsAdmin()]
        elif self.action in ['partial_update', 'destroy']:
            return [IsAuthenticated(), IsOwner()]
        elif self.action in ['retrieve', 'log_out', 'activate', 'password_reset_request', 'password_reset_response']:
            return [IsAuthenticated()]

    def get_serializer_class(self):
        if self.action in ['list', 'retrieve', 'create', 'partial_update']:
            return UserSerializer
        elif self.action in ['log_in']:
            return LogInSerializer
        elif self.action in ['activate']:
            return ActivationSerializer
        elif self.action in ['password_reset_response']:
            return PasswordResetSerializer


class RoleView(ModelViewSet):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAdmin]


class ShopView(ModelViewSet):
    queryset = Shop.objects.all()
    serializer_class = ShopSerializer
    authentication_classes = [TokenAuthentication]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer_class()(data=request.data)
        if serializer.is_valid():
            user = request.user
            if hasattr(user, 'shop'):
                return Response({"status": False, "message": f"Cannot create shop because you already have it"}, status=status.HTTP_400_BAD_REQUEST)
            serializer.save(user=user)
            user.role = Role.objects.get(name=RoleChoices.SHOP)  # Устанавливаем у пользователя роль магазина
            user.save()
            return Response(get_success_response(self.action, serializer), status=status.HTTP_201_CREATED)
        return Response(get_fail_response(self.action, serializer), status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        obj = get_object(Shop, pk)
        serializer = ShopSerializer(obj)
        return Response(get_success_response(self.action, serializer), status=status.HTTP_200_OK)



    def partial_update(self, request, pk=None):
        obj = get_object(Shop, pk)
        self.check_object_permissions(request, obj)
        serializer = ShopSerializer(obj, request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(get_success_response(self.action, serializer), status=status.HTTP_206_PARTIAL_CONTENT)
        return Response(get_fail_response(self.action, serializer), status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        obj = get_object(Shop, pk)
        self.check_object_permissions(request, obj)
        obj.delete()
        return Response(get_success_response(self.action, pk), status=status.HTTP_204_NO_CONTENT)

    @action(methods=['POST'], detail=False, url_path="accept-orders")
    def accept_orders(self, request):
        auth_token = get_auth_token(request)
        shop = Shop.objects.get(user__auth_tokens__in=[auth_token])
        if shop.accept_orders:
            shop.accept_orders = False
        else:
            shop.accept_orders = True
        shop.save()
        return Response({"status": True, "message": f"Accept orders was changed from {not shop.accept_orders} to {shop.accept_orders}"}, status=status.HTTP_200_OK)

    def get_permissions(self):
        if self.action in ['partial_update', 'destroy']:
            return [IsOwner()]
        if self.action == 'accept_orders':
            return [HasShop()]
        return []

    def perform_create(self, serializer):
        queryset = Shop.objects.filter(user=self.request.user)
        if queryset.exists():
            raise ValidationError({"status": False, "message": f"Cannot create shop because you already have it"}, code=status.HTTP_400_BAD_REQUEST)
        serializer.save(user=self.request.user)


class AddressView(ViewSet):
    authentication_classes = [TokenAuthentication]

    def list(self, request):
        queryset = Address.objects.all()
        serializer = AddressSerializer(queryset, many=True)
        return Response(get_success_response(self.action, serializer), status=status.HTTP_200_OK)

    def retrieve(self, request, pk=None):
        obj = get_object(Address, pk)
        self.check_object_permissions(request, obj)
        serializer = AddressSerializer(obj)
        return Response(get_success_response(self.action, serializer), status=status.HTTP_200_OK)

    def create(self, request):
        serializer = AddressSerializer(data=request.data)
        if serializer.is_valid():
            self.perform_create(serializer)
            return Response(get_success_response(self.action, serializer), status=status.HTTP_201_CREATED)
        return Response(get_fail_response(self.action, serializer), status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        obj = get_object(Address, pk)
        self.check_object_permissions(request, obj)
        serializer = AddressSerializer(obj, request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(get_success_response(self.action, serializer, pk), status=status.HTTP_206_PARTIAL_CONTENT)
        return Response(get_fail_response(self.action, serializer), status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        obj = get_object(Address, pk)
        self.check_object_permissions(request, obj)
        obj.delete()
        return Response(get_success_response(self.action, pk=pk), status=status.HTTP_204_NO_CONTENT)

    def get_permissions(self):
        if self.action == "list":
            return [IsAdmin()]
        elif self.action in ["retrieve", "partial_update", "destroy"]:
            return [IsOwner()]
        return []

    def perform_create(self, serializer):
        queryset = Address.objects.filter(**self.request.data, user=self.request.user)
        if queryset.exists():
            raise ValidationError({"status": False, "message": f"Cannot create it because such {Address.__name__.lower()} already exists in DB"}, code=status.HTTP_400_BAD_REQUEST)
        serializer.save(user=self.request.user)


class BrandView(ModelViewSet):
    queryset = Brand.objects.all()
    serializer_class = BrandSerializer
    authentication_classes = [TokenAuthentication]

    def get_permissions(self):
        if self.request.user.role.name == RoleChoices.ADMIN:
            return []
        elif self.action == 'create':
            return [HasShop()]
        elif self.action in ['partial_update', 'destroy']:
            return [IsAdmin()]
        return []

class ModelView(ModelViewSet):
    queryset = Model.objects.all()
    serializer_class = ModelSerializer
    authentication_classes = [TokenAuthentication]

    def create(self, request, *args, **kwargs):
        field = check_request_fields(request, Model)
        if field:
            return Response(get_fail_response(self.action, field=field), status=status.HTTP_400_BAD_REQUEST)
        try:
            obj = Model.objects.create(**get_model_fields(self.get_serializer_class(), request))
        except IntegrityError as err:
            return Response(get_fail_response(self.action, err=err), status=status.HTTP_400_BAD_REQUEST)
        return Response(get_success_response(self.action, obj=obj), status=status.HTTP_201_CREATED)

    def partial_update(self, request, *args, **kwargs):
        field = check_request_fields(request, Model)
        if field:
            return Response(get_fail_response(self.action, field=field), status=status.HTTP_400_BAD_REQUEST)
        obj = self.get_object()
        queryset = Model.objects.filter(id=obj.id)
        try:
            obj = queryset.update(**get_model_fields(self.get_serializer_class(), request))
        except IntegrityError as err:
            return Response(get_fail_response(self.action, err=err), status=status.HTTP_400_BAD_REQUEST)
        return Response(get_success_response(self.action, obj=obj), status=status.HTTP_206_PARTIAL_CONTENT)

    def destroy(self, request, *args, **kwargs):
        obj = self.get_object()
        queryset = Model.objects.filter(id=obj.id)
        queryset.delete()
        return Response(get_success_response(self.action), status=status.HTTP_204_NO_CONTENT)

    def get_permissions(self):
        if self.request.user.role.name == RoleChoices.ADMIN:
            return []
        elif self.action == 'create':
            return [HasShop()]
        elif self.action in ['partial_update', 'destroy']:
            return [IsAdmin()]
        return []


class CategoryView(ModelViewSet):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    authentication_classes = [TokenAuthentication]

    def get_permissions(self):
        if self.request.user.role.name == RoleChoices.ADMIN:
            return []
        elif self.action == 'create':
            return [HasShop()]
        elif self.action in ['partial_update', 'destroy']:
            return [IsAdmin()]
        return []


class ItemView(ModelViewSet):
    queryset = Item.objects.all()
    serializer_class = ItemSerializer
    authentication_classes = [TokenAuthentication]

    def create(self, request, *args, **kwargs):
        field = check_request_fields(request, Item)
        value = check_model_in_brand(Brand, request)
        if field or value:
            return Response(get_fail_response(self.action, field=field if field else value), status=status.HTTP_400_BAD_REQUEST)
        request = slugify_item(Brand, Model, Item, request)
        request.data['shop'] = request.user.shop.id
        try:
            obj = Item.objects.create(**get_model_fields(self.get_serializer_class(), request))
        except IntegrityError as err:
            return Response(get_fail_response(self.action, err=err), status=status.HTTP_400_BAD_REQUEST)
        return Response(get_success_response(self.action, obj=obj), status=status.HTTP_201_CREATED)

    def partial_update(self, request, *args, **kwargs):
        field = check_request_fields(request, Item)
        value = check_model_in_brand(Brand, request)
        if field or value:
            return Response(get_fail_response(self.action, field=field if field else value), status=status.HTTP_400_BAD_REQUEST)
        obj = self.get_object()
        queryset = Item.objects.filter(id=obj.id)
        try:
            obj = queryset.update(**get_model_fields(self.get_serializer_class(), request))
        except IntegrityError as err:
            return Response(get_fail_response(self.action, err=err), status=status.HTTP_400_BAD_REQUEST)
        return Response(get_success_response(self.action, obj=obj), status=status.HTTP_206_PARTIAL_CONTENT)

    def destroy(self, request, *args, **kwargs):
        obj = self.get_object()
        obj.delete()
        return Response(get_success_response(self.action), status=status.HTTP_204_NO_CONTENT)

    def get_permissions(self):
        if self.action == 'create':
            return [HasShop()]
        elif self.action in ['partial_update', 'destroy']:
            return [IsOwner()]
        return []


class PropertyNameView(ModelViewSet):
    queryset = PropertyName.objects.all()
    serializer_class = PropertyNameSerializer
    authentication_classes = [TokenAuthentication]

    def get_permissions(self):
        if self.request.user.role.name == RoleChoices.ADMIN:
            return []
        elif self.action == 'create':
            return [HasShop()]
        elif self.action in ['partial_update', 'destroy']:
            return [IsAdmin()]
        return []


class PropertyValueView(ModelViewSet):
    queryset = PropertyValue.objects.all()
    serializer_class = PropertyValueSerializer
    authentication_classes = [TokenAuthentication]

    def create(self, request, *args, **kwargs):
        field = check_request_fields(request, PropertyValue)
        if field:
            return Response(get_fail_response(self.action, field=field), status=status.HTTP_400_BAD_REQUEST)
        value = check_item_owner(Item, request)
        if value:
            return Response({"status": "False", "message": f"Item with id {value} doesn't belong to you"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            obj = PropertyValue.objects.create(**get_model_fields(self.get_serializer_class(), request))
        except IntegrityError as err:
            return Response(get_fail_response(self.action, err=err), status=status.HTTP_400_BAD_REQUEST)
        return Response(get_success_response(self.action, obj=obj), status=status.HTTP_201_CREATED)

    def partial_update(self, request, *args, **kwargs):
        field = check_request_fields(request, PropertyValue)
        if field:
            return Response(get_fail_response(self.action, field=field), status=status.HTTP_400_BAD_REQUEST)
        value = check_item_owner(Item, request)
        if value is int:
            return Response({"status": "False", "message": f"Item with id {value} doesn't belong to you"}, status=status.HTTP_400_BAD_REQUEST)
        if value is isinstance(value, Item.DoesNotExist):
            return Response({"status": "False", "message": f"Item with id {value} doesn't exists"}, status=status.HTTP_404_NOT_FOUND)
        obj = self.get_object()
        queryset = PropertyValue.objects.filter(id=obj.id)
        try:
            obj = queryset.update(**get_model_fields(self.get_serializer_class(), request))
        except IntegrityError as err:
            return Response(get_fail_response(self.action, err=err), status=status.HTTP_400_BAD_REQUEST)
        return Response(get_success_response(self.action, obj=obj), status=status.HTTP_206_PARTIAL_CONTENT)

    def destroy(self, request, *args, **kwargs):
        obj = self.get_object()
        obj.delete()
        return Response(get_success_response(self.action), status=status.HTTP_204_NO_CONTENT)

    def get_permissions(self):
        if self.action == 'create':
            return [HasShop()]
        elif self.action in ['partial_update', 'destroy']:
            return [IsOwner()]
        return []


