import datetime
import uuid
from typing import List, Type

import requests
from django.db import IntegrityError
from django.db.models import Q, Sum, F
from django.db.transaction import set_autocommit, rollback, commit
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import BasePermission
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from backend.auth import TokenAuthentication
from backend.filters import ItemFiler
from backend.models import ActivationToken, AuthToken, PasswordResetToken, User, RoleChoices, Role, Shop, Address, \
    Brand, Model, Category, Item, PropertyName, PropertyValue, OrderItem, Order, OrderChoices
from backend.notifications import notify
from backend.permissions import IsOwner, IsAdmin, HasShop, IsAuthenticated
from backend.serializers import UserSerializer, ActivationSerializer, PasswordResetSerializer, \
    LogInSerializer, RoleSerializer, ShopSerializer, AddressSerializer, BrandSerializer, ModelSerializer, \
    CategorySerializer, ItemSerializer, PropertyNameSerializer, PropertyValueSerializer, OrderSerializer, \
    OrderItemSerializer
from backend.utils import hash_password, check_passwords, get_auth_token, get_object, get_success_msg, \
    get_fail_msg, check_request_fields, check_model_in_brand, slugify_item, check_item_owner, \
    check_quantity, get_order, get_url_end_path, get_request_method, get_request_data, slugify_bulk_item, \
    get_admin_emails
from backend.validators import check_url


class UserView(ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer_class()(data=request.data)
        if serializer.is_valid():
            default_role = Role.objects.get(name=RoleChoices.CLIENT)
            user = serializer.save(role=default_role)
            token = ActivationToken.objects.create(key=uuid.uuid4(), user=user)
            notify(user.email, self.__class__, self.action, token=token)
            return Response({"status": True, "message": f"You successfully created account: {serializer.data}. Your activation token sent to your email: {token.user.email}"}, status=status.HTTP_201_CREATED)
        return Response(get_fail_msg(self.action, serializer), status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, *args, pk=None, **kwargs):
        obj = self.get_object()
        serializer = self.get_serializer_class()(obj, request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(get_success_msg(self.action, serializer), status=status.HTTP_206_PARTIAL_CONTENT)
        return Response(get_fail_msg(self.action, serializer), status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, pk=None, **kwargs):
        obj = self.get_object()
        obj.delete()
        return Response(get_success_msg(self.action, pk=pk), status=status.HTTP_204_NO_CONTENT)

    @action(methods=['POST'], detail=False, url_path='activate')
    def activate(self, request):
        serializer = self.get_serializer_class()(data=request.data)
        if serializer.is_valid():
            key = request.data['key']
            try:
                token = ActivationToken.objects.get(key=uuid.UUID(key))
            except ActivationToken.DoesNotExist:
                return Response({"status": False, "message": "Activation token key not found in DB"},
                                status=status.HTTP_404_NOT_FOUND)
            if token.user.is_active:
                return Response({"status": False, "message": "Account is already activated"},
                                status=status.HTTP_400_BAD_REQUEST)
            token.user.is_active = True
            token.user.save()
            token.delete()
            return Response({"status": True, "message": f"Account with ID {token.user.id} successfully activated"}, status=status.HTTP_200_OK)
        return Response({"status": False, "message": f"Activation failed: {serializer.errors}"}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['POST'], detail=False, url_path="log-in")
    def log_in(self, request):
        serializer = self.get_serializer_class()(data=request.data)
        if serializer.is_valid():
            username = request.data['username']

            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                return Response({"status": False, "message": "Wrong username or/and password"},
                                status=status.HTTP_404_NOT_FOUND)

            password = request.data['password']
            user_password = user.password
            if not check_passwords(password, user_password):
                return Response({"status": False, "message": "Wrong username or/and password"},
                                status=status.HTTP_404_NOT_FOUND)
            if not user.is_active:
                return Response({"status": False, "message": "You must activate your account before logging in"},
                                status=status.HTTP_400_BAD_REQUEST)

            AuthToken.objects.create(key=uuid.uuid4(), user=user)
            user.last_login = datetime.datetime.now()
            user.save()
            return Response({"status": True, "message": "You just logged in"}, status=status.HTTP_200_OK)
        return Response({"status": False, "message": f"Incorrect username or/and password input: {serializer.errors}"},
                        status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['POST'], detail=False, url_path='log-out')
    def log_out(self, request):
        token = get_auth_token(request)
        token.delete()
        return Response({"status": True, "message": "You just logged out"}, status=status.HTTP_200_OK)

    @action(methods=['POST'], detail=False, url_path='request-new-password')
    def request_new_password(self, request):
        user = self.request.user
        token = PasswordResetToken.objects.create(key=uuid.uuid4(), user=user)
        notify(user.email, self.__class__, self.action, token=token)
        return Response({"status": True, "message": f"Password reset token has been successfully sent to your email: {token.user.email}"},
                        status=status.HTTP_200_OK)

    @action(methods=['POST'], detail=False, url_path='set-new-password')
    def set_new_password(self, request):
        serializer = self.get_serializer_class()(data=request.data)
        if serializer.is_valid():
            key = request.data['key']
            try:
                reset_token = PasswordResetToken.objects.get(key=uuid.UUID(key))
            except PasswordResetToken.DoesNotExist:
                return Response({"status": False, "message": "PasswordResetToken key not found in DB"},
                                status=status.HTTP_404_NOT_FOUND)

            user = request.user
            password = request.data['password']
            user.password = hash_password(password)
            user.save()
            reset_token.delete()
            return Response({"status": True, "message": "Password successfully changed"}, status=status.HTTP_200_OK)
        return Response({"status": False, "message": f"Incorrect key or/and password provided: {serializer.errors}"},
                        status=status.HTTP_400_BAD_REQUEST)

    def get_authenticators(self):
        url_end = get_url_end_path(self.request, self.basename)
        request_method = get_request_method(self.request)
        if url_end in ['', self.__class__.log_in.url_path, self.__class__.activate.url_path] and request_method == 'POST':
            return []
        else:
            return [TokenAuthentication()]

    def get_serializer_class(self):
        if self.action in [self.__class__.list.__name__, self.__class__.retrieve.__name__, self.__class__.create.__name__, self.__class__.partial_update.__name__]:
            return UserSerializer
        elif self.action == self.__class__.log_in.__name__:
            return LogInSerializer
        elif self.action == self.__class__.activate.__name__:
            return ActivationSerializer
        elif self.action == self.__class__.set_new_password.__name__:
            return PasswordResetSerializer

    def get_permissions(self):
        permissions = [IsAuthenticated]
        if self.action in [self.__class__.create.__name__, self.__class__.log_in.__name__, self.__class__.activate.__name__]:
            return []
        elif self.action == self.__class__.list.__name__:
            permissions.append(IsAdmin)
        elif self.action in [self.__class__.update.__name__, self.__class__.partial_update.__name__, self.__class__.destroy.__name__]:
            permissions.append(IsOwner)
        else:
            pass
        return [p() for p in permissions]


class RoleView(ModelViewSet):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes: List[Type[BasePermission]] = [IsAuthenticated]


class ShopView(ModelViewSet):
    serializer_class = ShopSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes: List[Type[BasePermission]] = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer_class()(data=request.data)
        if serializer.is_valid():
            user = request.user
            if hasattr(user, 'shop'):
                return Response({"status": False, "message": f"Cannot create shop because you already have it"}, status=status.HTTP_400_BAD_REQUEST)
            serializer.save(user=user)
            user.role = Role.objects.get(name=RoleChoices.SHOP)
            user.save()
            return Response(get_success_msg(self.action, serializer), status=status.HTTP_201_CREATED)
        return Response(get_fail_msg(self.action, serializer), status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        obj = self.get_object()
        obj.delete()
        user = request.user
        user.role = Role.objects.get(name=RoleChoices.CLIENT)
        user.save()
        return Response(get_success_msg(self.action, obj.id), status=status.HTTP_204_NO_CONTENT)

    @action(methods=['POST'], detail=True, url_path="switch-accept-orders")
    def switch_accept_orders(self, request):
        token = get_auth_token(request)
        shop = token.user.shop
        shop.accept_orders = not shop.accept_orders
        shop.save()
        return Response(
            {"status": True, "message": f"Accept orders switched from {not shop.accept_orders} to {shop.accept_orders}"},
            status=status.HTTP_200_OK)

    @action(methods=['GET'], detail=False, url_path="active-orders")
    def get_active_orders(self, request):
        queryset = self.get_queryset()
        serializer = OrderSerializer(queryset, many=True)
        return Response(get_success_msg(self.action, serializer), status=status.HTTP_200_OK)

    def get_queryset(self):
        if self.action == self.__class__.get_active_orders.__name__:
            token = get_auth_token(self.request)
            inactive_state_orders = [OrderChoices.CART, OrderChoices.CANCELED]
            active_state_orders = [x[0] for x in OrderChoices.choices if x[0] not in inactive_state_orders]
            query = Q(state__in=active_state_orders)
            if self.request.user.role.name == RoleChoices.SHOP:
                query &= Q(user__shop=token.user.shop)
            queryset = Order.objects.filter(query).prefetch_related(
                "order_items__item__brand", "order_items__item__model", "order_items__item__category"). \
                select_related("address").annotate(sum=Sum(F("order_items__quantity") * F("order_items__item__price")))
            return queryset
        else:
            return Shop.objects.all()

    def get_permissions(self):
        if self.action == self.__class__.get_active_orders.__name__:
            if self.request.user.role.name == RoleChoices.ADMIN:
                return []
            else:
                self.permission_classes.extend([HasShop, IsOwner])
        if self.action in [self.__class__.update.__name__, self.__class__.partial_update.__name__, self.__class__.destroy.__name__, self.__class__.switch_accept_orders.__name__]:
            self.permission_classes.extend([HasShop, IsOwner])
        return [p() for p in self.permission_classes]


class AddressView(ModelViewSet):
    queryset = Address.objects.all()
    serializer_class = AddressSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes: List[Type[BasePermission]] = [IsAuthenticated]

    def list(self, request, *args, **kwargs):
        if request.user.role.name == RoleChoices.ADMIN:
            queryset = self.get_queryset()
        else:
            queryset = Address.objects.filter(user=request.user)
        serializer = self.get_serializer_class()(queryset, many=True)
        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer_class()(data=request.data)
        if serializer.is_valid():
            queryset = Address.objects.filter(**request.data, user=request.user)
            if queryset:
                return Response({"status": False, "message": f"You already have this address"}, status=status.HTTP_400_BAD_REQUEST)
            serializer.save(user=request.user)
            return Response(get_success_msg(self.action, serializer), status=status.HTTP_201_CREATED)
        return Response(get_fail_msg(self.action, serializer), status=status.HTTP_400_BAD_REQUEST)

    def get_permissions(self):
        if self.action in [self.__class__.retrieve.__name__, self.__class__.update.__name__, self.__class__.partial_update.__name__, self.__class__.destroy.__name__]:
            self.permission_classes.append(IsOwner)
        return [p() for p in self.permission_classes]


class BrandView(ModelViewSet):
    queryset = Brand.objects.all()
    serializer_class = BrandSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes: List[Type[BasePermission]] = [IsAuthenticated]

    def get_permissions(self):
        if self.action == self.__class__.create.__name__:
            self.permission_classes.append(HasShop)
        elif self.action in [self.__class__.update.__name__, self.__class__.partial_update.__name__, self.__class__.destroy.__name__]:
            self.permission_classes.append(IsAdmin)
        return [p() for p in self.permission_classes]


class ModelView(ModelViewSet):
    queryset = Model.objects.all()
    serializer_class = ModelSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes: List[Type[BasePermission]] = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        field = check_request_fields(request, Model)
        if field:
            return Response(get_fail_msg(self.action, field=field), status=status.HTTP_400_BAD_REQUEST)
        try:
            obj = Model.objects.create(**get_request_data(Model, request))
        except (IntegrityError, ValueError) as err:
            return Response(get_fail_msg(self.action, err=err), status=status.HTTP_400_BAD_REQUEST)
        return Response(get_success_msg(self.action, obj=obj), status=status.HTTP_201_CREATED)

    def partial_update(self, request, *args, **kwargs):
        field = check_request_fields(request, Model)
        if field:
            return Response(get_fail_msg(self.action, field=field))
        try:
            obj = Model.objects.filter(id=self.kwargs['pk']).update(**get_request_data(Model, request))
        except ValueError as err:
            return Response(get_fail_msg(self.action, err=err), status=status.HTTP_400_BAD_REQUEST)
        return Response(get_success_msg(self.action, obj=obj), status=status.HTTP_206_PARTIAL_CONTENT)

    def destroy(self, request, *args, **kwargs):
        obj = self.get_object()
        obj.delete()
        return Response(get_success_msg(self.action), status=status.HTTP_204_NO_CONTENT)

    def get_permissions(self):
        if self.action == self.__class__.create.__name__:
            self.permission_classes.append(HasShop)
        elif self.action in [self.__class__.update.__name__, self.__class__.partial_update.__name__, self.__class__.destroy.__name__]:
            self.permission_classes.append(IsAdmin)
        return [p() for p in self.permission_classes]


class CategoryView(ModelViewSet):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    authentication_classes = [TokenAuthentication]
    permission_classes: List[Type[BasePermission]] = [IsAuthenticated]

    def get_permissions(self):
        if self.action == self.__class__.create.__name__:
            self.permission_classes.append(HasShop)
        elif self.action in [self.__class__.update.__name__, self.__class__.partial_update.__name__, self.__class__.destroy.__name__]:
            self.permission_classes.append(IsAdmin)
        return [p() for p in self.permission_classes]


class ItemView(ModelViewSet):
    queryset = Item.objects.all()
    serializer_class = ItemSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes: List[Type[BasePermission]] = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_class = ItemFiler

    def retrieve(self, request, *args, **kwargs):
        pk = self.kwargs['pk']
        pk = {"id": pk} if pk.isdigit() else {"slug": pk}
        obj = Item.objects.filter(**pk).select_related("brand", "model", "category", "shop")
        if not obj:
            return Response(get_fail_msg(self.action, field=pk), status=status.HTTP_404_NOT_FOUND)
        serializer = self.get_serializer_class()(obj, many=True)
        return Response(get_success_msg(self.action, serializer), status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        field = check_request_fields(request, Item)
        if field:
            return Response(get_fail_msg(self.action, field=field), status=status.HTTP_400_BAD_REQUEST)
        value = check_model_in_brand(Brand, Model, request)
        if value:
            return Response(get_fail_msg(self.action, err=value), status=status.HTTP_400_BAD_REQUEST)

        slug = slugify_item(Brand, Model, Item, request)
        request.data['slug'] = slug
        request.data['shop_id'] = request.user.shop.id
        try:
            obj = Item.objects.create(**get_request_data(Item, request))
        except (IntegrityError, ValueError) as err:
            return Response(get_fail_msg(self.action, err=err), status=status.HTTP_400_BAD_REQUEST)
        return Response(get_success_msg(self.action, obj=obj), status=status.HTTP_201_CREATED)

    def partial_update(self, request, *args, **kwargs):
        obj = self.get_object()
        if request.FILES.get('image'):
            request.FILES['image'].name = get_image_name(request)
            obj.image = request.FILES['image']
            obj.save()
            return Response(get_success_msg(self.action, obj=obj))
        elif len(request.data) == 1 and 'description' in request.data.keys():
            obj.description = request.data['description']
            obj.save()
            return Response(get_success_msg(self.action, obj=obj))
        else:
            field = check_request_fields(request, Item)
            if field:
                return Response(get_fail_msg(self.action, field=field),
                                status=status.HTTP_400_BAD_REQUEST)

            value = check_model_in_brand(Brand, Model, request)
            if value:
                return Response(get_fail_msg(self.action, err=value),
                                status=status.HTTP_400_BAD_REQUEST)

            queryset = Item.objects.filter(id=obj.id)
            try:
                obj = queryset.update(**get_request_data(Item, request))
            except (IntegrityError, ValueError) as err:
                return Response(get_fail_msg(self.action, err=err), status=status.HTTP_400_BAD_REQUEST)
            return Response(get_success_msg(self.action, obj=obj), status=status.HTTP_206_PARTIAL_CONTENT)

    def destroy(self, request, *args, **kwargs):
        obj = self.get_object()
        obj.delete()
        return Response(get_success_msg(self.action), status=status.HTTP_204_NO_CONTENT)

    @action(methods=['POST'], detail=False, url_path="bulk-upload")
    def bulk_upload(self, request):
        url = request.data.get('url')
        check_url(url)
        content = requests.get(url).json()
        shop = request.user.shop

        for el in content:
            try:
                brand, _ = Brand.objects.get_or_create(name=el['brand'])
                model, _ = Model.objects.get_or_create(name=el['model'], brand=brand)
                category, _ = Category.objects.get_or_create(name=el['category'])
                item, _ = Item.objects.get_or_create(
                    brand=brand,
                    model=model,
                    category=category,
                    shop=shop,
                    description=el.get('description'),
                    image=el.get('image'),
                    price=el['price'],
                    quantity=el['quantity'],
                    slug=slugify_bulk_item(brand.name, model.name)
                )
                properties = el['properties']
                for x in properties:
                    property_name, _ = PropertyName.objects.get_or_create(name=x['name'])
                    property_value, _ = PropertyValue.objects.get_or_create(item=item, property_name=property_name, value=x['value'])
            except KeyError as err:
                return Response({"status": False, "message": f"You must provide {err.__str__()} property"}, status=status.HTTP_400_BAD_REQUEST)
            except IntegrityError:
                # noinspection PyUnboundLocalVariable
                return Response({"status": False, "message": f"Such item already exists in your stock: '{brand.name} {model.name}' in category '{category.name}'"}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"status": True, "message": f"Successfully uploaded all items"}, status=status.HTTP_201_CREATED)

    def get_permissions(self):
        if self.action in [self.__class__.create.__name__, self.__class__.bulk_upload.__name__]:
            self.permission_classes.append(HasShop)
        elif self.action in [self.__class__.update.__name__, self.__class__.partial_update.__name__, self.__class__.destroy.__name__]:
            self.permission_classes.append(IsOwner)
        return [p() for p in self.permission_classes]


class PropertyNameView(ModelViewSet):
    queryset = PropertyName.objects.all()
    serializer_class = PropertyNameSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes: List[Type[BasePermission]] = [IsAuthenticated]

    def get_permissions(self):
        if self.action in [self.__class__.create.__name__]:
            self.permission_classes.append(HasShop)
        elif self.action in [self.__class__.update.__name__, self.__class__.partial_update.__name__, self.__class__.destroy.__name__]:
            self.permission_classes.append(IsAdmin)
        return [p() for p in self.permission_classes]


class PropertyValueView(ModelViewSet):
    queryset = PropertyValue.objects.all()
    serializer_class = PropertyValueSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes: List[Type[BasePermission]] = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        field = check_request_fields(request, PropertyValue)
        if field:
            return Response(get_fail_msg(self.action, field=field), status=status.HTTP_400_BAD_REQUEST)
        value = check_item_owner(Item, request)
        if value:
            return Response(get_fail_msg(self.action, err=value if isinstance(value, Item.DoesNotExist) else f"Item with id {value} doesn't belong to you"), status=status.HTTP_400_BAD_REQUEST)

        try:
            obj = PropertyValue.objects.create(**get_request_data(PropertyValue, request))
        except (IntegrityError, ValueError) as err:
            return Response(get_fail_msg(self.action, err=err), status=status.HTTP_400_BAD_REQUEST)
        return Response(get_success_msg(self.action, obj=obj), status=status.HTTP_201_CREATED)

    def partial_update(self, request, *args, **kwargs):
        obj = self.get_object()
        field = check_request_fields(request, PropertyValue)
        if field:
            return Response(get_fail_msg(self.action, field=field), status=status.HTTP_400_BAD_REQUEST)
        value = check_item_owner(Item, request)
        if value:
            return Response(get_fail_msg(self.action, err=value if isinstance(value, Exception) else f"Item with id {value} doesn't belong to you"), status=status.HTTP_400_BAD_REQUEST)

        queryset = PropertyValue.objects.filter(id=obj.id)
        try:
            obj = queryset.update(**get_request_data(PropertyValue, request))
        except (IntegrityError, ValueError) as err:
            return Response(get_fail_msg(self.action, err=err), status=status.HTTP_400_BAD_REQUEST)
        return Response(get_success_msg(self.action, obj=obj), status=status.HTTP_206_PARTIAL_CONTENT)

    def destroy(self, request, *args, **kwargs):
        obj = self.get_object()
        obj.delete()
        return Response(get_success_msg(self.action), status=status.HTTP_204_NO_CONTENT)

    def get_permissions(self):
        if self.action in [self.__class__.create.__name__]:
            self.permission_classes.append(HasShop)
        elif self.action in [self.__class__.update.__name__, self.__class__.partial_update.__name__, self.__class__.destroy.__name__]:
            self.permission_classes.append(IsOwner)
        return [p() for p in self.permission_classes]


class OrderItemView(ModelViewSet):
    authentication_classes = [TokenAuthentication]
    permission_classes: List[Type[BasePermission]] = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        field = check_request_fields(request, OrderItem)
        if field:
            return Response(get_fail_msg(self.action, field=field), status=status.HTTP_400_BAD_REQUEST)

        item_id = request.data['item']
        try:
            item = Item.objects.get(id=item_id)
        except (Item.DoesNotExist, ValueError) as err:
            return Response(get_fail_msg(self.action, err=err), status=status.HTTP_400_BAD_REQUEST)

        if item.shop.accept_orders is False:
            return Response({"status": False,
                             "message": "You can't choose this item because the shop cannot accept any orders at this time"},
                            status=status.HTTP_400_BAD_REQUEST)

        quantity = request.data['quantity']
        quantity_err_msg = check_quantity(quantity, item)
        if quantity_err_msg:
            return Response(quantity_err_msg, status=status.HTTP_400_BAD_REQUEST)

        order = get_order(request, Order, OrderChoices.CART)
        try:
            obj = OrderItem.objects.create(**get_request_data(OrderItem, request), order=order)
        except (IntegrityError, ValueError) as err:
            return Response(get_fail_msg(self.action, err=err), status=status.HTTP_400_BAD_REQUEST)

        return Response(get_success_msg(self.action, obj=obj), status=status.HTTP_201_CREATED)

    def partial_update(self, request, *args, **kwargs):
        obj = self.get_object()
        field = check_request_fields(request, OrderItem)
        if field:
            return Response(get_fail_msg(self.action, field=field), status=status.HTTP_400_BAD_REQUEST)

        quantity = request.data.get('quantity')
        if quantity:
            quantity_err_msg = check_quantity(quantity, obj.item)
            if quantity_err_msg:
                return Response(quantity_err_msg, status=status.HTTP_400_BAD_REQUEST)

        queryset = OrderItem.objects.filter(id=obj.id)
        try:
            obj = queryset.update(**get_request_data(OrderItem, request))
        except (IntegrityError, ValueError) as err:
            return Response(get_fail_msg(self.action, err=err), status=status.HTTP_400_BAD_REQUEST)
        return Response(get_success_msg(self.action, obj=obj), status=status.HTTP_206_PARTIAL_CONTENT)

    def destroy(self, request, *args, **kwargs):
        obj = self.get_object()
        obj.delete()
        return Response(get_success_msg(self.action), status=status.HTTP_204_NO_CONTENT)

    def get_serializer_class(self):
        if self.action in [self.__class__.list.__name__, self.__class__.retrieve.__name__]:
            return OrderSerializer
        elif self.action == self.__class__.create.__name__:
            return OrderItemSerializer

    def get_queryset(self):
        if self.action in [self.__class__.list.__name__, self.__class__.retrieve.__name__]:
            query = Q(state=OrderChoices.CART)
            if self.request.user.role.name == RoleChoices.ADMIN:
                pass
            else:
                query &= Q(user=self.request.user)

            if self.action == self.__class__.retrieve.__name__:
                try:
                    pk = int(self.kwargs['pk'])
                except ValueError:
                    raise ValidationError({"status": False, "message": "You must provide integer value for order item id"})

                obj = get_object(Order, pk)
                query &= Q(id=obj.id)

            queryset = Order.objects.filter(query).prefetch_related("order_items__item__brand", "order_items__item__model", "order_items__item__category"). \
                select_related("address").annotate(sum=Sum(F("order_items__quantity") * F("order_items__item__price")))  # Если выполнять queryset.first().order_items.all().first().item.brand.name, то обращений к БД не будет, т.к. все связанные сущности уже были предзагружены из SQL в Python
            return queryset
        else:
            return OrderItem.objects.all()

    def get_permissions(self):
        if self.action == self.__class__.list.__name__:
            self.permission_classes.append(IsAdmin)
        elif self.action == self.__class__.retrieve.__name__:
            if self.request.user.role.name == RoleChoices.ADMIN:
                return []
            else:
                self.permission_classes.append(IsOwner)
        elif self.action in [self.__class__.update.__name__, self.__class__.partial_update.__name__, self.__class__.destroy.__name__]:
            self.permission_classes.append(IsOwner)
        return [p() for p in self.permission_classes]


class OrderView(ModelViewSet):
    serializer_class = OrderSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes: List[Type[BasePermission]] = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        field = check_request_fields(request, Order)
        if field:
            return Response(get_fail_msg(self.action, field=field), status=status.HTTP_400_BAD_REQUEST)

        try:
            order = Order.objects.get(user=request.user, state=OrderChoices.CART)
        except Order.DoesNotExist:
            return Response({"status": False, "message": "You have not added any items into your cart yet"}, status=status.HTTP_404_NOT_FOUND)
        except Order.MultipleObjectsReturned as err:
            return Response({"status": False,
                             "message": f"Unknown error occurred while making your order. You have to contact administrator(s): {get_admin_emails()} providing the following error: {err}"}, status=status.HTTP_400_BAD_REQUEST)
        order.state = OrderChoices.NEW
        order.address = Address.objects.get(id=request.data['address'])

        set_autocommit(autocommit=False)
        try:
            for el in order.order_items.all():
                diff = el.item.quantity - el.quantity
                if diff < 0:
                    return Response({"status": False,
                                     "message": f"Insufficient quantity of item {el.item.brand.name} {el.item.model.name} in stock. You chose {el.quantity} but only {el.item.quantity} are available in stock"},
                                    status=status.HTTP_400_BAD_REQUEST)
                el.item.quantity = diff
                el.item.save()
            order.save()
        except IntegrityError:
            rollback()
            return Response({"status": False, "message": "Unknown error occurred. Please try again later"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            commit()
            notify(order.user.email, self.__class__, self.action, order=order)
            notify(get_admin_emails(), self.__class__, self.action, order=order, admin=True)
            return Response({"status": True, "message": "Order successfully made"}, status=status.HTTP_201_CREATED)

    def partial_update(self, request, *args, **kwargs):
        obj = self.get_object()
        state = request.data.get('state')
        if not state:
            return Response({"status": False, "message": "You must provide field 'state'"}, status=status.HTTP_400_BAD_REQUEST)
        if state not in OrderChoices.values:
            return Response({"status": False, "message": f"Unknown state provided. You must provide one of the following states: {[x[0] for x in OrderChoices.choices]}"}, status=status.HTTP_404_NOT_FOUND)

        obj.state = getattr(OrderChoices, state.upper())
        obj.save()
        notify(obj.user.email, self.__class__, self.action, order=obj)
        return Response(get_success_msg(self.action, obj=obj), status=status.HTTP_206_PARTIAL_CONTENT)

    def destroy(self, request, *args, **kwargs):
        obj = self.get_object()
        obj.delete()
        return Response(get_success_msg(self.action), status=status.HTTP_204_NO_CONTENT)

    def get_queryset(self):
        if self.action in [self.__class__.list.__name__, self.__class__.retrieve.__name__]:
            query = ~Q(state=OrderChoices.CART)
            if self.request.user.role.name == RoleChoices.ADMIN:
                pass
            else:
                query &= Q(user=self.request.user)

            if self.action == self.__class__.retrieve.__name__:
                try:
                    pk = int(self.kwargs['pk'])
                except ValueError:
                    raise ValidationError({"status": False, "message": "You must provide integer value for order id"})

                obj = get_object(Order, pk)
                query &= Q(id=obj.id)

            queryset = Order.objects.filter(query).prefetch_related("order_items__item__brand", "order_items__item__model", "order_items__item__category"). \
                select_related("address").annotate(sum=Sum(F("order_items__quantity") * F("order_items__item__price")))
            return queryset

        else:
            return Order.objects.all()

    def get_permissions(self):
        if self.action in [self.__class__.retrieve.__name__]:
            if self.request.user.role.name == RoleChoices.ADMIN:
                return []
            else:
                self.permission_classes.append(IsOwner)
        elif self.action in [self.__class__.create.__name__]:
            self.permission_classes.append(IsOwner)
        elif self.action in [self.__class__.list.__name__, self.__class__.update.__name__, self.__class__.partial_update.__name__, self.__class__.destroy.__name__]:
            self.permission_classes.append(IsAdmin)
        return [p() for p in self.permission_classes]

