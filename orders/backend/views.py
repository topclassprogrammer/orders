import datetime
import uuid

from django.db import IntegrityError
from django.db.models import Q, Sum, F
from django.db.transaction import set_autocommit, rollback, commit
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet, ModelViewSet

from backend.auth import TokenAuthentication
from backend.models import ActivationToken, AuthToken, PasswordResetToken, User, RoleChoices, Role, Shop, Address, \
    Brand, Model, Category, Item, PropertyName, PropertyValue, OrderItem, Order, OrderChoices
from backend.notifications import notify
from backend.permissions import IsOwner, IsAdmin, HasShop, IsAuthenticated
from backend.serializers import UserSerializer, ActivationSerializer, PasswordResetSerializer, \
    LogInSerializer, RoleSerializer, ShopSerializer, AddressSerializer, BrandSerializer, ModelSerializer, \
    CategorySerializer, ItemSerializer, PropertyNameSerializer, PropertyValueSerializer, OrderSerializer, \
    OrderItemSerializer
from backend.utils import hash_password, check_passwords, get_auth_token, get_object, get_success_msg, \
    get_fail_msg, get_model_fields, check_request_fields, check_model_in_brand, slugify_item, check_item_owner, \
    check_quantity, get_order


class UserView(ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer_class()(data=request.data)
        if serializer.is_valid():
            role = Role.objects.get(name=RoleChoices.CLIENT)
            user = serializer.save(role=role)
            token = ActivationToken.objects.create(key=uuid.uuid4(), user=user)
            subject = f"Activation token for your account"
            msg = f"<p>Your activation token key is <b>{token.key}</b></p><p>You have to provided it in the POST request <a href=http://{request.META['HTTP_HOST']}/{BASE_URL}{self.activate.url_path}/>here</a>. Until you do so, you are not allowed to log in</p>"
            notify(user.email, subject, msg)
            return Response({"status": True, "message": f"You successfully created account: f{serializer.data}. To activate it you have to follow instructions sent to your email: {token.user.email}"}, status=status.HTTP_201_CREATED)
        return Response(get_fail_msg(self.action, serializer), status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, *args, pk=None, **kwargs):
        obj = get_object(User, pk)
        self.check_object_permissions(request, obj)
        serializer = self.get_serializer_class()(obj, request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(get_success_msg(self.action, serializer), status=status.HTTP_206_PARTIAL_CONTENT)
        return Response(get_fail_msg(self.action, serializer), status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, pk=None, **kwargs):
        obj = get_object(User, pk)
        self.check_object_permissions(request, obj)
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
                return Response({"status": False, "message": "Username or/and password not found in DB"},
                                status=status.HTTP_404_NOT_FOUND)

            password = request.data['password']
            user_password = user.password
            if not check_passwords(password, user_password):
                return Response({"status": False, "message": "Username or/and password not found in DB"},
                                status=status.HTTP_404_NOT_FOUND)
            if not user.is_active:
                return Response({"status": False, "message": "You must activate your account before logging in"},
                                status=status.HTTP_400_BAD_REQUEST)

            AuthToken.objects.create(key=uuid.uuid4(), user=user)
            user.last_login = datetime.datetime.now()
            user.save()
            return Response({"status": True, "message": "You just logged in"}, status=status.HTTP_200_OK)
        return Response({"status": False, "message": f"Incorrect username or/and password: {serializer.errors}"},
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
        subject = f"Password reset request for your account"
        msg = f"<p>Your password reset token key is <b>{token.key}</b></p><p>In order to change your password you have to provide this token in the POST request <a href=http://{request.META['HTTP_HOST']}/{BASE_URL}{self.set_new_password.url_path}>here</a>."
        notify(user.email, subject, msg)
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

    def get_permissions(self):
        if self.action in ['create', 'log_in', 'activate']:
            return []
        elif self.action == "list":
            return [IsAuthenticated(), IsAdmin()]
        elif self.action in ['partial_update', 'destroy']:
            return [IsAuthenticated(), IsOwner()]
        elif self.action in ['retrieve', 'log_out', 'password_reset_request', 'password_reset_response']:
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
    def switch_accept_orders(self, request, pk=None):
        obj = self.get_object()
        obj.accept_orders = not obj.accept_orders
        obj.save()
        return Response(
            {"status": True, "message": f"Accept orders switched from {not obj.accept_orders} to {obj.accept_orders}"},
            status=status.HTTP_200_OK)

    def get_permissions(self):
        if self.action in ['partial_update', 'destroy', 'switch_accept_orders']:
            return [IsOwner()]
        return []


class AddressView(ModelViewSet):
    queryset = Address.objects.all()
    serializer_class = AddressSerializer
    authentication_classes = [TokenAuthentication]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer_class()(data=request.data)
        if serializer.is_valid():
            queryset = Address.objects.filter(**self.request.data, user=self.request.user)
            if queryset:
                return Response({"status": False, "message": f"You already have this address"}, status=status.HTTP_400_BAD_REQUEST)
            serializer.save(user=request.user)
            return Response(get_success_msg(self.action, serializer), status=status.HTTP_201_CREATED)
        return Response(get_fail_msg(self.action, serializer), status=status.HTTP_400_BAD_REQUEST)

    def get_permissions(self):
        if self.action == "list":
            return [IsAdmin()]
        elif self.action in ["retrieve", "partial_update", "destroy"]:
            return [IsOwner()]
        return []


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
            return Response(get_fail_msg(self.action, field=field), status=status.HTTP_400_BAD_REQUEST)
        try:
            obj = Model.objects.create(**get_model_fields(self.get_serializer_class(), request))
        except IntegrityError as err:
            return Response(get_fail_msg(self.action, err=err), status=status.HTTP_400_BAD_REQUEST)
        return Response(get_success_msg(self.action, obj=obj), status=status.HTTP_201_CREATED)

    def partial_update(self, request, *args, **kwargs):
        field = check_request_fields(request, Model)
        if field:
            return Response(get_fail_msg(self.action, field=field), status=status.HTTP_400_BAD_REQUEST)
        obj = self.get_object()
        queryset = Model.objects.filter(id=obj.id)
        try:
            obj = queryset.update(**get_model_fields(self.get_serializer_class(), request))
        except IntegrityError as err:
            return Response(get_fail_msg(self.action, err=err), status=status.HTTP_400_BAD_REQUEST)
        return Response(get_success_msg(self.action, obj=obj), status=status.HTTP_206_PARTIAL_CONTENT)

    def destroy(self, request, *args, **kwargs):
        obj = self.get_object()
        queryset = Model.objects.filter(id=obj.id)
        queryset.delete()
        return Response(get_success_msg(self.action), status=status.HTTP_204_NO_CONTENT)

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
            return Response(get_fail_msg(self.action, field=field if field else value), status=status.HTTP_400_BAD_REQUEST)
        request = slugify_item(Brand, Model, Item, request)
        request.data['shop'] = request.user.shop.id
        try:
            obj = Item.objects.create(**get_model_fields(self.get_serializer_class(), request))
        except IntegrityError as err:
            return Response(get_fail_msg(self.action, err=err), status=status.HTTP_400_BAD_REQUEST)
        return Response(get_success_msg(self.action, obj=obj), status=status.HTTP_201_CREATED)

    def partial_update(self, request, *args, **kwargs):
        field = check_request_fields(request, Item)
        value = check_model_in_brand(Brand, request)
        if field or value:
            return Response(get_fail_msg(self.action, field=field if field else value), status=status.HTTP_400_BAD_REQUEST)
        obj = self.get_object()
        queryset = Item.objects.filter(id=obj.id)
        try:
            obj = queryset.update(**get_model_fields(self.get_serializer_class(), request))
        except IntegrityError as err:
            return Response(get_fail_msg(self.action, err=err), status=status.HTTP_400_BAD_REQUEST)
        return Response(get_success_msg(self.action, obj=obj), status=status.HTTP_206_PARTIAL_CONTENT)

    def destroy(self, request, *args, **kwargs):
        obj = self.get_object()
        obj.delete()
        return Response(get_success_msg(self.action), status=status.HTTP_204_NO_CONTENT)

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
            return Response(get_fail_msg(self.action, field=field), status=status.HTTP_400_BAD_REQUEST)
        value = check_item_owner(Item, request)
        if value:
            return Response({"status": "False", "message": f"Item with id {value} doesn't belong to you"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            obj = PropertyValue.objects.create(**get_model_fields(self.get_serializer_class(), request))
        except IntegrityError as err:
            return Response(get_fail_msg(self.action, err=err), status=status.HTTP_400_BAD_REQUEST)
        return Response(get_success_msg(self.action, obj=obj), status=status.HTTP_201_CREATED)

    def partial_update(self, request, *args, **kwargs):
        field = check_request_fields(request, PropertyValue)
        if field:
            return Response(get_fail_msg(self.action, field=field), status=status.HTTP_400_BAD_REQUEST)
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
            return Response(get_fail_msg(self.action, err=err), status=status.HTTP_400_BAD_REQUEST)
        return Response(get_success_msg(self.action, obj=obj), status=status.HTTP_206_PARTIAL_CONTENT)

    def destroy(self, request, *args, **kwargs):
        obj = self.get_object()
        obj.delete()
        return Response(get_success_msg(self.action), status=status.HTTP_204_NO_CONTENT)

    def get_permissions(self):
        if self.action == 'create':
            return [HasShop()]
        elif self.action in ['partial_update', 'destroy']:
            return [IsOwner()]
        return []


class OrderItemView(ModelViewSet):
    authentication_classes = [TokenAuthentication]

    def create(self, request, *args,
               **kwargs):
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
            obj = OrderItem.objects.create(**get_model_fields(self.get_serializer_class(), request), order=order)
        except (IntegrityError, ValueError) as err:
            return Response(get_fail_msg(self.action, err=err), status=status.HTTP_400_BAD_REQUEST)

        return Response(get_success_msg(self.action, obj=obj), status=status.HTTP_201_CREATED)

    def partial_update(self, request, *args, **kwargs):
        field = check_request_fields(request, OrderItem)
        if field:
            return Response(get_fail_msg(self.action, field=field), status=status.HTTP_400_BAD_REQUEST)

        obj = self.get_object()
        quantity = request.data['quantity']
        quantity_err_msg = check_quantity(quantity, obj.item)
        if quantity_err_msg:
            return Response(quantity_err_msg, status=status.HTTP_400_BAD_REQUEST)

        try:
            order = Order.objects.get(id=request.data['order'], user=request.user)
        except (Order.DoesNotExist, ValueError) as err:
            return Response(get_fail_msg(self.action, err=err, field=request.data['order']), status=status.HTTP_400_BAD_REQUEST)

        try:
            item = Item.objects.get(id=request.data['item'])
        except (Item.DoesNotExist, ValueError) as err:
            return Response(get_fail_msg(self.action, err=err, field=request.data['item']), status=status.HTTP_400_BAD_REQUEST)

        obj.order = order
        obj.item = item
        obj.quantity = request.data['quantity']
        obj.save()
        return Response(get_success_msg(self.action, obj=obj), status=status.HTTP_201_CREATED)

    def destroy(self, request, *args, **kwargs):
        obj = self.get_object()
        obj.delete()
        return Response(get_success_msg(self.action), status=status.HTTP_204_NO_CONTENT)

    def get_permissions(self):
        if self.request.user.role.name == RoleChoices.ADMIN:
            return []
        elif self.action in ['retrieve', 'partial_update', 'destroy']:
            return [IsOwner()]
        return []

    def get_serializer_class(self):
        if self.action in ['list', 'retrieve']:
            return OrderSerializer
        elif self.action in ['create']:
            return OrderItemSerializer

    def get_queryset(self):
        if self.action in ['list', 'retrieve']:
            query = Q(state=OrderChoices.CART)
            if self.request.user.role.name == RoleChoices.ADMIN:
                pass
            else:
                query &= Q(user=self.request.user)

            if self.action == 'retrieve':
                pk = int(self.request.__dict__['parser_context']['kwargs']['pk'])  # self.get_object() выдает здесь рекурсию, поэтому используем такую длинную конструкцию
                obj = get_object(Order, pk)
                self.check_object_permissions(self.request, obj)
                query &= Q(id=obj.id)

            queryset = Order.objects.filter(query).prefetch_related("order_items__item"). \
                annotate(sum=Sum(F("order_items__item__quantity") * F("order_items__item__price")))
            return queryset
        else:
            return OrderItem.objects.all()


class OrderView(ModelViewSet):
    serializer_class = OrderSerializer
    authentication_classes = [TokenAuthentication]

    def create(self, request, *args, **kwargs):
        field = check_request_fields(request, Order)
        if field:
            return Response(get_fail_msg(self.action, field=field), status=status.HTTP_400_BAD_REQUEST)

        order = get_order(request, Order, state=OrderChoices.CART)
        if not isinstance(order, Order):
            return Response(get_fail_msg(self.action, err=order), status=status.HTTP_404_NOT_FOUND)
        order.state = OrderChoices.NEW
        order.address = Address.objects.get(id=request.data['address'])

        set_autocommit(autocommit=False)
        try:
            for el in order.order_items.all():
                diff = el.item.quantity - el.quantity
                if diff < 0:
                    return Response({"status": False,
                                     "message": f"Insufficient quantity of item {el.item.brand.name} "
                                                f"{el.item.model.name} in stock. You chose {el.quantity} "
                                                f"but only {el.item.quantity} are available in stock"},
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
            return Response({"status": True, "message": "Order successfully made"}, status=status.HTTP_201_CREATED)

    def partial_update(self, request, *args, **kwargs):
        state = request.data.get('state')
        if not state:
            return Response({"status": False, "message": "You must provide field 'state'"},
                            status=status.HTTP_400_BAD_REQUEST)
        if state not in OrderChoices.values:
            return Response({"status": False, "message": "Unknown state provided"}, status=status.HTTP_404_NOT_FOUND)

        obj = self.get_object()
        obj.state = getattr(OrderChoices, state.upper())
        obj.save()
        return Response(get_success_msg(self.action, obj=obj), status=status.HTTP_206_PARTIAL_CONTENT)

    def destroy(self, request, *args, **kwargs):
        obj = self.get_object()
        obj.delete()
        return Response(get_success_msg(self.action), status=status.HTTP_204_NO_CONTENT)

    def get_queryset(self):
        if self.action in ['list', 'retrieve']:
            query = ~Q(state=OrderChoices.CART)
            if self.request.user.role.name == RoleChoices.ADMIN:
                pass
            else:
                query &= Q(user=self.request.user)

            if self.action == 'retrieve':
                pk = int(self.request.__dict__['parser_context']['kwargs']['pk'])
                obj = get_object(Order, pk)
                self.check_object_permissions(self.request, obj)
                query &= Q(id=obj.id)

            queryset = Order.objects.filter(query).prefetch_related("order_items__item"). \
                annotate(sum=Sum(F("order_items__item__quantity") * F("order_items__item__price")))
            return queryset

        else:
            return Order.objects.all()

    def get_permissions(self):
        if self.request.user.role.name == RoleChoices.ADMIN:
            return []
        elif self.action in ['create', 'retrieve']:
            return [IsOwner()]
        elif self.action in ['partial_update', 'destroy']:
            return [IsAdmin()]
        return []

