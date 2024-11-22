import datetime
import uuid

from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet

from backend.auth import TokenAuthentication
from backend.models import User, AuthToken, ActivationToken, PasswordResetToken, Role, Shop, RoleChoices, Address
from backend.permissions import IsOwner, IsAdmin, HasShop
from backend.serializers import LogInSerializer, ActivationSerializer, PasswordResetSerializer, \
    RoleSerializer, ShopSerializer, UserSerializer, AddressSerializer
from backend.utils import hash_password, check_hashed_passwords, get_success_response, get_fail_response, get_object, \
    get_auth_token


class UserView(ViewSet):
    def create(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            hashed_password = hash_password(request.data['password'])
            role = Role.objects.get(name=RoleChoices.CLIENT)
            user = serializer.save(password=hashed_password, role=role)
            ActivationToken.objects.create(key=uuid.uuid4(), user=user)
            return Response(get_success_response(self.action, serializer), status=status.HTTP_201_CREATED)
        return Response(get_fail_response(self.action, serializer), status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        obj = get_object(User, pk)
        serializer = UserSerializer(obj)
        return Response(get_success_response(self.action, serializer, pk), status=status.HTTP_200_OK)

    def partial_update(self, request, pk=None):
        obj = get_object(User, pk)
        self.check_object_permissions(request, obj)
        serializer = UserSerializer(obj, request.data, partial=True)
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
        serializer = LogInSerializer(data=request.data)
        if serializer.is_valid():
            username = request.data['username']
            password = request.data['password']
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                return Response({"status": False, "message": "Username or/and password not found in DB"}, status=status.HTTP_404_NOT_FOUND)
            user_password = user.password
            if not check_hashed_passwords(password, user_password):
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
        serializer = ActivationSerializer(data=request.data)
        if serializer.is_valid():
            key = request.data['key']
            user = request.user
            try:
                registration_token = ActivationToken.objects.get(key=uuid.UUID(key))
            except ActivationToken.DoesNotExist:
                return Response({"status": False, "message": "Activation token key not found in DB"}, status=status.HTTP_404_NOT_FOUND)
            if registration_token.user != user:
                return Response({"status": False, "message": "You cannot activate account that does not belong to you"}, status=status.HTTP_403_FORBIDDEN)
            if user.is_active:
                return Response({"status": False, "message": "Account is already activated"}, status=status.HTTP_400_BAD_REQUEST)
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
        serializer = PasswordResetSerializer(data=request.data)
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
        if self.action in ['partial_update', 'destroy']:
            return [IsOwner()]
        return []

    def get_authenticators(self):
        if self.request.method not in ['POST', 'log_in']:
            return [TokenAuthentication()]
        return []


class RoleView(ViewSet):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAdmin]

    def list(self, request):
        queryset = Role.objects.all()
        serializer = RoleSerializer(queryset, many=True)
        return Response(get_success_response(self.action, serializer), status=status.HTTP_200_OK)

    def retrieve(self, request, pk=None):
        try:
            instance = Role.objects.get(id=pk)
        except Role.DoesNotExist:
            return Response({"status": False, "message": f"Role with id {pk} does not exist"}, status=status.HTTP_404_NOT_FOUND)
        serializer = RoleSerializer(instance)
        return Response({"status": True, "message": serializer.data}, status=status.HTTP_200_OK)

    def create(self, request):
        serializer = RoleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(get_success_response(self.action, serializer), status=status.HTTP_201_CREATED)
        return Response(get_fail_response(self.action, serializer), status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        obj = get_object(Role, pk)
        serializer = RoleSerializer(obj, request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(get_success_response(self.action, serializer), status=status.HTTP_206_PARTIAL_CONTENT)
        return Response(get_fail_response(self.action, serializer), status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        obj = get_object(Role, pk)
        obj.delete()
        return Response(get_success_response(self.action, pk=pk), status=status.HTTP_204_NO_CONTENT)


class ShopView(ViewSet):
    authentication_classes = [TokenAuthentication]

    def list(self, request):
        queryset = Shop.objects.all()
        serializer = ShopSerializer(queryset, many=True)
        return Response(get_success_response(self.action, serializer), status=status.HTTP_200_OK)

    def retrieve(self, request, pk=None):
        obj = get_object(Shop, pk)
        serializer = ShopSerializer(obj)
        return Response(get_success_response(self.action, serializer), status=status.HTTP_200_OK)

    def create(self, request):
        serializer = ShopSerializer(data=request.data)
        if serializer.is_valid():
            self.perform_create(serializer)
            return Response(get_success_response(self.action, serializer), status=status.HTTP_201_CREATED)
        return Response(get_fail_response(self.action, serializer), status=status.HTTP_400_BAD_REQUEST)

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

