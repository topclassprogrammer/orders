import datetime
import uuid

from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet

from backend.auth import TokenAuthentication
from backend.models import User, AuthToken, ActivationToken
from backend.serializers import CreateAccountSerializer, LogInSerializer, ActivationSerializer
from backend.utils import hash_password, check_hashed_passwords


class Account(ViewSet):
    @action(methods=['POST'], detail=False, url_path="create-account")
    def create_account(self, request):
        serializer = CreateAccountSerializer(data=request.data)
        if serializer.is_valid():
            hashed_password = hash_password(request.data['password'])
            user = serializer.save(password=hashed_password)
            ActivationToken.objects.create(key=uuid.uuid4(), user=user)
            return Response({"status": True, "message": f"You successfully created account: {serializer.data}"}, status=status.HTTP_201_CREATED)
        return Response({"status": False, "message": f"Incorrect registration data: {serializer.errors}"}, status.HTTP_400_BAD_REQUEST)

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
            else:
                user_password = user.password
                if not check_hashed_passwords(password, user_password):
                    return Response({"status": False, "message": "Username or/and password not found in DB"}, status=status.HTTP_404_NOT_FOUND)
            AuthToken.objects.create(key=uuid.uuid4(), user=user)
            user.last_login = datetime.datetime.now()
            user.save()
            return Response({"status": True, "message": "You just logged in"}, status=status.HTTP_200_OK)
        return Response({"status": False, "message": f"Incorrect username or/and password: {serializer.errors}"}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['POST'], authentication_classes=[TokenAuthentication], detail=False, url_path='log-out')
    def log_out(self, request):
        token_header = request.META.get('HTTP_AUTHORIZATION')
        token_list = token_header.split(" ")
        token = token_list[1]
        auth_token = AuthToken.objects.get(key=uuid.UUID(token))
        auth_token.delete()
        return Response({"status": True, "message": "You just logged out"})

    @action(methods=['POST'], authentication_classes=[TokenAuthentication], detail=False, url_path='activate')
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
                return Response({"status": False, "message": "User is already activated"}, status=status.HTTP_400_BAD_REQUEST)
            user.is_active = True
            user.save()
            registration_token.delete()
            return Response({"status": True, "message": "Account successfully activated"}, status=status.HTTP_200_OK)
        return Response({"status": False, "message": f"Incorrect activation data: {serializer.errors}"}, status=status.HTTP_400_BAD_REQUEST)
