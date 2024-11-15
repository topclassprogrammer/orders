import datetime
import uuid

from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet

from backend.models import ConfirmRegistrationToken, User, AuthToken
from backend.serializers import CreateAccountSerializer, LogInSerializer
from backend.utils import hash_password, check_hashed_passwords


class Account(ViewSet):
    @action(methods=['POST'], detail=False, url_path="create-account")
    def create_account(self, request):
        serializer = CreateAccountSerializer(data=request.data)
        if serializer.is_valid():
            hashed_password = hash_password(request.data['password'])
            user = serializer.save(password=hashed_password)
            ConfirmRegistrationToken.objects.create(key=uuid.uuid4(), user=user)
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

