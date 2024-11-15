import uuid

from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet

from backend.models import ConfirmRegistrationToken
from backend.serializers import CreateAccountSerializer
from backend.utils import hash_password


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
