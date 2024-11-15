from rest_framework import serializers

from backend.models import User
from backend.validators import check_password


class CreateAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'username', 'password', 'email', 'phone', 'role', 'is_active', 'created_at']
        read_only_fields = ['id', 'created_at', 'is_active']
        extra_kwargs = {
            'password': {'write_only': True}
        }


class LogInSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=128, validators=[check_password])

    class Meta:
        model = User
        fields = ['id', 'username', 'password']
        read_only_fields = ['id']
        extra_kwargs = {
            'username': {'write_only': True},
            'password': {'write_only': True}
        }
