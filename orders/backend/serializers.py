from rest_framework import serializers

from backend.models import User


class CreateAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'username', 'password', 'email', 'phone', 'role', 'is_active', 'created_at']
        read_only_fields = ['id', 'created_at', 'is_active']
        extra_kwargs = {
            'password': {'write_only': True}
        }


