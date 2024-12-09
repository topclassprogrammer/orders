from rest_framework import serializers

from backend.models import User, ActivationToken, PasswordResetToken, Role, Shop, Address, Brand, Model, Category, Item, \
    PropertyName, PropertyValue, Order, OrderItem
from backend.utils import hash_password
from backend.validators import check_password, check_username


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'username', 'password', 'email', 'phone', 'role', 'is_active', 'created_at']
        read_only_fields = ['id', 'is_active', 'role', 'created_at']
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def validate_password(self, value) -> str:
        return hash_password(value)


class LogInSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=128, validators=[check_username])

    class Meta:
        model = User
        fields = ['id', 'username', 'password']
        read_only_fields = ['id']
        extra_kwargs = {
            'username': {'write_only': True},
            'password': {'write_only': True}
        }


class ActivationSerializer(serializers.ModelSerializer):
    class Meta:
        model = ActivationToken
        fields = ['id', 'key', 'created_at', 'user']
        read_only_fields = ['id', 'created_at', 'user']
        extra_kwargs = {
            'key': {'write_only': True}
        }


class PasswordResetSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=128, validators=[check_password])

    class Meta:
        model = PasswordResetToken
        fields = ['id', 'key', 'created_at', 'password']
        read_only_fields = ['id', 'created_at']
        extra_kwargs = {
            'key': {'write_only': True},
            'password': {'write_only': True}
        }


class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ['id', 'name']
        read_only_fields = ['id']


class ShopSerializer(serializers.ModelSerializer):
    class Meta:
        model = Shop
        fields = ['id', 'name', 'url', 'accept_orders', 'user']
        read_only_fields = ['id', 'user']


class AddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = Address
        fields = ['id', 'country', 'region', 'city', 'street', 'house', 'apartment', 'user']
        read_only_fields = ['id', 'user']


class BrandSerializer(serializers.ModelSerializer):
    class Meta:
        model = Brand
        fields = ['id', 'name']
        read_only_fields = ['id']


class ModelSerializer(serializers.ModelSerializer):
    brand = BrandSerializer(read_only=True)

    class Meta:
        model = Model
        fields = ['id', 'name', 'brand']
        read_only_fields = ['id']


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ['id', 'name']
        read_only_fields = ['id']


class ItemSerializer(serializers.ModelSerializer):
    brand = BrandSerializer(read_only=True)
    model = ModelSerializer(read_only=True)
    category = CategorySerializer(read_only=True)
    shop = ShopSerializer(read_only=True)

    class Meta:
        model = Item
        fields = ['id', 'brand', 'model', 'category', 'shop', 'description', 'image', 'price', 'quantity', 'slug']
        read_only_fields = ['id', 'shop']


class PropertyNameSerializer(serializers.ModelSerializer):
    class Meta:
        model = PropertyName
        fields = ['id', 'name']
        read_only_fields = ['id']


class PropertyValueSerializer(serializers.ModelSerializer):
    property_name = PropertyNameSerializer()
    item = ItemSerializer()

    class Meta:
        model = PropertyValue
        fields = ['id', 'item', 'property_name', 'value']
        read_only_fields = ['id']


class OrderSerializer(serializers.ModelSerializer):
    address = AddressSerializer()
    user = UserSerializer(read_only=True)
    sum = serializers.DecimalField(max_digits=15, decimal_places=2)

    class Meta:
        model = Order
        fields = ['id', 'state', 'address', 'user', 'sum', 'created_at']
        read_only_fields = ['id', 'state', 'user', 'sum' 'created_at']


class OrderItemSerializer(serializers.ModelSerializer):
    order = OrderSerializer()
    item = ItemSerializer()

    class Meta:
        model = OrderItem
        fields = ['id', 'order', 'item', 'quantity']
        read_only_fields = ['id', 'order']



