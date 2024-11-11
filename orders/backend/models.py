from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models

from orders.backend.validators import check_username, check_password, check_email, check_phone, check_url, \
    check_shop_role


class RoleChoices(models.TextChoices):
    ADMIN = "admin", "Admin"
    CLIENT = "client", "Client"
    SHOP = "shop", "Shop"


class CartChoices(models.TextChoices):
    CART = "cart", "In cart"
    NEW = "new", "Ordered"
    PACKING = "packing", "Packing"
    PACKED = "packed", "Packed"
    DELIVERING = "delivering", "Delivering"
    DELIVERED = "delivered", "Delivered"
    CANCELED = "сanceled", "Сanceled"
    RECEIVED = "received", "Received"


class Role(models.Model):
    name = models.CharField(choices=RoleChoices, unique=True)


class User(AbstractBaseUser):
    USERNAME_FIELD = "username"

    first_name = models.CharField(max_length=32)
    last_name = models.CharField(max_length=32)
    username = models.CharField(max_length=32, unique=True, validators=[check_username])
    password = models.CharField(max_length=32, validators=[check_password])
    email = models.CharField(max_length=320, unique=True, validators=[check_email])
    phone = models.CharField(max_length=19, validators=[check_phone])
    role = models.ForeignKey("Role", on_delete=models.CASCADE, related_name="users")
    created_at = models.DateTimeField(auto_now_add=True)


class Shop(models.Model):
    name = models.CharField(max_length=64, unique=True)
    url = models.URLField(max_length=256, null=True, validators=[check_url])
    accept_orders = models.BooleanField(default=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="shop", validators=[check_shop_role])


class AuthToken(models.Model):
    key = models.UUIDField()
    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="auth_tokens")


class ConfirmRegistrationToken(models.Model):
    key = models.UUIDField()
    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="confirm_registration_tokens")


class PasswordResetToken(models.Model):
    key = models.UUIDField()
    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="password_reset_tokens")


class Order(models.Model):
    state = models.CharField(choices=CartChoices, default=CartChoices.CART)
    created_at = models.DateTimeField(auto_now_add=True)
    address = models.ForeignKey("Address", on_delete=models.CASCADE, related_name="orders")
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="orders")


class OrderItems(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name="order_items")
    item = models.ForeignKey("Item", on_delete=models.CASCADE, related_name="order_items")
    quantity = models.PositiveSmallIntegerField(default=0)


class Address(models.Model):
    country = models.CharField(max_length=64)
    region = models.CharField(max_length=64)
    city = models.CharField(max_length=64)
    street = models.CharField(max_length=64)
    house = models.PositiveSmallIntegerField()
    apartment = models.PositiveSmallIntegerField(null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="addresses")


