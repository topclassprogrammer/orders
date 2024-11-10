from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models

from orders.backend.validators import check_username, check_password, check_email, check_phone, check_url, \
    check_shop_role


class RoleChoices(models.TextChoices):
    ADMIN = "admin", "Admin"
    CLIENT = "client", "Client"
    SHOP = "shop", "Shop"


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


