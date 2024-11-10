from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models


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

