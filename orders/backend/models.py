from django.db import models


class RoleChoices(models.TextChoices):
    ADMIN = "admin", "Admin"
    CLIENT = "client", "Client"
    SHOP = "shop", "Shop"


class Role(models.Model):
    name = models.CharField(choices=RoleChoices, unique=True)
