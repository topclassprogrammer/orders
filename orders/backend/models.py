import uuid

import bcrypt
from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models
from django.utils.text import slugify

from backend.validators import check_username, check_password, check_email, check_phone, check_url, \
    check_shop_role


class RoleChoices(models.TextChoices):
    ADMIN = "admin", "Admin"
    CLIENT = "client", "Client"
    SHOP = "shop", "Shop"


class CartChoices(models.TextChoices):
    CART = "cart", "In cart"
    NEW = "new", "New"
    PACKING = "packing", "Packing"
    PACKED = "packed", "Packed"
    DELIVERING = "delivering", "Delivering"
    DELIVERED = "delivered", "Delivered"
    CANCELED = "сanceled", "Сanceled"
    RECEIVED = "received", "Received"


class User(AbstractBaseUser):
    USERNAME_FIELD = "username"

    first_name = models.CharField(max_length=32)
    last_name = models.CharField(max_length=32)
    username = models.CharField(max_length=32, unique=True, validators=[check_username])
    password = models.CharField(max_length=128, validators=[check_password])
    email = models.CharField(max_length=320, unique=True, validators=[check_email])
    phone = models.CharField(max_length=19, validators=[check_phone])
    role = models.ForeignKey("Role", on_delete=models.CASCADE, related_name="users")
    is_active = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def clean(self):
        super().clean()
        password_bytes = self.password.encode()
        password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
        self.password = password.decode()


class Role(models.Model):
    name = models.CharField(choices=RoleChoices, unique=True)


class Shop(models.Model):
    name = models.CharField(max_length=64, unique=True)
    url = models.URLField(max_length=256, blank=True, validators=[check_url])
    accept_orders = models.BooleanField(default=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="shop", validators=[check_shop_role])


class AuthToken(models.Model):
    key = models.UUIDField()
    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="auth_tokens")


class ActivationToken(models.Model):
    key = models.UUIDField()
    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="activation_token")


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


class Item(models.Model):
    brand = models.ForeignKey("Brand", on_delete=models.CASCADE, related_name="items")
    model = models.ForeignKey("Model", on_delete=models.CASCADE, related_name="items")
    category = models.ForeignKey("Category", on_delete=models.CASCADE, related_name="items")
    details = models.OneToOneField("Details", on_delete=models.CASCADE, related_name="item")
    shop = models.ForeignKey(Shop, on_delete=models.CASCADE, related_name="items")
    price = models.DecimalField(max_digits=10, decimal_places=2)
    quantity = models.PositiveSmallIntegerField(default=0)
    slug = models.SlugField(max_length=64, unique=True, blank=True)

    def clean(self):
        super().clean()
        self.slug = slugify(self.brand.name + self.model.name)
        if Item.objects.filter(slug=self.slug):
            self.slug += str(uuid.uuid4())


class Details(models.Model):
    description = models.TextField(null=True, blank=True)
    image = models.ImageField(upload_to="images", null=True, blank=True)
    display_diagonal = models.DecimalField(max_digits=4, decimal_places=2, null=True, blank=True)
    display_resolution = models.CharField(max_length=24, null=True, blank=True)
    camera_back = models.DecimalField(max_digits=3, decimal_places=1, null=True, blank=True)
    camera_front = models.DecimalField(max_digits=3, decimal_places=1, null=True, blank=True)
    cpu_cores = models.PositiveSmallIntegerField(default=1, null=True, blank=True)
    battery = models.PositiveSmallIntegerField(null=True, blank=True)
    memory = models.PositiveSmallIntegerField(null=True, blank=True)
    color = models.CharField(max_length=32, null=True, blank=True)
    year = models.PositiveSmallIntegerField(null=True, blank=True)


class Brand(models.Model):
    name = models.CharField(max_length=32)


class Model(models.Model):
    name = models.CharField(max_length=64)
    brand = models.ForeignKey(Brand, on_delete=models.CASCADE, related_name="models")


class Category(models.Model):
    name = models.CharField(max_length=32)



