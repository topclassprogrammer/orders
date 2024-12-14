import uuid

from django.contrib.auth.base_user import AbstractBaseUser
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.text import slugify

from backend.utils import hash_password
from backend.validators import check_email, check_password, check_phone, \
    check_url, check_username


class RoleChoices(models.TextChoices):
    """Enumeration for user roles."""
    ADMIN = "admin", "Admin"
    CLIENT = "client", "Client"
    SHOP = "shop", "Shop"


class OrderChoices(models.TextChoices):
    """Enumeration for order statuses."""
    CART = "cart", "In cart"
    NEW = "new", "New"
    PACKING = "packing", "Packing"
    PACKED = "packed", "Packed"
    DELIVERING = "delivering", "Delivering"
    DELIVERED = "delivered", "Delivered"
    CANCELED = "canceled", "Canceled"
    RECEIVED = "received", "Received"


class User(AbstractBaseUser):
    """User model."""
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
        """Hash the password before saving the user."""
        super().clean()
        self.password = hash_password(self.password)


class Role(models.Model):
    """User roles model."""
    name = models.CharField(max_length=32, unique=True)


class Shop(models.Model):
    """Shop model."""
    name = models.CharField(max_length=64, unique=True)
    url = models.URLField(max_length=256, blank=True, validators=[check_url])
    accept_orders = models.BooleanField(default=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="shop")

    def clean(self):
        """Validate that the associated user has shop rights."""
        super().clean()
        if self.user.role.name != RoleChoices.SHOP:
            raise ValidationError(f"User {self.user} does not have shop rights")


class AuthToken(models.Model):
    """Model representing authentication tokens for users."""
    key = models.UUIDField(db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="auth_tokens")

    def clean(self):
        """Generate a new UUID for the token before saving."""
        super().clean()
        self.key = uuid.uuid4()


class ActivationToken(models.Model):
    """Model representing activation tokens for user accounts."""
    key = models.UUIDField()
    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="activation_tokens")


class PasswordResetToken(models.Model):
    """Model representing password reset tokens for user accounts."""
    key = models.UUIDField()
    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="password_reset_tokens")


class Order(models.Model):
    """Model representing an order placed by a user."""
    state = models.CharField(choices=OrderChoices, default=OrderChoices.CART)
    address = models.ForeignKey("Address", on_delete=models.CASCADE, related_name="orders", null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="orders", db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)


class OrderItem(models.Model):
    """Model representing an individual item in an order."""
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name="order_items", db_index=True)
    item = models.ForeignKey("Item", on_delete=models.CASCADE, related_name="order_items")
    quantity = models.PositiveSmallIntegerField(default=0)


class Address(models.Model):
    """Model representing a user's delivery address."""
    country = models.CharField(max_length=64)
    region = models.CharField(max_length=64)
    city = models.CharField(max_length=64)
    street = models.CharField(max_length=64)
    house = models.PositiveSmallIntegerField()
    apartment = models.PositiveSmallIntegerField(null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="addresses")

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['country', 'region', 'city', 'street', 'house', 'apartment', 'user'],
                                    name='unique_address'),
        ]


class Item(models.Model):
    """Model representing an item for sale."""
    brand = models.ForeignKey("Brand", on_delete=models.CASCADE, related_name="items")
    model = models.ForeignKey("Model", on_delete=models.CASCADE, related_name="items")
    category = models.ForeignKey("Category", on_delete=models.CASCADE, related_name="items")
    shop = models.ForeignKey(Shop, on_delete=models.CASCADE, related_name="items", db_index=True)
    description = models.TextField(null=True, blank=True)
    image = models.ImageField(null=True, blank=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    quantity = models.PositiveSmallIntegerField(default=0)
    slug = models.SlugField(max_length=128, unique=True, blank=True)

    def clean(self):
        """Generate a unique slug for the item based on the brand and model names."""
        super().clean()
        self.slug = slugify(self.brand.name + '-' + self.model.name)
        if Item.objects.filter(slug=self.slug):
            self.slug += ('-' + str(uuid.uuid4()))
        if Item.objects.filter(image=self.image):
            # noinspection PyUnresolvedReferences
            image_split = self.image.split('.')
            filename = image_split[-2]
            ext = image_split[-1]
            filename += ('-' + str(uuid.uuid4()))
            self.image = filename + '.' + ext

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['brand', 'model', 'category', 'shop'], name='unique_item')
        ]


class PropertyValue(models.Model):
    """Model representing a value for a specific property of an item."""
    item = models.ForeignKey(Item, on_delete=models.CASCADE, related_name="property_value")
    property_name = models.ForeignKey("PropertyName", on_delete=models.CASCADE, related_name="property_value")
    value = models.CharField(max_length=32)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['item', 'property_name'], name='unique_property_value'),
        ]


class PropertyName(models.Model):
    """Model representing the name of a property."""
    name = models.CharField(max_length=32, unique=True)


class Brand(models.Model):
    """Model representing a brand of products."""
    name = models.CharField(max_length=32, unique=True)


class Model(models.Model):
    """Model representing a specific model of a product."""
    name = models.CharField(max_length=64)
    brand = models.ForeignKey(Brand, on_delete=models.CASCADE, related_name="models", db_index=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['name', 'brand'], name='unique_model')
        ]


class Category(models.Model):
    """Model representing a category of items."""
    name = models.CharField(max_length=32, unique=True)



