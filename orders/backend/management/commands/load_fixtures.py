import json

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand
from django.db.utils import IntegrityError

from backend.models import Role, User, Shop, Address, Brand, Model, Category, Details, Item, Order, OrderItems
from django.conf import settings


class Command(BaseCommand):
    def handle(self, *args, **options):
        fixture_path = str(settings.BASE_DIR) + '\\fixture.json'
        fixture_file = open(fixture_path, encoding="utf-8")
        stream = json.load(fixture_file)
        try:
            role_objs = [Role(**el) for el in stream['role']]
            [el.full_clean() for el in role_objs]
            Role.objects.bulk_create(role_objs)

            user_objs = [User(**el) for el in stream['user']]
            [el.full_clean() for el in user_objs]
            User.objects.bulk_create(user_objs)

            shop_objs = [Shop(**el) for el in stream['shop']]
            [el.full_clean() for el in shop_objs]
            Shop.objects.bulk_create(shop_objs)

            address_objs = [Address(**el) for el in stream['address']]
            [el.full_clean() for el in address_objs]
            Address.objects.bulk_create(address_objs)

            brand_objs = [Brand(**el) for el in stream['brand']]
            [el.full_clean() for el in brand_objs]
            Brand.objects.bulk_create(brand_objs)

            model_objs = [Model(**el) for el in stream['model']]
            [el.full_clean() for el in model_objs]
            Model.objects.bulk_create(model_objs)

            category_objs = [Category(**el) for el in stream['category']]
            [el.full_clean() for el in category_objs]
            Category.objects.bulk_create(category_objs)

            details_objs = [Details(**el) for el in stream['details']]
            [el.full_clean() for el in details_objs]
            Details.objects.bulk_create(details_objs)

            item_objs = [Item(**el) for el in stream['item']]
            [el.full_clean() for el in item_objs]
            Item.objects.bulk_create(item_objs)

            order_objs = [Order(**el) for el in stream['order']]
            [el.full_clean() for el in order_objs]
            Order.objects.bulk_create(order_objs)

            order_items_objs = [OrderItems(**el) for el in stream['order_items']]
            [el.full_clean() for el in order_items_objs]
            OrderItems.objects.bulk_create(order_items_objs)

        except IntegrityError as err:
            raise ValidationError(f"Объект уже существует: {err}")
        except TypeError as err:
            raise ValidationError(f"Поле модели не существует: {err}")
