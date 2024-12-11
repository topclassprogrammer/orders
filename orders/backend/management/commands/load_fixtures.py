import json

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand
from django.db.transaction import set_autocommit, commit, rollback
from django.db.utils import IntegrityError

from backend.models import Role, User
from django.conf import settings


FIXTURE_FILE_NAME = 'fixture.json'


class Command(BaseCommand):
    def handle(self, *args, **options):
        fixture_path = str(settings.BASE_DIR) + '/' + FIXTURE_FILE_NAME
        with open(fixture_path, encoding='utf-8') as fixture_file:
            stream = json.load(fixture_file)
        set_autocommit(autocommit=False)
        try:
            role_objs = [Role(**el) for el in stream['role']]
            [el.full_clean() for el in role_objs]
            Role.objects.bulk_create(role_objs)

            user_objs = [User(**el) for el in stream['user']]
            [el.full_clean() for el in user_objs]
            User.objects.bulk_create(user_objs)

        except (IntegrityError, TypeError, ValidationError) as err:
            rollback()
            print(f"Cannot apply any fixtures because of error: {err}")
        else:
            commit()

