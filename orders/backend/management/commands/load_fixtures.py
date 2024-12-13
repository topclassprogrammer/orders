import json

from backend.models import Role, User
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand
from django.db.transaction import commit, rollback, set_autocommit
from django.db.utils import IntegrityError

FIXTURE_FILE_NAME = 'fixture.json'


class Command(BaseCommand):
    """Django management command for loading data fixtures."""
    def handle(self, *args, **options):
        """Load data fixtures into the database."""
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
