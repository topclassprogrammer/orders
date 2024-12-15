import json
import os

from backend.models import Role, User
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand
from django.db.transaction import commit, rollback, set_autocommit
from django.db.utils import IntegrityError
from dotenv import load_dotenv

from backend.utils import hash_password

load_dotenv()

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

            User.objects.create(**stream['user'][0], username=os.getenv('ADMIN_USERNAME'),
                                password=hash_password(os.getenv('ADMIN_PASSWORD')),
                                email=os.getenv('ADMIN_EMAIL'), is_active=True)
        except (IntegrityError, TypeError, ValidationError) as err:
            rollback()
            print(f"Cannot apply any fixtures because of error: {err}")
        else:
            commit()
