import json

from django.core.management.base import BaseCommand

from django.conf import settings


class Command(BaseCommand):
    def handle(self, *args, **options):
        fixture_path = str(settings.BASE_DIR) + '\\fixture.json'
        fixture_file = open(fixture_path, encoding="utf-8")
        stream = json.load(fixture_file)

