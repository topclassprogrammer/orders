import pytest
import os
import django
from django.conf import settings

USER_DATA = {
    'first_name': 'test_first_name',
    'last_name': 'test_last_name',
    'username': 'test_username',
    'password': 'test_password',
    'email': 'test@email.com',
    'phone': '+70123456789'
}


def django_test_setup():
    os.environ['DJANGO_SETTINGS_MODULE'] = "orders.settings"
    django.setup()


django_test_setup()


@pytest.fixture
def client():
    from rest_framework.test import APIClient
    return APIClient()


@pytest.fixture
def create_roles():
    from backend.models import Role
    Role.objects.create(name='admin')
    Role.objects.create(name='client')
    Role.objects.create(name='shop')


