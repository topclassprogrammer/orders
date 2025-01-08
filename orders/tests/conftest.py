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


