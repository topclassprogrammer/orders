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
    """Set up the Django test environment."""
    os.environ['DJANGO_SETTINGS_MODULE'] = "orders.settings"
    django.setup()


django_test_setup()


@pytest.fixture
def client():
    """
    Create and return an instance of APIClient for testing.

    Returns:
        APIClient: An instance of APIClient for making API requests in tests.
    """
    from rest_framework.test import APIClient
    return APIClient()


@pytest.fixture
def create_roles():
    """Create predefined roles for testing purposes."""
    from backend.models import Role
    Role.objects.create(name='admin')
    Role.objects.create(name='client')
    Role.objects.create(name='shop')


@pytest.fixture
def user():
    """
    Create and return a test user.

    Returns:
        User: The created user instance.
    """
    from backend.models import User, Role, RoleChoices
    user = User.objects.create(**USER_DATA, is_active=True, role=Role.objects.get(name=RoleChoices.CLIENT))
    return user


@pytest.fixture
def user_throttle_rate():
    """
    Return the user's throttle rate from settings.

    Returns:
        int: The number of allowed requests for users in the throttle rate.
    """
    user_rate_str = settings.__dict__['REST_FRAMEWORK']['DEFAULT_THROTTLE_RATES']['user']
    user_rate = int(user_rate_str.split('/')[0])
    return user_rate


@pytest.fixture
def anon_throttle_rate():
    """
    Return the anonymous user's throttle rate from settings.

    Returns:
        int: The number of allowed requests for anonymous users in the throttle rate.
    """
    anon_rate_str = settings.__dict__['REST_FRAMEWORK']['DEFAULT_THROTTLE_RATES']['anon']
    anon_rate = int(anon_rate_str.split('/')[0])
    return anon_rate
