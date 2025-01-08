import uuid

import pytest
from django.urls import reverse
from backend.models import User, ActivationToken, AuthToken, PasswordResetToken
from tests.conftest import USER_DATA


@pytest.mark.django_db
def test_user(client, create_roles, subtests):
    response = client.post(reverse('user-list'), USER_DATA, format='json')
    assert response.status_code == 201

    with subtests.test(msg="Check if activation token exists"):
        user = User.objects.get(username='test_username')
        assert user.id == 1

        activation_token_filter = ActivationToken.objects.filter(user=user)
        assert activation_token_filter

    with subtests.test(msg="Activate user account"):
        activation_token = activation_token_filter[0]
        response = client.post(reverse("user-activate"), {
            "key": str(activation_token.key)
        })
        assert response.status_code == 200

    with subtests.test(msg="Check if activation token does not exist"):
        activation_token_filter = ActivationToken.objects.filter(key=activation_token.key)
        assert not activation_token_filter

    with subtests.test(msg="Log in"):
        response = client.post(reverse("user-log-in"), {
            'username': 'test_username',
            'password': 'test_password',
        })
        assert response.status_code == 200

    with subtests.test(msg="Check if auth token exists"):
        auth_token_filter = AuthToken.objects.filter(user=user)
        assert auth_token_filter

    with subtests.test(msg="Log out"):
        auth_token = auth_token_filter[0]
        response = client.post(reverse("user-log-out"), headers={'Authorization': f'Token {auth_token.key}'})
        assert response.status_code == 200

    with subtests.test(msg="Check if auth token does not exist"):
        auth_token = AuthToken.objects.filter(key=auth_token.key)
        assert not auth_token

    with subtests.test(msg="Request new password"):
        response = client.post(reverse("user-request-new-password"), {"email": "test@email.com"})
        assert response.status_code == 200

    with subtests.test(msg="Check if password reset token exists"):
        password_reset_token_filter = PasswordResetToken.objects.filter(user=user)
        assert password_reset_token_filter

    with subtests.test(msg="Set new password"):
        password_reset_token = password_reset_token_filter[0]
        response = client.post(reverse("user-set-new-password"), {
            "key": password_reset_token.key, "password": "test_new_password"})
        assert response.status_code == 200

    with subtests.test(msg="Check if password reset token does not exist"):
        password_reset_token = PasswordResetToken.objects.filter(key=password_reset_token.key)
        assert not password_reset_token

    with subtests.test(msg="Log in with new password"):
        response = client.post(reverse("user-log-in"), {
            'username': 'test_username',
            'password': 'test_new_password',
        })
        assert response.status_code == 200


@pytest.mark.django_db
def test_anon_throttle(client, create_roles, anon_throttle_rate):
    for rate in range(1, anon_throttle_rate + 2):
        response = client.post(reverse('user-list'), format='json')
        if response.status_code == 400:
            continue
        assert response.status_code == 429


