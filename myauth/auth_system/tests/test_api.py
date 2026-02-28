import pytest
from auth_system.models import User
from django.urls import reverse
from rest_framework.test import APIClient


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def test_user():
    return User.objects.create_user(
        email='test@example.com',
        first_name='Test',
        last_name='User',  # Исправлено: было lastname
        password='testpass123'
    )


class TestAPITests:
    @pytest.mark.django_db
    def test_login_success(self, api_client, test_user):
        url = reverse('login')
        data = {
            'email': 'test@example.com',
            'password': 'testpass123'
        }
        response = api_client.post(url, data, format='json')
        assert response.status_code == 200
        assert 'token' in response.data


@pytest.mark.django_db
def test_protected_endpoint_with_valid_token(api_client, test_user, user_role, access_rule):
    login_url = reverse('login')
    login_data = {
        'email': 'test@example.com',
        'password': 'testpass123'
    }
    login_response = api_client.post(login_url, login_data, format='json')

    # Проверка успешного логина
    assert login_response.status_code == 200
    token = login_response.data['token']

    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
    protected_url = reverse('posts-list')
    response = api_client.get(protected_url)
    assert response.status_code in [200, 201], f'Expected 200 or 201, got {response.status_code}'
