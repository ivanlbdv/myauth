import pytest
from django.urls import reverse
from rest_framework.test import APIClient, APITestCase


class TestAuthViews(APITestCase):
    def setUp(self):
        self.client = APIClient()

    def test_register_view_validation_error(self):
        url = reverse('register')
        data = {'email': 'invalid-email'}
        response = self.client.post(url, data, format='json')
        assert response.status_code == 400
        assert 'email' in response.data

    def test_user_detail_get_unauthenticated(self):
        url = reverse('user-detail', kwargs={'user_id': 1})
        response = self.client.get(url)
        assert response.status_code in [401, 403]
