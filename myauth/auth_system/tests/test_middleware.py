from unittest.mock import patch

import pytest
from auth_system.middleware import CustomAuthMiddleware
from django.http import HttpRequest

@pytest.fixture
def middleware():
    return CustomAuthMiddleware(get_response=lambda request: None)

@pytest.fixture
def mock_request():
    request = HttpRequest()
    request.path = '/api/protected/'
    request.method = 'GET'
    return request

class TestCustomAuthMiddleware:
    def test_valid_jwt_authentication(self, middleware, mock_request):
        with patch('auth_system.middleware.verify_jwt_token', return_value=True):
            response = middleware(mock_request)
            assert response is None

    def test_invalid_token_returns_anonymous(self, middleware, mock_request):
        mock_request.META['HTTP_AUTHORIZATION'] = 'Bearer invalid_token'
        response = middleware(mock_request)
        assert mock_request.user.is_anonymous
