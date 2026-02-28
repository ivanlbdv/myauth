from datetime import timedelta
from unittest.mock import patch

import jwt
from auth_system.middleware import CustomAuthMiddleware
from auth_system.models import User
from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory, TestCase
from django.utils import timezone


class CustomAuthMiddlewareTestCase(TestCase):
    def setUp(self):
        self.middleware = CustomAuthMiddleware(lambda request: None)
        self.factory = RequestFactory()

        self.user = User.objects.create_user(
            email='test@example.com',
            first_name='Test',
            last_name='User',
            password='testpass123'
        )

    def create_jwt_token(self, user_id, expires_in_hours=24):
        """Вспомогательная функция для создания JWT‑токена"""
        payload = {
            'user_id': user_id,
            'email': 'test@example.com',
            'exp': timezone.now() + timedelta(hours=expires_in_hours),
            'iat': timezone.now(),
        }
        return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

    def test_middleware_exempt_paths(self):
        """Тест: middleware пропускает публичные эндпоинты"""
        exempt_paths = [
            '/api/auth/register/',
            '/api/auth/login/',
            '/api/auth/logout/'
        ]

        for path in exempt_paths:
            request = self.factory.get(path)
            response = self.middleware(request)
            self.assertIsNone(response)

    def test_middleware_valid_jwt(self):
        """Тест: успешная аутентификация с валидным JWT"""
        token = self.create_jwt_token(self.user.id)

        request = self.factory.get('/api/protected/')
        request.headers = {'Authorization': f'Bearer {token}'}

        with patch.object(self.middleware, 'has_permission', return_value=True):
            response = self.middleware(request)

        self.assertEqual(request.user, self.user)
        self.assertIsNone(response)

    def test_middleware_expired_jwt(self):
        """Тест: отказ с просроченным JWT"""
        expired_token = self.create_jwt_token(self.user.id, expires_in_hours=-1)

        request = self.factory.get('/api/protected/')
        request.headers = {'Authorization': f'Bearer {expired_token}'}

        response = self.middleware(request)

        self.assertIsInstance(request.user, AnonymousUser)
        self.assertIsNone(response, "Middleware должно возвращать None для просроченного токена")

    def test_middleware_invalid_jwt(self):
        """Тест: отказ с неверным JWT (неверная подпись)"""
        valid_token = self.create_jwt_token(self.user.id)
        invalid_token = valid_token + 'x'  # Добавляем лишний символ для инвалидации токена

        request = self.factory.get('/api/protected/')
        request.headers = {'Authorization': f'Bearer {invalid_token}'}

        response = self.middleware(request)

        self.assertIsInstance(request.user, AnonymousUser)
        self.assertIsNone(response, "Middleware должно возвращать None для неверного JWT")

    def test_middleware_missing_authorization_header(self):
        """Тест: запрос без заголовка Authorization"""
        request = self.factory.get('/api/protected/')

        response = self.middleware(request)

        self.assertIsInstance(request.user, AnonymousUser)
        self.assertIsNone(response, "Middleware должно возвращать None при отсутствии заголовка Authorization")

    def test_middleware_invalid_authorization_format(self):
        """Тест: неверный формат заголовка Authorization (отсутствует Bearer)"""
        token = self.create_jwt_token(self.user.id)

        request = self.factory.get('/api/protected/')
        request.headers = {'Authorization': token}

        response = self.middleware(request)

        self.assertIsInstance(request.user, AnonymousUser)
        self.assertIsNone(response, "Middleware должно возвращать None для неверного формата Authorization")

    def test_middleware_user_not_found(self):
        """Тест: JWT валиден, но пользователь не найден в БД"""
        nonexistent_user_id = 99999
        token = self.create_jwt_token(nonexistent_user_id)

        request = self.factory.get('/api/protected/')
        request.headers = {'Authorization': f'Bearer {token}'}

        response = self.middleware(request)

        self.assertIsInstance(request.user, AnonymousUser)
        self.assertIsNone(response, "Middleware должно возвращать None, когда пользователь не найден")

    def test_middleware_permission_check_fails(self):
        """Тест: JWT валиден, пользователь найден, но нет прав доступа"""
        token = self.create_jwt_token(self.user.id)

        request = self.factory.get('/api/protected/')
        request.headers = {'Authorization': f'Bearer {token}'}

        with patch.object(self.middleware, 'has_permission', return_value=True):
            response_auth = self.middleware(request)

        self.assertTrue(hasattr(request, 'user'), "JWT должен быть обработан и user установлен")
        self.assertEqual(request.user, self.user, "Пользователь должен быть аутентифицирован по JWT")

        with patch.object(self.middleware, 'has_permission', return_value=False):
            response = self.middleware(request)

        self.assertIsNone(response, "Middleware должно пропускать запрос даже при отсутствии прав")

    def test_middleware_permission_check_succeeds(self):
        """Тест: JWT валиден, пользователь найден, права доступа есть"""
        token = self.create_jwt_token(self.user.id)

        request = self.factory.get('/api/protected/')
        request.headers = {'Authorization': f'Bearer {token}'}

        with patch.object(self.middleware, 'has_permission', return_value=True):
            response = self.middleware(request)

        self.assertTrue(hasattr(request, 'user'), "Атрибут 'user' должен быть установлен middleware после успешной аутентификации")

        self.assertFalse(isinstance(request.user, AnonymousUser), "Пользователь не должен быть анонимным при валидном JWT")
        self.assertEqual(request.user, self.user, "Пользователь должен быть аутентифицирован по JWT")

        self.assertIsNone(response, "Middleware должно пропускать запрос при наличии прав")

    def test_middleware_exception_handling(self):
        """Тест: обработка неожиданных исключений в middleware"""
        token = self.create_jwt_token(self.user.id)

        request = self.factory.get('/api/protected/')
        request.headers = {'Authorization': f'Bearer {token}'}

        with patch.object(self.middleware, 'has_permission', return_value=True):
            self.middleware(request)
        self.assertEqual(request.user, self.user, "Пользователь должен быть аутентифицирован")

        with patch.object(
            self.middleware,
            'has_permission',
            side_effect=Exception("Unexpected error")
        ):
            response = self.middleware(request)

        self.assertTrue(hasattr(request, 'user'), "user должен сохраняться при исключении")
        self.assertEqual(request.user, self.user, "user не должен меняться при исключении")
        self.assertIsNone(response, "Middleware должно пропускать запрос даже при исключении")
