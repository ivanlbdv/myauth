import time

import jwt
from auth_system.models import Role, User, UserRole
from django.conf import settings
from django.urls import reverse
from rest_framework.test import APITestCase


class TestUserRegistration(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.role_user = Role.objects.create(
            name='user',
            description='Обычный пользователь'
        )

    def _register_and_login_user(self, email, password):
        """Вспомогательный метод: регистрирует и логинит пользователя, возвращает response от логина"""
        register_data = {
            'first_name': 'Test',
            'last_name': 'User',
            'email': email,
            'password': password,
            'password_confirm': password
        }
        register_response = self.client.post(
            reverse('register'),
            register_data,
            format='json'
        )
        self.assertEqual(register_response.status_code, 201)

        login_data = {'email': email, 'password': password}
        login_response = self.client.post(
            reverse('login'),
            login_data,
            format='json'
        )
        self.assertEqual(login_response.status_code, 200)

        if 'access' in login_response.data:
            login_response.data['token'] = login_response.data['access']

        return login_response

    def test_user_registration_assigns_user_role(self):
        """Тест: при регистрации пользователю должна назначаться роль 'user'"""
        url = reverse('register')
        data = {
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'test@example.com',
            'password': 'testpass123',
            'password_confirm': 'testpass123'
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, 201)

        user = User.objects.get(email='test@example.com')

        user_role = UserRole.objects.filter(user=user, role=self.role_user)
        self.assertTrue(user_role.exists())

        if 'token' in response.data:
            self.assertIsNotNone(response.data['token'])

    def test_registration_with_existing_email_fails(self):
        """Тест: регистрация с существующим email должна быть отклонена"""
        User.objects.create_user(
            email='existing@example.com',
            password='pass123',
            first_name='Existing',
            last_name='User'
        )

        url = reverse('register')
        data = {
            'first_name': 'Duplicate',
            'last_name': 'User',
            'email': 'existing@example.com',
            'password': 'testpass123',
            'password_confirm': 'testpass123'
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, 400)

        self.assertIn('email', response.data)
        if 'email' in response.data:
            error_message = str(response.data['email']).lower()
            self.assertTrue(
                'уже существует' in error_message or
                'already exists' in error_message or
                'taken' in error_message
            )

    def test_user_login_success(self):
        """Тест: успешный логин пользователя должен возвращать JWT‑токен"""
        url_register = reverse('register')
        register_data = {
            'first_name': 'Login',
            'last_name': 'Test',
            'email': 'login@test.com',
            'password': 'loginpass123',
            'password_confirm': 'loginpass123'
        }
        register_response = self.client.post(url_register, register_data, format='json')
        self.assertEqual(register_response.status_code, 201)

        url_login = reverse('login')
        login_data = {
            'email': 'login@test.com',
            'password': 'loginpass123'
        }
        login_response = self.client.post(url_login, login_data, format='json')

        self.assertEqual(login_response.status_code, 200)

        self.assertIn('token', login_response.data)
        self.assertIsNotNone(login_response.data['token'])
        self.assertTrue(len(login_response.data['token']) > 0)

    def test_login_with_invalid_credentials_fails(self):
        """Тест: логин с неверными учётными данными должен быть отклонён"""
        url = reverse('login')

        # Сценарий 1: несуществующий email
        data_invalid_email = {
            'email': 'nonexistent@test.com',
            'password': 'wrongpass123'
        }
        response1 = self.client.post(url, data_invalid_email, format='json')

        self.assertEqual(response1.status_code, 401)

        if hasattr(response1, 'data'):
            has_error_field = 'error' in response1.data
            has_detail_field = 'detail' in response1.data

            self.assertTrue(
                has_error_field or has_detail_field,
                "Ответ не содержит ни поля 'error', ни поля 'detail'"
            )

            if has_error_field:
                error_message = str(response1.data['error']).lower()
            else:
                error_message = str(response1.data['detail']).lower()

            expected_keywords = [
                'неверный', 'invalid', 'неаутентифицирован',
                'unauthorized', 'email', 'пользователь не найден',
                'учетные данные', 'учётные данные'
            ]
            self.assertTrue(
                any(keyword in error_message for keyword in expected_keywords),
                f"Сообщение об ошибке не содержит ожидаемых ключевых слов. Получено: '{error_message}'"
            )

        # Сценарий 2: существующий email + неверный пароль
        register_url = reverse('register')
        register_data = {
            'first_name': 'Auth',
            'last_name': 'Test',
            'email': 'auth@test.com',
            'password': 'correctpass123',
            'password_confirm': 'correctpass123'
        }
        self.client.post(register_url, register_data, format='json')

        data_wrong_password = {
            'email': 'auth@test.com',
            'password': 'wrongpassword123'
        }
        response2 = self.client.post(url, data_wrong_password, format='json')

        self.assertEqual(response2.status_code, 401)

        if hasattr(response2, 'data'):
            has_error_field2 = 'error' in response2.data
            has_detail_field2 = 'detail' in response2.data

            self.assertTrue(
                has_error_field2 or has_detail_field2,
                "Ответ не содержит ни поля 'error', ни поля 'detail'"
            )

            if has_error_field2:
                error_message2 = str(response2.data['error']).lower()
            else:
                error_message2 = str(response2.data['detail']).lower()

            self.assertTrue(
                any(keyword in error_message2 for keyword in expected_keywords),
                f"Сообщение об ошибке не содержит ожидаемых ключевых слов. Получено: '{error_message2}'"
            )

    def test_login_with_inactive_user_fails(self):
        """Тест: логин неактивного пользователя должен быть отклонён"""
        inactive_user = User.objects.create_user(
            email='inactive@test.com',
            password='inactivepass',
            first_name='Inactive',
            last_name='User',
            is_active=False
        )

        url = reverse('login')
        data = {
            'email': 'inactive@test.com',
            'password': 'inactivepass'
        }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, 401)

        if hasattr(response, 'data'):
            self.assertTrue(
                'error' in response.data or 'detail' in response.data,
                "Ответ не содержит ни поля 'error', ни поля 'detail'"
            )

            if 'error' in response.data:
                error_message = str(response.data['error']).lower()
            else:
                error_message = str(response.data['detail']).lower()

            expected_keywords = [
                'неактивен', 'inactive', 'неактивный',
                'учетная запись', 'учётная запись', 'активация',
                'неверные учетные данные', 'неверные учётные данные'
            ]
            self.assertTrue(
                any(keyword in error_message for keyword in expected_keywords),
                f"Сообщение об ошибке не содержит ожидаемых ключевых слов. Получено: '{error_message}'"
            )

    def test_jwt_token_structure(self):
        """Тест: JWT‑токен должен содержать корректные claims и иметь срок действия"""
        login_response = self._register_and_login_user('jwt@test.com', 'password123')

        access_token = login_response.data['token']

        decoded = jwt.decode(access_token, options={"verify_signature": False})

        self.assertIn('user_id', decoded)
        self.assertIsNotNone(decoded['user_id'])

        self.assertIn('exp', decoded)
        self.assertGreater(decoded['exp'], time.time())

        self.assertGreater(decoded['exp'], decoded['iat'])

        self.assertIn('iat', decoded)
        self.assertLessEqual(time.time() - decoded['iat'], 60)

        self.assertGreaterEqual(decoded['iat'], time.time() - 60)

        self.assertIn('jti', decoded)
        self.assertIsInstance(decoded['jti'], str)
        self.assertGreater(len(decoded['jti']), 5)

        self.assertIn('token_type', decoded)
        self.assertEqual(decoded['token_type'], 'access')

        print("✓ JWT‑токен содержит корректные claims и имеет срок действия")

    def test_logout_success(self):
        """Тест: успешный логаут пользователя"""
        login_response = self._register_and_login_user(
            'logout@test.com', 'password123'
        )
        access_token = login_response.data['token']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')

        logout_response = self.client.post(reverse('logout'), format='json')
        self.assertEqual(logout_response.status_code, 200)

        self.client.credentials()

        register_response = self.client.post(
            reverse('register'),
            {},
            format='json'
        )

        self.assertIn(register_response.status_code, [400, 401])

        if register_response.status_code == 400:
            self.assertIn('email', register_response.data)
            self.assertIn('password', register_response.data)

        elif register_response.status_code == 401:
            if 'detail' in register_response.data:
                self.assertIn(
                    'authentication credentials were not provided',
                    str(register_response.data['detail']).lower()
                )

    def test_input_validation_on_registration(self):
        """Тест: валидация входных данных при регистрации"""
        invalid_data = {
            'email': 'invalid-email',
            'password': '123',
            'first_name': '',
        }
        response = self.client.post(reverse('register'), invalid_data, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertIn('email', response.data)
        self.assertIn('password', response.data)
