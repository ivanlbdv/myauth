from auth_system.models import (AccessRule, Permission, Resource, Role, User,
                                UserRole)
from auth_system.permissions import HasPermission
from django.contrib.auth.models import AnonymousUser
from django.test import TestCase
from rest_framework.test import APIRequestFactory


class HasPermissionTestCase(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.permission = HasPermission()

        self.user = User.objects.create_user(
            email='test@example.com',
            first_name='Test',
            last_name='User',
            password='testpass123'
        )

        self.role = Role.objects.create(
            name='test_role',
            description='Test Role'
        )

        UserRole.objects.create(user=self.user, role=self.role)

        self.resource = Resource.objects.create(
            name='test_resource',
            description='Test Resource'
        )
        self.permission_obj = Permission.objects.create(
            code='test_permission',
            description='Test Permission'
        )

    def test_has_permission_allowed(self):
        """Тест: доступ разрешен — есть соответствующее правило доступа"""
        AccessRule.objects.create(
            role=self.role,
            resource=self.resource,
            permission=self.permission_obj,
            is_allowed=True
        )

        request = self.factory.get('/api/test/')
        request.user = self.user

        view = type('TestView', (), {
            'kwargs': {
                'resource_code': self.resource.name,
                'permission_code': self.permission_obj.code
            }
        })()

        result = self.permission.has_permission(request, view)
        self.assertTrue(result, f"Ожидалось True, но получено {result}")

    def test_has_permission_denied_by_rule(self):
        """Тест: доступ запрещен — правило доступа явно запрещает"""
        AccessRule.objects.create(
            role=self.role,
            resource=self.resource,
            permission=self.permission_obj,
            is_allowed=False
        )

        request = self.factory.get('/api/test/')
        request.user = self.user

        view = type('TestView', (), {
            'kwargs': {
                'resource_code': self.resource.name,
                'permission_code': self.permission_obj.code
            }
        })()

        result = self.permission.has_permission(request, view)
        self.assertFalse(result, f"Ожидалось False, но получено {result}")

    def test_has_permission_no_rules(self):
        """Тест: доступ запрещен — нет правил доступа для роли"""

        request = self.factory.get('/api/test/')
        request.user = self.user

        view = type('TestView', (), {
            'kwargs': {
                'resource_code': self.resource.name,
                'permission_code': self.permission_obj.code
            }
        })()

        result = self.permission.has_permission(request, view)
        self.assertFalse(result, f"Ожидалось False, но получено {result}")

    def test_has_permission_user_not_authenticated(self):
        """Тест: доступ запрещен — пользователь не авторизован"""

        request = self.factory.get('/api/test/')
        request.user = AnonymousUser()

        view = type('TestView', (), {
            'kwargs': {
                'resource_code': self.resource.name,
                'permission_code': self.permission_obj.code
            }
        })()

        result = self.permission.has_permission(request, view)
        self.assertFalse(result, f"Ожидалось False, но получено {result}")

    def test_has_permission_resource_not_found(self):
        """Тест: доступ запрещен — ресурс с указанным кодом не найден"""
        AccessRule.objects.create(
            role=self.role,
            resource=self.resource,
            permission=self.permission_obj,
            is_allowed=True
        )

        request = self.factory.get('/api/test/')
        request.user = self.user

        view = type('TestView', (), {
            'kwargs': {
                'resource_code': 'nonexistent_resource',
                'permission_code': self.permission_obj.code
            }
        })()

        result = self.permission.has_permission(request, view)
        self.assertFalse(result, f"Ожидалось False, но получено {result}")

    def test_has_permission_permission_not_found(self):
        """Тест: доступ запрещен — разрешение с указанным кодом не найдено"""
        AccessRule.objects.create(
            role=self.role,
            resource=self.resource,
            permission=self.permission_obj,
            is_allowed=True
        )

        request = self.factory.get('/api/test/')
        request.user = self.user

        view = type('TestView', (), {
            'kwargs': {
                'resource_code': self.resource.name,
                'permission_code': 'nonexistent_permission'
            }
        })()

        result = self.permission.has_permission(request, view)
        self.assertFalse(result, f"Ожидалось False, но получено {result}")
