from unittest.mock import Mock

import pytest
from auth_system.middleware import CustomAuthMiddleware
from auth_system.models import (AccessRule, Permission, Resource, Role, User,
                                UserRole)
from auth_system.permissions import HasPermission


@pytest.fixture
def test_user():
    user = User.objects.create_user(
        email='test@example.com',
        password='testpass123'
    )
    if hasattr(user, 'username'):
        user.username = 'testuser'
        user.save()
    return user


@pytest.fixture
def resource():
    return Resource.objects.create(
        name='test_resource',
        description='Test Resource'
    )


@pytest.fixture
def permission():
    return Permission.objects.create(
        name='read',
        description='Read permission'
    )


@pytest.fixture
def user(role):
    user = User.objects.create_user(
        email='test@example.com',
        first_name='Test',
        last_name='User',
        password='testpass123'
    )
    UserRole.objects.create(user=user, role=role)
    return user


@pytest.fixture
def role():
    return Role.objects.create(
        name='test_role',
        description='Test Role'
    )


@pytest.fixture
def permission_check():
    return HasPermission()


@pytest.fixture
def mock_request():
    request = Mock()
    request.user = Mock(is_authenticated=True)
    return request


@pytest.fixture
def access_rule(role, resource, permission):
    return AccessRule.objects.create(
        role=role,
        resource=resource,
        permission=permission,
        is_allowed=True
    )


@pytest.fixture
def user_role(test_user, role):
    return UserRole.objects.create(
        user=test_user,
        role=role
    )


class TestPermissionTests:
    @pytest.mark.django_db
    def test_has_permission_with_valid_access(test_user, user_role, access_rule):
        middleware = CustomAuthMiddleware(get_response=lambda x: x)
        has_perm = middleware.has_permission(test_user, '/api/posts/', 'GET')
        assert has_perm is True


    @pytest.mark.django_db
    def test_has_permission_without_access_rule(
        self,
        permission_check,
        mock_request
    ):
        view = Mock()
        view.kwargs = {}
        result = permission_check.has_permission(mock_request, view)
        assert result is False
