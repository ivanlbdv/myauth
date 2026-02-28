import pytest
from auth_system.models import (AccessRule, Permission, Resource, Role, User,
                                UserRole)


@pytest.fixture
def role():
    return Role.objects.create(name='user', description='Обычная роль')

@pytest.fixture
def resource():
    return Resource.objects.create(name='test_resource', description='Тестовый ресурс')

@pytest.fixture
def permission():
    return Permission.objects.create(code='read', description='Чтение')

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

class TestUserModel:
    @pytest.mark.django_db
    def test_user_creation(self, user):
        assert user.email == 'test@example.com'
        assert user.first_name == 'Test'
        assert user.check_password('testpass123')

    @pytest.mark.django_db
    def test_jwt_generation(self, user):
        token = user.generate_jwt()
        assert isinstance(token, str)
        assert len(token) > 0

class TestRoleModel:
    @pytest.mark.django_db
    def test_role_creation(self, role):
        assert role.name == 'user'
        assert 'user' in str(role)

class TestResourceModel:
    @pytest.mark.django_db
    def test_resource_creation(self, resource):
        assert resource.name == 'test_resource'
        assert 'Тестовый ресурс' in str(resource)

class TestPermissionModel:
    @pytest.mark.django_db
    def test_permission_creation(self, permission):
        assert permission.code == 'read'
        assert 'Чтение' in str(permission)

class TestUserRoleModel:
    @pytest.mark.django_db
    def test_user_role_assignment(self, user, role):
        user_role = UserRole.objects.create(user=user, role=role)
        assert user_role.user == user
        assert user_role.role == role
        assert f'{user.email} → {role.name}' in str(user_role)

class TestAccessRuleModel:
    @pytest.mark.django_db
    def test_access_rule_creation(self, role, resource, permission):
        access_rule = AccessRule.objects.create(
            role=role,
            resource=resource,
            permission=permission,
            is_allowed=True
        )
        assert access_rule.is_allowed is True
        assert 'разрешено' in str(access_rule)
