import os

import django
from django.conf import settings

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myauth.settings')
django.setup()

from auth_system.models import (AccessRule, Permission, Resource, Role, User,
                                UserRole)


def create_initial_data():
    admin_role, _ = Role.objects.get_or_create(
        name='admin',
        description='Администратор системы'
    )
    user_role, _ = Role.objects.get_or_create(
        name='user',
        description='Обычный пользователь'
    )

    permissions_data = [
        ('view_posts', 'Просмотр постов'),
        ('create_posts', 'Создание постов'),
        ('edit_posts', 'Редактирование постов'),
        ('delete_posts', 'Удаление постов'),
        ('view_users', 'Просмотр пользователей'),
        ('delete_users', 'Деактивация пользователей'),
        ('edit_users', 'Редактирование пользователей'),
        ('edit_profile', 'Редактирование профиля'),
        ('manage_roles', 'Управление ролями'),
        ('manage_rules', 'Управление правилами доступа'),
        ('create_comments', 'Создание комментариев'),
        ('views_comments', 'Просмотр комментариев'),
        ('edit_comments', 'Редактирование комментариев'),
        ('delete_comments', 'Удаление комментариев'),
        ('view_roles', 'Просмотр ролей'),
        ('create_roles', 'Создание ролей'),
        ('edit_roles', 'Редактирование ролей'),
        ('delete_roles', 'Удаление ролей'),
        ('view_permissions', 'Просмотр разрешений'),
        ('create_access_rules', 'Создание правил доступа'),
        ('view_access_rules', 'Просмотр правил доступа'),
        ('edit_access_rules', 'Редактирование правил доступа'),
        ('delete_access_rules', 'Удаление правил доступа'),
    ]

    for code, desc in permissions_data:
        Permission.objects.get_or_create(code=code, description=desc)

    resources_data = [
        ('posts', 'Посты в блоге'),
        ('users', 'Пользователи системы'),
        ('roles', 'Роли'),
        ('access_rules', 'Правила доступа'),
        ('comments', 'Комментарии'),
        ('permissions', 'Разрешения'),
    ]

    for name, desc in resources_data:
        Resource.objects.get_or_create(name=name, description=desc)

    admin_rules = [
        ('posts', 'view_posts'),
        ('posts', 'create_posts'),
        ('posts', 'edit_posts'),
        ('posts', 'delete_posts'),
        ('users', 'view_users'),
        ('users', 'edit_profile'),
        ('users', 'delete_users'),
        ('users', 'edit_users'),
        ('roles', 'manage_roles'),
        ('roles', 'view_roles'),
        ('roles', 'create_roles'),
        ('roles', 'edit_roles'),
        ('roles', 'delete_roles'),
        ('access_rules', 'manage_rules'),
        ('comments', 'create_comments'),
        ('comments', 'view_comments'),
        ('comments', 'edit_comments'),
        ('comments', 'delete_comments'),
        ('permissions', 'view_permissions'),
        ('access_rules', 'create_access_rules'),
        ('access_rules', 'view_access_rules'),
        ('access_rules', 'edit_access_rules'),
        ('access_rules', 'delete_access_rules'),
    ]

    for resource_name, perm_code in admin_rules:
        try:
            resource = Resource.objects.get(name=resource_name)
            permission = Permission.objects.get(code=perm_code)
            AccessRule.objects.get_or_create(
                role=admin_role,
                resource=resource,
                permission=permission,
                is_allowed=True
            )
        except (Resource.DoesNotExist, Permission.DoesNotExist) as e:
            print(f'Ошибка при создании правила для админа: {e}')

    user_rules = [
        ('posts', 'create_posts'),
        ('posts', 'edit_posts'),
        ('posts', 'delete_posts'),
        ('posts', 'view_posts'),
        ('users', 'edit_profile'),
        ('users', 'edit_users'),
        ('comments', 'create_comments'),
        ('comments', 'view_comments'),
        ('comments', 'edit_comments'),
        ('comments', 'delete_comments'),
    ]

    for resource_name, perm_code in user_rules:
        try:
            resource = Resource.objects.get(name=resource_name)
            permission = Permission.objects.get(code=perm_code)
            AccessRule.objects.get_or_create(
                role=user_role,
                resource=resource,
                permission=permission,
                is_allowed=True
            )
        except (Resource.DoesNotExist, Permission.DoesNotExist) as e:
            print(f'Ошибка при создании правила для пользователя: {e}')

    if not User.objects.filter(email='admin@example.com').exists():
        admin_user = User(
            first_name='Admin',
            last_name='User',
            email='admin@example.com'
        )
        admin_user.set_password('adminpass123')
        admin_user.save()

        try:
            UserRole.objects.create(user=admin_user, role=admin_role)
        except Exception as e:
            print(f'Ошибка при назначении роли админу: {e}')

    print('Инициализация завершена!')


if __name__ == '__main__':
    create_initial_data()
