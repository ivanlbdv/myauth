#!/usr/bin/env python3
"""
Инициализация базы данных: создание ролей, разрешений, ресурсов и правил доступа.
"""

import os

import django
from auth_system.models import (AccessRule, Permission, Resource, Role, User,
                                UserRole)
from django.conf import settings

# Настройка Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myauth.settings')
django.setup()


def create_initial_data():
    # 1. Создаём роли
    admin_role, _ = Role.objects.get_or_create(
        name='admin',
        description='Администратор системы'
    )
    user_role, _ = Role.objects.get_or_create(
        name='user',
        description='Обычный пользователь'
    )

    # 2. Создаём разрешения
    permissions_data = [
        ('view_posts', 'Просмотр постов'),
        ('create_posts', 'Создание постов'),
        ('edit_posts', 'Редактирование постов'),
        ('delete_posts', 'Удаление постов'),
        ('view_users', 'Просмотр пользователей'),
        ('edit_profile', 'Редактирование профиля'),
        ('manage_roles', 'Управление ролями'),
        ('manage_rules', 'Управление правилами доступа'),
        ('create_comments', 'Создание комментариев'),
    ]

    for code, desc in permissions_data:
        Permission.objects.get_or_create(code=code, description=desc)

    # 3. Создаём ресурсы
    resources_data = [
        ('posts', 'Посты в блоге'),
        ('users', 'Пользователи системы'),
        ('roles', 'Роли'),
        ('access_rules', 'Правила доступа'),
        ('comments', 'Комментарии'),
    ]

    for name, desc in resources_data:
        Resource.objects.get_or_create(name=name, description=desc)

    # 4. Назначаем правила доступа для администратора
    admin_rules = [
        ('posts', 'view_posts'),
        ('posts', 'create_posts'),
        ('posts', 'edit_posts'),
        ('posts', 'delete_posts'),
        ('users', 'view_users'),
        ('users', 'edit_profile'),
        ('roles', 'manage_roles'),
        ('access_rules', 'manage_rules'),
        ('comments', 'createcomments'),
    ]

    for resource_name, perm_code in admin_rules:
        resource = Resource.objects.get(name=resource_name)
        permission = Permission.objects.get(code=perm_code)
        AccessRule.objects.get_or_create(
            role=admin_role,
            resource=resource,
            permission=permission,
            is_allowed=True
        )

    # 5. Правила для обычного пользователя
    user_rules = [
        ('posts', 'view_posts'),
        ('users', 'edit_profile'),
        ('comments', 'createcomments'),
    ]

    for resource_name, perm_code in user_rules:
        resource = Resource.objects.get(name=resource_name)
        permission = Permission.objects.get(code=perm_code)
        AccessRule.objects.get_or_create(
            role=user_role,
            resource=resource,
            permission=permission,
            is_allowed=True
        )

    # 6. Создаём тестового администратора
    if not User.objects.filter(email='admin@example.com').exists():
        admin_user = User(
            first_name='Admin',
            last_name='User',
            email='admin@example.com'
        )
        admin_user.set_password('adminpass123')
        admin_user.save()

        # Назначаем роль admin
        UserRole.objects.create(user=admin_user, role=admin_role)

    print("Инициализация завершена!")


if __name__ == '__main__':
    create_initial_data()
