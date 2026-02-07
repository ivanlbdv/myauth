from datetime import timedelta

import bcrypt
import jwt
from django.conf import settings
from django.contrib.auth.base_user import BaseUserManager
from django.core.management import CommandError
from django.db import models
from django.utils import timezone


class CustomUserManager(BaseUserManager):
    def get_by_natural_key(self, email):
        return self.get(email=email)

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email обязателен')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if password is None:
            try:
                from getpass import getpass
                password = getpass('Password: ')
            except ImportError:
                raise CommandError('Невозможно запросить пароль')

        return self.create_user(email, password, **extra_fields)


class User(models.Model):
    first_name = models.CharField(max_length=50, verbose_name='Имя')
    last_name = models.CharField(max_length=50, verbose_name='Фамилия')
    patronymic = models.CharField(max_length=50, blank=True, null=True, verbose_name='Отчество')
    email = models.EmailField(unique=True, verbose_name='Email')
    password_hash = models.CharField(max_length=100, verbose_name='Хэш пароля')
    is_active = models.BooleanField(default=True, verbose_name='Активный')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='Дата создания')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='Дата обновления')
    is_staff = models.BooleanField(default=False, verbose_name='Персонал')
    is_superuser = models.BooleanField(default=False, verbose_name='Суперпользователь')

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    objects = CustomUserManager()

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def has_perm(self, perm, obj=None):
        return self.is_superuser

    def has_module_perms(self, app_label):
        return self.is_superuser

    def get_all_permissions(self, obj=None):
        return set()

    def set_password(self, password):
        if password is None:
            raise ValueError('Пароль не может быть None')
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode(), salt).decode()

    def check_password(self, password):
        return bcrypt.checkpw(
            password.encode(),
            self.password_hash.encode()
        )

    def generate_jwt(self):
        payload = {
            'user_id': self.id,
            'email': self.email,
            'exp': timezone.now() + timedelta(hours=24),
            'iat': timezone.now(),
        }
        return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

    def __str__(self):
        return self.email

    class Meta:
        verbose_name = 'Пользователь'
        verbose_name_plural = 'Пользователи'


class Role(models.Model):
    name = models.CharField(max_length=50, unique=True, verbose_name='Имя')
    description = models.TextField(blank=True, null=True, verbose_name='Описание')

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = 'Роль'
        verbose_name_plural = 'Роли'


class Resource(models.Model):
    name = models.CharField(max_length=100, unique=True, verbose_name='Имя')
    description = models.TextField(blank=True, null=True, verbose_name='Описание')

    def __str__(self):
        return self.description

    class Meta:
        verbose_name = 'Ресурс'
        verbose_name_plural = 'Ресурсы'


class Permission(models.Model):
    code = models.CharField(max_length=50, unique=True, verbose_name='Код')
    description = models.TextField(blank=True, null=True, verbose_name='Описание')

    def __str__(self):
        return f'{self.description} ({self.code})'

    class Meta:
        verbose_name = 'Разрешение'
        verbose_name_plural = 'Разрешения'


class UserRole(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name='Пользователь')
    role = models.ForeignKey(Role, on_delete=models.CASCADE, verbose_name='Роль')

    def __str__(self):
        return f'{self.user.email} → {self.role.name}'

    class Meta:
        verbose_name = 'Пользовательская роль'
        verbose_name_plural = 'Пользовательские роли'


class AccessRule(models.Model):
    role = models.ForeignKey(Role, on_delete=models.CASCADE, verbose_name='Роль')
    resource = models.ForeignKey(Resource, on_delete=models.CASCADE, verbose_name='Ресурс')
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE, verbose_name='Разрешение')
    is_allowed = models.BooleanField(default=True, verbose_name='Разрешено')

    def __str__(self):
        return f"{self.role.description} → {self.resource.description}: {self.permission.description} ({'разрешено' if self.is_allowed else 'запрещено'})"

    class Meta:
        unique_together = ('role', 'resource', 'permission')
        verbose_name = 'Правило доступа'
        verbose_name_plural = 'Правила доступа'
