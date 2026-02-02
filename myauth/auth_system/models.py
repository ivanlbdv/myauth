from datetime import datetime, timedelta

import bcrypt
import jwt
from django.conf import settings
from django.db import models


class User(models.Model):
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    patronymic = models.CharField(max_length=50, blank=True, null=True)
    email = models.EmailField(unique=True)
    password_hash = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def set_password(self, password):
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
            'exp': datetime.utcnow() + timedelta(hours=24)
        }
        return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')


class Role(models.Model):
    name = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True, null=True)


class Permission(models.Model):
    code = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True, null=True)


class UserRole(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)


class Resource(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)


class AccessRule(models.Model):
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    resource = models.ForeignKey(Resource, on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)
    is_allowed = models.BooleanField(default=True)

    class Meta:
        unique_together = ('role', 'resource', 'permission')
