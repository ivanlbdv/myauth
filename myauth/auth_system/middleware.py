import logging

import jwt
from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.http import HttpResponseForbidden
from django.utils import timezone
from rest_framework_simplejwt.backends import TokenBackend
from rest_framework_simplejwt.exceptions import TokenBackendError
from .models import User, UserRole, AccessRule

logger = logging.getLogger(__name__)


class CustomAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def has_permission(self, user, path, method):
        logger.info(f"Checking permissions for user {user.email} on {method} {path}")

        try:
            user_roles = UserRole.objects.filter(user=user)
            if not user_roles.exists():
                logger.warning(f"User {user.email} has no assigned roles")
                return False

            for user_role in user_roles:
                access_rules = AccessRule.objects.filter(
                    role=user_role.role,
                    is_allowed=True
                )
                if access_rules.exists():
                    logger.info(f"User {user.email} has permission via role {user_role.role.name}")
                    return True

            logger.warning(f"No allowed access rules found for user {user.email}")
            return False
        except Exception as e:
            logger.error(f"Error checking permissions: {e}")
            return False

    def __call__(self, request):
        logger.info(f"Middleware triggered. Path: {request.path}, Method: {request.method}")

        exempt_paths = ['/api/auth/register/', '/api/auth/login/', '/api/auth/logout/']

        for path in exempt_paths:
            logger.info(f"Checking: request.path.startswith('{path}') → {request.path.startswith(path)}")

        if any(request.path.startswith(path) for path in exempt_paths):
            logger.info("Path exempted — skipping auth check")
            return self.get_response(request)

        current_user = getattr(request, 'user', None)
        if current_user and current_user.is_authenticated:
            return self.get_response(request)

        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header[7:]
            try:
                backend = TokenBackend(
                    algorithm='HS256',
                    signing_key=settings.SECRET_KEY
                )
                payload = backend.decode(token, verify=True)

                user_id = payload['user_id']
                user = User.objects.get(id=user_id)

                if not self.has_permission(user, request.path, request.method):
                    logger.warning(f"Forbidden: {request.path} — insufficient permissions")
                    return HttpResponseForbidden()

                request.user = user
                logger.info(f"User {user.email} authenticated successfully")
            except (
                jwt.ExpiredSignatureError,
                jwt.InvalidTokenError,
                User.DoesNotExist,
                KeyError,
                TokenBackendError
            ) as e:
                logger.error(f"Authentication failed: {e}")
                request.user = AnonymousUser()
        else:
            request.user = AnonymousUser()

        response = self.get_response(request)
        return response


def verify_jwt_token(token):
    try:
        backend = TokenBackend(
            algorithm='HS256',
            signing_key=settings.SECRET_KEY
        )
        backend.decode(token, verify=True)
        return True
    except Exception:
        return False


def has_permission(self, user, path, method):
    return True
