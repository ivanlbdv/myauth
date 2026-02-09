import jwt
from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.utils import timezone

from .models import User


class CustomAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        import logging
        logger = logging.getLogger(__name__)
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
                payload = jwt.decode(
                    token,
                    settings.SECRET_KEY,
                    algorithms=['HS256'],
                    options={'verify_iat': True, 'verify_nbf': True}
                )
                if payload['exp'] < timezone.now().timestamp():
                    request.user = AnonymousUser()
                    return self.get_response(request)

                user_id = payload['user_id']
                request.user = User.objects.get(id=user_id)
            except (
                jwt.ExpiredSignatureError,
                jwt.InvalidTokenError,
                User.DoesNotExist,
                KeyError
            ):
                request.user = AnonymousUser()
        else:
            request.user = AnonymousUser()

        response = self.get_response(request)
        return response
