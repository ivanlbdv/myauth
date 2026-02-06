import logging

from django.contrib.auth import authenticate
from django.http import Http404
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import AccessToken

from .mixins import PermissionContextMixin
from .models import AccessRule, Permission, Role, User
from .permissions import HasPermission, IsAuthenticated
from .serializers import (AccessRuleSerializer, PermissionSerializer,
                          RoleSerializer, UserSerializer)

logger = logging.getLogger(__name__)


class UserDetailView(APIView, PermissionContextMixin):
    permission_classes = [IsAuthenticated, HasPermission]
    resource_code = None
    permission_code = None

    http_method_names = ['get', 'put', 'delete', 'head', 'options', 'trace']

    def get_object(self, user_id):
        return get_object_or_404(User, id=user_id)

    def check_permissions(self, request):
        if request.method == 'GET':
            self.resource_code = 'users'
            self.permission_code = 'view_users'
        elif request.method == 'PUT':
            self.resource_code = 'users'
            self.permission_code = 'edit_users'
        elif request.method == 'DELETE':
            self.resource_code = 'users'
            self.permission_code = 'delete_users'

        self.kwargs['resource_code'] = self.resource_code
        self.kwargs['permission_code'] = self.permission_code

        super().check_permissions(request)

    def check_object_permissions(self, request, obj):
        if request.method == 'GET':
            if request.user == obj:
                return True
            return True

        if request.method == 'PUT':
            if request.user == obj:
                return True
            return True

        if request.method == 'DELETE':
            return True

        return super().check_object_permissions(request, obj)

    def get(self, request, user_id, **kwargs):
        user = self.get_object(user_id)
        serializer = UserSerializer(user)
        return Response(serializer.data, status=200)

    def put(self, request, user_id, **kwargs):
        user = self.get_object(user_id)
        if not self.check_object_permissions(request, user):
            return Response(
                {'error': 'У вас нет прав на редактирование этого пользователя'},
                status=403
            )
        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=200)
        return Response(serializer.errors, status=400)

    def delete(self, request, user_id, **kwargs):
        user = self.get_object(user_id)
        if not self.check_object_permissions(request, user):
            return Response(
                {'error': 'У вас нет прав на удаление этого пользователя'},
                status=403
            )
        user.is_active = False
        user.save()
        return Response(
            {'message': 'Пользователь успешно деактивирован'},
            status=204
        )


class RegisterView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {'message': 'Пользователь зарегистрирован'},
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        logger.info('LoginView: POST request received')
        logger.info(f'Request data: {request.data}')

        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            logger.warning('Missing email or password')
            return Response(
                {'error': 'Требуется указать адрес электронной почты и пароль'},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = authenticate(request, email=email, password=password)
        if user is None:
            logger.warning(f'Authentication failed for email: {email}')
            return Response(
                {'error': 'Неверные учетные данные'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        if not user.is_active:
            logger.warning(f'User {email} is inactive')
            return Response(
                {'error': 'Пользователь неактивен'},
                status=status.HTTP_403_FORBIDDEN
            )

        logger.info(f'User {email} authenticated successfully')

        try:
            token = AccessToken.for_user(user)
            logger.info('JWT token generated successfully')
            return Response({'token': str(token)}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f'Failed to generate JWT: {e}')
            return Response(
                {'error': 'Внутренняя ошибка сервера: не удалось сгенерировать токен'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class LogoutView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        auth_header = request.headers.get('Authorization')

        if not auth_header:
            return Response(
                {'error': 'Заголовок Authorization отсутствует'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        parts = auth_header.split()

        if len(parts) < 2:
            return Response(
                {
                    'detail': 'В заголовке Authorization не хватает токена. Формат: "Bearer <токен>"',
                    'code': 'missing_token'
                },
                status=status.HTTP_401_UNAUTHORIZED
            )

        if parts[0] != 'Bearer':
            return Response(
                {
                    'detail': 'Первый элемент заголовка должен быть "Bearer"',
                    'code': 'invalid_scheme'
                },
                status=status.HTTP_401_UNAUTHORIZED
            )

        token = parts[1]
        if not token:
            return Response(
                {
                    'detail': 'Токен не может быть пустым',
                    'code': 'empty_token'
                },
                status=status.HTTP_401_UNAUTHORIZED
            )

        logger.info('Logout successful')
        return Response(
            {'detail': 'Пользователь успешно вышел из системы'},
            status=status.HTTP_200_OK
        )


class UserUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise Http404

        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            if 'password' in request.data:
                user.set_password(request.data['password'])
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, user_id):
        if request.method != 'DELETE':
            return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise Http404

        user.is_active = False
        user.save()
        return Response(
            {'message': 'Аккаунт деактивирован'},
            status=status.HTTP_204_NO_CONTENT
        )


class RoleListCreateView(APIView, PermissionContextMixin):
    permission_classes = [IsAuthenticated, HasPermission]
    resource_code = 'roles'
    permission_code = None

    def check_permissions(self, request):
        if request.method == 'GET':
            self.permission_code = 'view_roles'
        elif request.method == 'POST':
            self.permission_code = 'create_roles'

        self.kwargs['resource_code'] = self.resource_code
        self.kwargs['permission_code'] = self.permission_code

        super().check_permissions(request)

    def get(self, request, **kwargs):
        roles = Role.objects.all()
        serializer = RoleSerializer(roles, many=True)
        return Response(serializer.data, status=200)

    def post(self, request, **kwargs):
        serializer = RoleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)


class RoleDetailView(APIView, PermissionContextMixin):
    permission_classes = [IsAuthenticated, HasPermission]
    resource_code = 'roles'
    permission_code = None

    def check_permissions(self, request):
        if request.method == 'GET':
            self.permission_code = 'view_roles'
        elif request.method == 'PUT':
            self.permission_code = 'edit_roles'
        elif request.method == 'DELETE':
            self.permission_code = 'delete_roles'

        self.kwargs['resource_code'] = self.resource_code
        self.kwargs['permission_code'] = self.permission_code

        super().check_permissions(request)

    def check_object_permissions(self, request, obj):
        return True

    def get(self, request, role_id, **kwargs):
        role = self.get_object(role_id)
        if not self.check_object_permissions(request, role):
            return Response(
                {'error': 'У вас нет прав на просмотр этой роли'},
                status=403
            )
        serializer = RoleSerializer(role)
        return Response(serializer.data, status=200)

    def put(self, request, role_id, **kwargs):
        role = self.get_object(role_id)
        if not self.check_object_permissions(request, role):
            return Response(
                {'error': 'У вас нет прав на редактирование этой роли'},
                status=403
            )
        serializer = RoleSerializer(role, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=200)
        return Response(serializer.errors, status=400)

    def delete(self, request, role_id, **kwargs):
        role = self.get_object(role_id)
        if not self.check_object_permissions(request, role):
            return Response(
                {'error': 'У вас нет прав на удаление этой роли'},
                status=403
            )
        role.delete()
        return Response({'message': 'Роль успешно удалена'}, status=204)

    def get_object(self, role_id):
        return get_object_or_404(Role, id=role_id)


class PermissionListView(APIView, PermissionContextMixin):
    permission_classes = [IsAuthenticated, HasPermission]
    resource_code = 'permissions'
    permission_code = 'view_permissions'

    def check_permissions(self, request):
        if request.method == 'GET':
            self.permission_code = 'view_permissions'
        elif request.method == 'POST':
            self.permission_code = 'create_permissions'

        self.kwargs['resource_code'] = self.resource_code
        self.kwargs['permission_code'] = self.permission_code

        super().check_permissions(request)

    def get(self, request, **kwargs):
        self.kwargs['resource_code'] = 'permissions'
        self.kwargs['permission_code'] = 'view_permissions'
        permissions = Permission.objects.all()
        serializer = PermissionSerializer(permissions, many=True)
        return Response(serializer.data)


class AccessRuleCreateView(APIView, PermissionContextMixin):
    permission_classes = [IsAuthenticated, HasPermission]
    resource_code = 'access_rules'
    permission_code = 'create_access_rules'

    def check_permissions(self, request):
        if request.method == 'POST':
            self.permission_code = 'create_access_rules'
        elif request.method == 'GET':
            self.permission_code = 'view_access_rules'

        self.kwargs['resource_code'] = self.resource_code
        self.kwargs['permission_code'] = self.permission_code

        super().check_permissions(request)

    def post(self, request, *args, **kwargs):
        self.kwargs['resource_code'] = 'access_rules'
        self.kwargs['permission_code'] = 'manage_rules'
        serializer = AccessRuleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AccessRuleDetailView(APIView, PermissionContextMixin):
    permission_classes = [IsAuthenticated, HasPermission]
    resource_code = 'access_rules'
    permission_code = 'view_access_rules'

    def check_permissions(self, request):
        if request.method == 'GET':
            self.permission_code = 'view_access_rules'
        elif request.method == 'PUT':
            self.permission_code = 'edit_access_rules'
        elif request.method == 'DELETE':
            self.permission_code = 'delete_access_rules'

        self.kwargs['resource_code'] = self.resource_code
        self.kwargs['permission_code'] = self.permission_code

        super().check_permissions(request)

    def get(self, request, rule_id, **kwargs):
        self.kwargs['resource_code'] = 'access_rules'
        self.kwargs['permission_code'] = 'manage_rules'
        try:
            rule = AccessRule.objects.get(id=rule_id)
            serializer = AccessRuleSerializer(rule)
            return Response(serializer.data)
        except AccessRule.DoesNotExist:
            return Response(
                {'error': 'Правило не найдено'},
                status=status.HTTP_404_NOT_FOUND
            )

    def put(self, request, rule_id, **kwargs):
        self.kwargs['resource_code'] = 'access_rules'
        self.kwargs['permission_code'] = 'manage_rules'
        try:
            rule = AccessRule.objects.get(id=rule_id)
        except AccessRule.DoesNotExist:
            return Response(
                {'error': 'Правило не найдено'},
                status=status.HTTP_404_NOT_FOUND
            )

        serializer = AccessRuleSerializer(
            rule,
            data=request.data,
            partial=True
        )
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, rule_id, **kwargs):
        self.kwargs['resource_code'] = 'access_rules'
        self.kwargs['permission_code'] = 'manage_rules'
        try:
            rule = AccessRule.objects.get(id=rule_id)
            rule.delete()
            return Response(
                {'message': 'Правило удалено'},
                status=status.HTTP_204_NO_CONTENT
            )
        except AccessRule.DoesNotExist:
            return Response(
                {'error': 'Правило не найдено'},
                status=status.HTTP_404_NOT_FOUND
            )
