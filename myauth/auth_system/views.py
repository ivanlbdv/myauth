from django.contrib.auth import authenticate
from django.http import Http404
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import AccessRule, Permission, Role, User
from .permissions import HasPermission, IsAuthenticated
from .serializers import (AccessRuleSerializer, PermissionSerializer,
                          RoleSerializer, UserSerializer)


class UserDetailView(APIView):
    permission_classes = [IsAuthenticated, HasPermission]

    def get_object(self, user_id):
        return get_object_or_404(User, id=user_id)

    def check_object_permissions(self, request, obj):
        if request.method == 'PUT':
            if request.user == obj:
                return True
            else:
                return HasPermission().has_permission(
                    request,
                    self,
                    resource_code='users',
                    permission_code='edit_users'
                )

        elif request.method == 'DELETE':
            return HasPermission().has_permission(
                request,
                self,
                resource_code='users',
                permission_code='delete_users'
            )

        return False

    def put(self, request, user_id):
        user = self.get_object(user_id)

        if not self.check_object_permissions(request, user):
            return Response(
                {'error': 'У вас нет прав на редактирование этого пользователя'},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, user_id):
        user = self.get_object(user_id)

        if not self.check_object_permissions(request, user):
            return Response(
                {'error': 'У вас нет прав на удаление этого пользователя'},
                status=status.HTTP_403_FORBIDDEN
            )

        user.is_active = False
        user.save()
        return Response(
            {'message': 'Пользователь успешно деактивирован'},
            status=status.HTTP_204_NO_CONTENT
        )


class RegisterView(APIView):
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
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response(
                {'error': 'Email и пароль обязательны'},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = authenticate(email=email, password=password)
        if not user:
            return Response(
                {'error': 'Неверные учетные данные'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        if not user.is_active:
            return Response(
                {'error': 'Аккаунт неактивен'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        token = user.generate_jwt()
        return Response({'token': token}, status=status.HTTP_200_OK)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        return Response(
            {'message': 'Выход выполнен'},
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


class RoleListCreateView(APIView):
    permission_classes = [IsAuthenticated, HasPermission]

    def get(self, request):
        self.kwargs['resource_code'] = 'roles'
        self.kwargs['permission_code'] = 'manage_roles'
        roles = Role.objects.all()
        serializer = RoleSerializer(roles, many=True)
        return Response(serializer.data)

    def post(self, request):
        self.kwargs['resource_code'] = 'roles'
        self.kwargs['permission_code'] = 'manage_roles'
        serializer = RoleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RoleDetailView(APIView):
    permission_classes = [IsAuthenticated, HasPermission]

    def get(self, request, role_id):
        self.kwargs['resource_code'] = 'roles'
        self.kwargs['permission_code'] = 'manage_roles'
        try:
            role = Role.objects.get(id=role_id)
            serializer = RoleSerializer(role)
            return Response(serializer.data)
        except Role.DoesNotExist:
            return Response(
                {'error': 'Роль не найдена'},
                status=status.HTTP_404_NOT_FOUND
            )

    def put(self, request, role_id):
        self.kwargs['resource_code'] = 'roles'
        self.kwargs['permission_code'] = 'manage_roles'
        try:
            role = Role.objects.get(id=role_id)
        except Role.DoesNotExist:
            return Response(
                {'error': 'Роль не найдена'},
                status=status.HTTP_404_NOT_FOUND
            )

        serializer = RoleSerializer(role, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, role_id):
        self.kwargs['resource_code'] = 'roles'
        self.kwargs['permission_code'] = 'manage_roles'
        try:
            role = Role.objects.get(id=role_id)
            role.delete()
            return Response(
                {'message': 'Роль удалена'},
                status=status.HTTP_204_NO_CONTENT
            )
        except Role.DoesNotExist:
            return Response(
                {'error': 'Роль не найдена'},
                status=status.HTTP_404_NOT_FOUND
            )


class PermissionListView(APIView):
    permission_classes = [IsAuthenticated, HasPermission]

    def get(self, request):
        self.kwargs['resource_code'] = 'permissions'
        self.kwargs['permission_code'] = 'view_permissions'
        permissions = Permission.objects.all()
        serializer = PermissionSerializer(permissions, many=True)
        return Response(serializer.data)


class AccessRuleCreateView(APIView):
    permission_classes = [IsAuthenticated, HasPermission]

    def post(self, request):
        self.kwargs['resource_code'] = 'access_rules'
        self.kwargs['permission_code'] = 'manage_rules'
        serializer = AccessRuleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AccessRuleDetailView(APIView):
    permission_classes = [IsAuthenticated, HasPermission]

    def get(self, request, rule_id):
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

    def put(self, request, rule_id):
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

    def delete(self, request, rule_id):
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
