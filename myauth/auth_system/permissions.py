from rest_framework import permissions

from .models import AccessRule, Permission, Resource, UserRole


class IsAuthenticated(permissions.BasePermission):
    """
    Проверяет, что пользователь аутентифицирован (имеет валидный JWT-токен).
    """
    def has_permission(self, request, view):
        return hasattr(request, 'user') and request.user is not None


class HasPermission(permissions.BasePermission):
    """
    Проверяет, имеет ли пользователь право на действие над ресурсом.

    Аргументы:
    - resource_code: код ресурса (например, 'posts')
    - permission_code: код действия (например, 'view_posts')

    Пример использования:
    permission_classes = [HasPermission('posts', 'view_posts')]
    """

    def __init__(self, resource_code, permission_code):
        self.resource_code = resource_code
        self.permission_code = permission_code

    def has_permission(self, request, view):
        # 1. Проверяем аутентификацию
        if not hasattr(request, 'user') or request.user is None:
            return False

        # 2. Получаем роли пользователя
        user_roles = UserRole.objects.filter(user=request.user)
        role_ids = [ur.role.id for ur in user_roles]

        if not role_ids:
            return False  # Нет ролей → нет доступа

        # 3. Получаем ресурс и право по кодам
        try:
            resource = Resource.objects.get(name=self.resource_code)
            permission = Permission.objects.get(code=self.permission_code)
        except (Resource.DoesNotExist, Permission.DoesNotExist):
            return False  # Ресурс или право не найдены → доступ запрещён

        # 4. Проверяем наличие разрешающего правила доступа
        return AccessRule.objects.filter(
            role__id__in=role_ids,
            resource=resource,
            permission=permission,
            is_allowed=True
        ).exists()
