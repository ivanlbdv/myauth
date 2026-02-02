from rest_framework import permissions

from .models import AccessRule, Permission, Resource, UserRole


class IsAuthenticated(permissions.BasePermission):
    def has_permission(self, request, view):
        return hasattr(request, 'user') and request.user is not None


class HasPermission(permissions.BasePermission):
    def __init__(self, resource_code, permission_code):
        self.resource_code = resource_code
        self.permission_code = permission_code

    def has_permission(self, request, view):
        if not hasattr(request, 'user') or request.user is None:
            return False

        user_roles = UserRole.objects.filter(user=request.user)
        role_ids = [ur.role.id for ur in user_roles]

        if not role_ids:
            return False

        try:
            resource = Resource.objects.get(name=self.resource_code)
            permission = Permission.objects.get(code=self.permission_code)
        except (Resource.DoesNotExist, Permission.DoesNotExist):
            return False

        return AccessRule.objects.filter(
            role__id__in=role_ids,
            resource=resource,
            permission=permission,
            is_allowed=True
        ).exists()
