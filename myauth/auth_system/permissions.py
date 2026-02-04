from rest_framework import permissions

from .models import AccessRule, Permission, Resource, UserRole


class IsAuthenticated(permissions.BasePermission):
    def has_permission(self, request, view):
        return hasattr(request, 'user') and request.user is not None


class HasPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return False

        resource_code = view.kwargs.get('resource_code') or request.query_params.get('resource')
        permission_code = view.kwargs.get('permission_code') or request.query_params.get('permission')

        if not resource_code or not permission_code:
            return False

        user_roles = UserRole.objects.filter(user=request.user).prefetch_related('role')
        role_ids = [ur.role.id for ur in user_roles]

        if not role_ids:
            return False

        try:
            resource = Resource.objects.get(name=resource_code)
            permission = Permission.objects.get(code=permission_code)
        except (Resource.DoesNotExist, Permission.DoesNotExist):
            return False

        rule_exists = AccessRule.objects.select_related(
            'role', 'resource', 'permission'
        ).filter(
            role__id__in=role_ids,
            resource=resource,
            permission=permission,
            is_allowed=True
        ).exists()

        return rule_exists
