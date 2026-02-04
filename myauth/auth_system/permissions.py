from rest_framework import permissions

from .models import AccessRule, Permission, Resource, UserRole


class IsAuthenticated(permissions.BasePermission):
    def has_permission(self, request, view):
        return hasattr(request, 'user') and request.user is not None


class HasPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        resource_code = view.kwargs.get('resource_code')
        permission_code = view.kwargs.get('permission_code')

        print(f"[HasPermission] resource_code={resource_code}, permission_code={permission_code}")

        if not resource_code or not permission_code:
            return False

        if not request.user or not request.user.is_authenticated:
            return False

        role_ids = UserRole.objects.filter(user=request.user).values_list('role__id', flat=True)
        if not role_ids:
            return False

        try:
            resource = Resource.objects.get(name=resource_code)
            permission = Permission.objects.get(code=permission_code)
        except (Resource.DoesNotExist, Permission.DoesNotExist):
            return False

        return AccessRule.objects.filter(
            role_id__in=role_ids,
            resource=resource,
            permission=permission,
            is_allowed=True
        ).exists()
