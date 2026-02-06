from rest_framework import permissions

from .models import AccessRule, Permission, Resource, UserRole


class IsAuthenticated(permissions.BasePermission):
    def has_permission(self, request, view):
        return hasattr(request, 'user') and request.user is not None


class HasPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if (request.method == 'GET' and
                'user_id' in view.kwargs and
                request.user and
                request.user.id == view.kwargs['user_id']):
            return True

        if not request.user or not request.user.is_authenticated:
            return False

        resource_code = view.kwargs.get('resource_code')
        permission_code = view.kwargs.get('permission_code')

        if not resource_code or not permission_code:
            return False

        if not request.user or not request.user.is_authenticated:
            return False

        try:
            role_ids = UserRole.objects.filter(
                user=request.user
            ).values_list('role__id', flat=True)
        except Exception:
            return False

        if not role_ids:
            return False

        try:
            resource = Resource.objects.get(name=resource_code)
            permission = Permission.objects.get(code=permission_code)
        except Resource.DoesNotExist:
            return False
        except Permission.DoesNotExist:
            return False
        except Exception as e:
            return False

        try:
            has_access = AccessRule.objects.filter(
                role_id__in=role_ids,
                resource=resource,
                permission=permission,
                is_allowed=True
            ).exists()
            print(f"[HasPermission] Access check result: {has_access}")
            return has_access
        except Exception as e:
            print(f"[HasPermission] Error checking access rules: {e}")
            return False
