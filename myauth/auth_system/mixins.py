class PermissionContextMixin:
    def get_permissions(self):
        print(f"[Mixin] get_permissions: resource_code={self.resource_code}, permission_code={self.permission_code}")
        if hasattr(self, 'resource_code'):
            self.kwargs['resource_code'] = self.resource_code
        if hasattr(self, 'permission_code'):
            self.kwargs['permission_code'] = self.permission_code
        return super().get_permissions()
