from django.contrib import admin
from .models import AccessRule, Permission, Resource, Role, User, UserRole


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'description')
    search_fields = ('name', 'description')
    ordering = ('name',)


@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = ('id', 'code', 'description')
    search_fields = ('code', 'description')
    ordering = ('code',)


@admin.register(Resource)
class ResourceAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'description')
    search_fields = ('name', 'description')
    ordering = ('name',)


@admin.register(AccessRule)
class AccessRuleAdmin(admin.ModelAdmin):
    list_display = ('id', 'role', 'resource', 'permission', 'is_allowed')
    list_filter = ('is_allowed', 'role', 'resource', 'permission')
    search_fields = ('role__name', 'resource__name', 'permission__code')
    raw_id_fields = ('role', 'resource', 'permission')
    ordering = ('role__name', 'resource__name')


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'email',
        'first_name',
        'last_name',
        'is_active',
        'is_staff',
        'is_superuser',
        'created_at',
        'updated_at'
    )
    list_filter = (
        'is_active',
        'is_staff',
        'is_superuser',
        'created_at',
        'updated_at'
    )
    search_fields = ('email', 'first_name', 'last_name')
    readonly_fields = ('created_at', 'updated_at')
    fieldsets = (
        (None, {
            'fields': ('email', 'password_hash')
        }),
        ('Персональная информация', {
            'fields': ('first_name', 'last_name', 'patronymic')
        }),
        ('Права доступа', {
            'fields': ('is_active', 'is_staff', 'is_superuser'),
            'classes': ('collapse',)
        }),
        ('Даты', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    ordering = ('email',)

    def get_readonly_fields(self, request, obj=None):
        if obj:
            return self.readonly_fields + ('password_hash',)
        return self.readonly_fields


@admin.register(UserRole)
class UserRoleAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'role')
    list_filter = ('role',)
    search_fields = (
        'user__email',
        'user__first_name',
        'user__last_name',
        'role__name'
    )
    raw_id_fields = ('user', 'role')
    ordering = ('user__email', 'role__name')
