from rest_framework import serializers

from .models import AccessRule, Permission, Resource, Role, User, UserRole


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    password_confirm = serializers.CharField(write_only=True)

    def validate(self, data):
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError("Пароли не совпадают.")
        return data

    def create(self, validated_data):
        user = User(
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            patronymic=validated_data.get('patronymic'),
            email=validated_data['email']
        )
        user.set_password(validated_data['password'])
        user.save()
        role = Role.objects.get(name='user')
        UserRole.objects.create(user=user, role=role)
        return user

    class Meta:
        model = User
        fields = [
            'id',
            'first_name',
            'last_name',
            'patronymic',
            'email',
            'password',
            'password_confirm'
        ]


class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = '__all__'


class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = '__all__'


class ResourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Resource
        fields = '__all__'


class AccessRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = AccessRule
        fields = '__all__'
