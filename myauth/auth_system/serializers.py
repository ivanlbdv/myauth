from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from rest_framework import serializers

from .models import AccessRule, Permission, Resource, Role, User, UserRole


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False)
    password_confirm = serializers.CharField(write_only=True, required=False)

    def validate(self, data):
        password = data.get('password')
        password_confirm = data.get('password_confirm')

        if password and password_confirm:
            if password != password_confirm:
                raise serializers.ValidationError({
                    'password_confirm': 'Пароли не совпадают.'
                })
        elif password and not password_confirm:
            raise serializers.ValidationError({
                'password_confirm': 'Пожалуйста, подтвердите пароль.'
            })
        elif not password and password_confirm:
            raise serializers.ValidationError({
                'password': 'Пожалуйста, введите пароль.'
            })

        email = data.get('email')
        if email:
            try:
                validate_email(email)
            except ValidationError:
                raise serializers.ValidationError(
                    {'email': 'Некорректный формат email.'}
                )

            if not self.instance or self.instance.email != email:
                if User.objects.filter(email=email).exists():
                    raise serializers.ValidationError({
                        'email': 'Email уже зарегистрирован.'
                    })

        return data

    def create(self, validated_data):
        validated_data.pop('password_confirm', None)

        user = User(
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            patronymic=validated_data.get('patronymic'),
            email=validated_data['email']
        )
        user.set_password(validated_data['password'])
        user.save()

        role_name = 'user'
        try:
            role = Role.objects.get(name=role_name)
            UserRole.objects.create(user=user, role=role)
        except Role.DoesNotExist:
            raise ValidationError(f'Роль {role_name} не найдена.')

        return user

    def update(self, instance, validated_data):
        validated_data.pop('password_confirm', None)

        password = validated_data.get('password')
        if password:
            instance.set_password(password)

        return super().update(instance, validated_data)

    class Meta:
        model = User
        fields = [
            'first_name',
            'last_name',
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
