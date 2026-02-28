import pytest
from auth_system.models import Role, UserRole
from auth_system.serializers import UserSerializer

@pytest.fixture
def valid_user_data():
    role, _ = Role.objects.get_or_create(name='user')  # Исправлен синтаксис
    return {
        'first_name': 'John',
        'last_name': 'Doe',
        'email': 'john@example.com',
        'password': 'securepass123',
        'password_confirm': 'securepass123'
    }

class TestUserSerializer:
    @pytest.mark.django_db
    def test_create_user_success(self, valid_user_data):
        serializer = UserSerializer(data=valid_user_data)
        assert serializer.is_valid(), serializer.errors
        user = serializer.save()
        assert user.email == valid_user_data['email']
        assert user.first_name == valid_user_data['first_name']
        assert user.last_name == valid_user_data['last_name']
        # Проверяем, что пароль хеширован
        assert user.check_password(valid_user_data['password'])

    @pytest.mark.django_db
    def test_invalid_email_format(self, valid_user_data):
        valid_user_data['email'] = 'invalid-email'
        serializer = UserSerializer(data=valid_user_data)
        assert not serializer.is_valid()
        assert 'email' in serializer.errors
        assert 'Введите правильный адрес электронной почты.' in str(serializer.errors['email'])

    @pytest.mark.django_db
    def test_password_required_on_creation(self, valid_user_data):
        del valid_user_data['password']
        serializer = UserSerializer(data=valid_user_data)
        assert not serializer.is_valid()
        assert 'password' in serializer.errors
        assert 'Обязательное поле.' in str(serializer.errors['password'])

    @pytest.mark.django_db
    def test_password_confirmation_mismatch(self, valid_user_data):
        valid_user_data['password_confirm'] = 'different_password'
        serializer = UserSerializer(data=valid_user_data)
        assert not serializer.is_valid()
        assert 'password_confirm' in serializer.errors
        assert 'Пароли не совпадают.' in str(serializer.errors['password_confirm'])

    @pytest.mark.django_db
    def test_missing_required_fields(self):
        # Пустые данные — проверяем все обязательные поля
        data = {}
        serializer = UserSerializer(data=data)
        assert not serializer.is_valid()
        required_fields = ['first_name', 'last_name', 'email', 'password', 'password_confirm']
        for field in required_fields:
            assert field in serializer.errors, f"Поле {field} должно быть обязательным"
            if field == 'password_confirm':
                assert 'Обязательное поле.' in str(serializer.errors[field])

    @pytest.mark.django_db
    def test_duplicate_email(self, valid_user_data):
        # Сначала создаём пользователя с этим email
        serializer1 = UserSerializer(data=valid_user_data)
        assert serializer1.is_valid()
        serializer1.save()

        # Пытаемся создать второго пользователя с тем же email
        serializer2 = UserSerializer(data=valid_user_data)
        assert not serializer2.is_valid()
        assert 'email' in serializer2.errors
        assert 'пользователь с таким email уже существует.' in str(serializer2.errors['email']).lower()


    @pytest.mark.django_db
    def test_short_password(self, valid_user_data):
        valid_user_data['password'] = 'short'
        valid_user_data['password_confirm'] = 'short'
        serializer = UserSerializer(data=valid_user_data)
        assert not serializer.is_valid()
        assert 'password' in serializer.errors
        # Сообщение может отличаться в зависимости от валидаторов
        assert 'Пароль должен быть не менее 8 символов.' in str(serializer.errors['password'])

    @pytest.mark.django_db
    def test_valid_data_with_role(self, valid_user_data):
        role, _ = Role.objects.get_or_create(name='user')
        valid_user_data['role_id'] = role.id
        serializer = UserSerializer(data=valid_user_data)
        assert serializer.is_valid(), serializer.errors
        user = serializer.save()
        # Предполагаем, что сериализатор назначает роль пользователю
        assert UserRole.objects.filter(user=user, role=role).exists()
