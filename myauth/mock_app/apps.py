from django.apps import AppConfig


class MockAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'mock_app'
