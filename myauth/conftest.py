import os

import django
import pytest
from django.conf import settings


def pytest_configure():
    if not settings.configured:
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myauth.settings')
        django.setup()


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    pass
