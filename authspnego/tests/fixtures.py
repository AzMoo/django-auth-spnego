import pytest


@pytest.fixture
def client_request():
    from django.test import RequestFactory
    from django.contrib.auth.models import AnonymousUser
    from django.contrib.sessions.backends.db import SessionStore

    factory = RequestFactory()
    request = factory.get('/')
    request.user = AnonymousUser()
    request.session = SessionStore()

    return request
