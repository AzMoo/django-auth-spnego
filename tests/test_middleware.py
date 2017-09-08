from authspnego.middleware import AuthSpnegoMiddleware
from django.http import HttpResponse
from fixtures import *  # noqa


def get_response():
    return HttpResponse('myresponse')


def test_missing_authentication_returns_valid_401(client_request):
    """
    When we make a request without an authentication header
    we should get a response with status code 401 and 2
    WWW-Authenticate headers specifying Negotiate and
    Basic authentication types are supported.
    """
    realm_string = 'realm="SPNEGOREALM.AUTHTEST.STUFF"'
    has_negotiate = False
    has_basic = False
    has_basic_realm = False

    response = AuthSpnegoMiddleware(get_response)(client_request)

    for header in response.items():
        if header[0] == 'WWW-Authenticate':
            if header[1] == 'Negotiate':
                has_negotiate = True
            elif header[1].startswith('Basic'):
                has_basic = True
                if header[1].split()[1] == realm_string:
                    has_basic_realm = True
    assert response.status_code == 401
    assert has_negotiate is True
    assert has_basic is True
    assert has_basic_realm is True
