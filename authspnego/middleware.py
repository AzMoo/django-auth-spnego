import base64
import logging
import kerberos

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http.response import HttpResponse
from .exceptions import NotAuthorized


class SpnegoHttpUnauthorized(HttpResponse):
    status_code = 401

    def items(self, *args, **kwargs):
        yield from super().items(*args, **kwargs)
        yield ('WWW-Authenticate', 'Negotiate')
        yield ('WWW-Authenticate', 'Basic realm="{}"'.format(settings.SPNEGO_REALM))


class AuthSpnegoMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def auth_basic(self, auth_header):
        auth_decoded = base64.decodestring(auth_header.encode('utf8')).decode()
        username, password = auth_decoded.split(':', maxsplit=1)
        kerberos.checkPassword(
            username, password, 
            kerberos.getServerPrincipalDetails('HTTP', settings.SPNEGO_HOSTNAME),
            settings.SPNEGO_REALM
        )
        return username

    def auth_negotiate(self, auth_header):
        gssstring = None
        user = None
        context = None
        try:
            result, context = kerberos.authGSSServerInit('HTTP@{}'.format(settings.SPNEGO_HOSTNAME))
            if result != 1:
                logging.error('Kerberos init failed.')
                raise NotAuthorized
            result = kerberos.authGSSServerStep(context, auth_header)
            if result == 1:
                gssstring = kerberos.authGSSServerResponse(context)
            user = kerberos.authGSSServerUserName(context)
        except kerberos.GSSError as e:
            logging.error("Kerberos error: {}".format(e))
            raise NotAuthorized
        finally:
            if context:
                kerberos.authGSSServerClean(context)
        return (gssstring, user)

    def auth_kerberos(self, auth_header):
        split_auth = auth_header.split()
        if split_auth[0] == 'Basic':
            try:
                user = self.auth_basic(split_auth[1])
            except kerberos.BasicAuthError as e:
                logging.error('Basic Auth Failed: {}'.format(e))
                raise NotAuthorized
        elif split_auth[0] == 'Negotiate':
            gssstring, user = self.auth_negotiate(split_auth[1])
        else:
            raise NotAuthorized

    def __call__(self, request):
        if not hasattr(settings, 'SPNEGO_REALM'):
            raise ImproperlyConfigured(
                "The Spnego Authentication Middleware requires the "
                "SPNEGO_REALM setting to be configured as the kerberos "
                "realm to be authenticated against. This is used in basic "
                "authentication."
            )

        if not hasattr(settings, 'SPNEGO_HOSTNAME'):
            raise ImproperlyConfigured(
                "The Spnego Authentication Middleware requires the "
                "SPNEGO_HOSTNAME setting to be configured as the hostname "
                "the service is authorized for. "
            )
        
        try:
            try:
                authorization = request.META['HTTP_AUTHORIZATION']
                self.auth_kerberos(authorization)
            except KeyError:
                raise NotAuthorized
        except NotAuthorized:
            return SpnegoHttpUnauthorized('Unauthorized')
        return self.get_response(request)
