import base64
import logging

import kerberos
from django.conf import settings
from django.contrib.auth import load_backend, login
from django.core.exceptions import ImproperlyConfigured
from django.http.response import HttpResponse


class NotAuthorized(Exception):
    pass


def _get_ldap_backend():
    backend_path = 'django_auth_ldap.backend.LDAPBackend'
    if backend_path not in settings.AUTHENTICATION_BACKENDS:
        raise ImproperlyConfigured(
            "LDAP Backend has not been defined. django-auth-ldap "
            "is required to use django-auth-spnego."
        )
    return load_backend('django_auth_ldap.backend.LDAPBackend')


class SpnegoHttpUnauthorized(HttpResponse):
    status_code = 401

    def items(self):
        yield from super().items()
        yield ('WWW-Authenticate', 'Negotiate')
        yield ('WWW-Authenticate', 'Basic realm="{}"'.format(settings.SPNEGO_REALM))


class AuthSpnegoMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def auth_basic(self, auth_header):
        auth_decoded = base64.decodebytes(auth_header.encode('utf8')).decode()
        userstring, password = auth_decoded.split(':', maxsplit=1)
        try:
            # If the user specifies a realm in the username verify
            # it matches the configured SPNEGO realm so we
            # don't open ourselves up to KDC spoofing
            username, realm = userstring.split('@', maxsplit=1)
            if realm != settings.SPNEGO_REALM:
                raise NotAuthorized
        except ValueError:
            username = userstring

        kerberos.checkPassword(
            username, password,
            kerberos.getServerPrincipalDetails(
                'HTTP', settings.SPNEGO_HOSTNAME),
            settings.SPNEGO_REALM
        )

        return username

    def auth_negotiate(self, auth_header):
        gssstring = None
        user = None
        context = None
        try:
            result, context = kerberos.authGSSServerInit(
                'HTTP@{}'.format(settings.SPNEGO_HOSTNAME))
            if result != 1:
                logging.error('Kerberos init failed.')
                raise NotAuthorized
            result = kerberos.authGSSServerStep(context, auth_header)
            if result == 1:
                gssstring = kerberos.authGSSServerResponse(context)
            user = kerberos.authGSSServerUserName(context)
        except kerberos.GSSError as e:
            logging.error("Kerberos error: %s", e)
            raise NotAuthorized
        finally:
            if context:
                kerberos.authGSSServerClean(context)
        return (gssstring, user)

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

        backend = _get_ldap_backend()

        try:
            try:
                split_auth = request.META['HTTP_AUTHORIZATION'].split()
                if split_auth[0] == 'Basic':
                    try:
                        krb_username = self.auth_basic(split_auth[1])
                    except kerberos.BasicAuthError as e:
                        logging.error('Basic Auth Failed: %s', e)
                        raise NotAuthorized
                elif split_auth[0] == 'Negotiate':
                    gssstring, krb_username = self.auth_negotiate(
                        split_auth[1])
                else:
                    raise NotAuthorized
                username = krb_username.split('@', maxsplit=1)[0]
                user = backend.populate_user(username)
                # user = authenticate(username=username, kerberos=True)
                if user is not None:
                    login(request, user,
                          backend='django_auth_ldap.backend.LDAPBackend')
            except KeyError:
                raise NotAuthorized
        except NotAuthorized:
            return SpnegoHttpUnauthorized('Unauthorized')

        # Create the response
        response = self.get_response(request)

        # If we have a GSS result result add it to the response
        if gssstring:
            response['WWW-Authenticate'] = "Negotiate {}".format(gssstring)
        return response
