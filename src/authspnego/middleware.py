import base64
import logging
from datetime import timedelta

import kerberos
from django.conf import settings
from django.contrib.auth import load_backend, login, logout
from django.core.exceptions import ImproperlyConfigured
from django.http.response import HttpResponse
from django.utils import timezone


class NotAuthorized(Exception):
    pass


def _get_ldap_backend():
    """
    Returns the LDAPBackend so we can use it to get the django
    user object.
    """
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
        """
        We need to send two separate WWW-Authenticate headers, one to tell
        the browser we support Negotiate and one to tell them we can fall
        back to Basic if required.

        We're overriding items() here because Django's header store on
        HttpResponse is a dictionary and only allows one of each type of header
        to be sent.

        This is awful but we're doing it because browsers don't properly
        support the HTTP standards for the WWW-Authenticate header and
        django doesn't allow us to send a header twice by default.

        A more elegant solution would be to override the default WSGI handler
        which actually loops through the headers, and have it support a list as
        value in the headers dictionary but I've chosen to do it this way
        because I didn't want the solution to require a custom WSGI handler.
        """
        yield from super().items()
        yield ('WWW-Authenticate', 'Negotiate')
        yield ('WWW-Authenticate', 'Basic realm="{}"'.format(
            settings.SPNEGO_REALM))


class AuthSpnegoMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def auth_basic(self, auth_header):
        """
        Manages the basic authorization process with kerberos.
        Returns a username or raises a BasicAuthError.
        """

        # The authorization header is base64 encoded, we need it decoded
        auth_decoded = base64.decodebytes(auth_header.encode('utf8')).decode()
        # Decoded format is <username>:<password> so we need to split it
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
        """
        Manages the Negotiate authorization process with
        kerberos. Returns the gss server response after
        the kerberos negotiation is complete.
        """

        gssstring = None
        user = None
        context = None

        try:
            # Initialize the kerberos auth. This will
            # fail if the entries in the keytab are invalid.
            result, context = kerberos.authGSSServerInit(
                'HTTP@{}'.format(settings.SPNEGO_HOSTNAME))
            if result != 1:
                logging.error('Kerberos init failed.')
                raise NotAuthorized

            result = kerberos.authGSSServerStep(context, auth_header)
            if result == 1:
                gssstring = kerberos.authGSSServerResponse(context)
            else:
                # There's something wrong with our session ticket
                # We should've already raised a GSSError
                raise NotAuthorized
            # This will give us the username in <user>@<realm> format
            user = kerberos.authGSSServerUserName(context)
        except kerberos.GSSError as e:
            logging.error("Kerberos error: %s", e)
            raise NotAuthorized
        finally:
            if context:
                kerberos.authGSSServerClean(context)
        return (gssstring, user)

    def authenticate_user(self, request):
        """
        This method determines the authorization method to use
        (Basic or Negotiate) and then makes it happen. If the
        user is authorized then log them in using the
        LDAP backend and return the gss server response if set
        to be added to the response.
        """
        backend = _get_ldap_backend()
        gssstring = None

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
            # The username is returned as <user>@<realm> so drop the realm
            username = krb_username.split('@', maxsplit=1)[0]
            # This gets us a user object without needing to authenticate
            # through the backend which is awesomely handy.
            user = backend.populate_user(username)
            if user is not None:
                # If everything went well we should have a user to login
                login(request, user,
                      backend='django_auth_ldap.backend.LDAPBackend')
        except KeyError:
            raise NotAuthorized

        return gssstring

    def expire_login(self, request):
        """
        Limit the length of the user's login session to the number of
        minutes defined in SPNEGO_EXPIRE_LOGIN. This defaults to 600 minutes
        because that's the default maximum length of a kerberos session
        ticket on a windows domain.
        """
        expire_minutes = getattr(settings, 'SPNEGO_EXPIRE_LOGIN', 600)
        if expire_minutes:
            expiry_time = request.user.last_login + timedelta(
                minutes=expire_minutes,
            )
            if timezone.now() > expiry_time:
                logout(request)

    def __call__(self, request):
        gssstring = None

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

        # Check to see if we need to expire the login
        if request.user.is_authenticated():
            self.expire_login(request)

        # If the user isn't authenticated (and saved in the session) then
        # we should attempt to do so.
        if not request.user.is_authenticated():
            try:
                gssstring = self.authenticate_user(request)
            except NotAuthorized:
                # If the user is not authorized they can't be logged in
                logout(request)
                return SpnegoHttpUnauthorized('Unauthorized')

        # Create the response
        response = self.get_response(request)

        # If we have a GSS result result add it to the response
        if gssstring:
            response['WWW-Authenticate'] = "Negotiate {}".format(gssstring)
        return response
