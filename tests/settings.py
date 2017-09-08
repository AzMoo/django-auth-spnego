SECRET_KEY = 'imasecretlol'  # noqa
DEBUG = True
DATABASE_ENGINE = 'sqlite3'
DATABASE_NAME = 'test.db'
INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
)
AUTHENTICATION_BACKENDS = (
    'django_auth_ldap.backend.LDAPBackend',
    'django.contrib.auth.backends.ModelBackend',
)
SPNEGO_REALM = 'SPNEGOREALM.AUTHTEST.STUFF'
SPNEGO_HOSTNAME = 'notarealhost.authest.stuff'
