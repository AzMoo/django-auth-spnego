# django-auth-spnego

This project provides SPNEGO and Kerberos authentication to a django project. You can do this with apache
or IIS and use Django's RemoteUser middleware for authentication but I don't use those web servers
and others don't support it.

The actual authorization is done using a middleware that handles the kerberos negotiation and
the django user management and login handling implements the incredibly useful
[django-auth-ldap](https://bitbucket.org/illocution/django-auth-ldap).

The hardest thing about getting this working is getting the kerberos set up properly between your
application server and the AD domain. Some docs for this are coming.

If your django project uses sessions for much other than authentication then this project
might not be for you, as the middleware will log a user out after the kerberos ticket
has expired (default 600 minutes) which destroys the entire session. You can change this
but then you have to figure out how you're going to destroy a session when the user's
kerberos session ticket expires.

### Prerequisites

* An Active Directory Domain
* A valid kerberos configuration on your application server
* An SPN created for the user running the application server

### Installing

You will need to add the following to your `settings.py` in your django project.

Add the middleware to django's `MIDDLEWARE` setting below the `AuthenticationMiddleware`.
The order of your middlware classes are important as django-auth-spnego requires `request.user`
to be set by `AuthenticationMiddleware`. For example:

```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'authspnego.middleware.AuthSpnegoMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
```

Add the `LDAPBackend` to your `AUTHENTICATION_BACKENDS` setting:

```python
AUTHENTICATION_BACKENDS = (
    'django_auth_ldap.backend.LDAPBackend',
    'django.contrib.auth.backends.ModelBackend',
)
```

Add the SPNEGO specific settings. It's critical you get these values right or none of this will work:

```python
SPNEGO_REALM = 'LAB.AZMOO.ID.AU' # Your AD Domain. This is almost always capitalised.
SPNEGO_HOSTNAME = 'your-app-server.lab.azmoo.id.au' # The FQDN of your app server.
SPNEGO_EXPIRE_LOGIN = 600 # Set this to false to never expire
```

Finally you need to configure [django-auth-ldap](https://bitbucket.org/illocution/django-auth-ldap).

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/your/project/tags).

## Authors

* **Matt Magin** - *Initial work* - [AzMoo](https://github.com/AzMoo)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* The SSO implementation for [GateOne](https://liftoff.github.io/GateOne/Developer/sso.html) was very useful to see how the kerberos library was supposed to be used.
* [django-auth-ldap](https://bitbucket.org/illocution/django-auth-ldap) saved me a load of time for the django auth side of things
