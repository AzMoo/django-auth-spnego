from glob import glob
from os.path import basename, splitext

from setuptools import find_packages, setup


def readme():
    with open('README.md') as f:
        return f.read()


# Test Dependencies
test_deps = [
    'pytest',
    'pytest-django',
    'pytest-pythonpath',
    'mockldap'
]

setup(
    name='django-auth-spnego',
    version='0.1.2',
    author='Matt Magin',
    author_email='matt.azmoo@gmail.com',
    url='https://github.com/AzMoo/django-auth-spnego',
    description='SPNEGO Kerberos authentication middleware for django',
    long_description=readme(),
    license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Framework :: Django :: 1.11',
        'Framework :: Django :: 1.10',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Middleware',
        'Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP',  # noqa
    ],
    keywords='django spnego auth ldap middleware',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    py_modules=[splitext(basename(path))[0] for path in glob('src/*.py')],
    zip_safe=False,
    install_requires=[
        'django',
        'kerberos',
        'django-auth-ldap'
    ],
    python_requires='>=3.4',
    tests_require=test_deps,
    extras_require={
        'tests': test_deps
    }
)
