from setuptools import setup, find_packages

setup(
    name='django-auth-spnego',
    version='0.0.1',
    author='Matt Magin',
    author_email='matt.azmoo@gmail.com',
    description='SPNEGO-based Kerberos and NTLM authentication in django',
    license='MIT',
    packages=find_packages(),
    install_requires=[
        'pykerberos==1.1.14',
    ]
)
