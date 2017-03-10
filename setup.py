from setuptools import setup, find_packages

from asn1crypto import version

setup(
    name='asn1crypto',
    version=version.__version__,

    description=(
        'Fast ASN.1 parser and serializer with definitions for private keys, '
        'public keys, certificates, CRL, OCSP, CMS, PKCS#3, PKCS#7, PKCS#8, '
        'PKCS#12, PKCS#5, X.509 and TSP'
    ),
    long_description='Docs for this project are maintained at https://github.com/wbond/asn1crypto#readme.',

    url='https://github.com/wbond/asn1crypto',

    author='wbond',
    author_email='will@wbond.net',

    license='MIT',

    classifiers=[
        'Development Status :: 4 - Beta',

        'Intended Audience :: Developers',

        'License :: OSI Approved :: MIT License',

        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: PyPy',

        'Topic :: Security :: Cryptography',
    ],

    keywords='asn1 crypto pki x509 certificate rsa dsa ec dh',

    packages=find_packages(exclude=['tests*', 'dev*']),

    test_suite='tests.make_suite',
)
