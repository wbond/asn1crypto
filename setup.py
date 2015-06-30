from setuptools import setup, find_packages
import asn1crypto


setup(
    name='asn1crypto',
    version=asn1crypto.__version__,

    description='Fast ASN.1 parser and serializer with definitions for private keys, public keys, certificates, CRL, OCSP, CMS, PKCS#7, PKCS#8, PKCS#12, PKCS#5, X509 and TSA',
    long_description='Docs for this project are maintained at https://github.com/wbond/asn1crypto#readme.',

    url='https://github.com/wbond/asn1crypto',

    author='wbond',
    author_email='will@wbond.net',

    license='MIT',

    classifiers=[
        'Development Status :: 4 - Beta',

        'Intended Audience :: Developers',

        'License :: OSI Approved :: MIT License',

        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
    ],

    keywords='asn1 crypto',

    packages=find_packages(exclude=['tests*', 'dev*'])
)
