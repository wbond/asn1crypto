# coding: utf-8
from __future__ import unicode_literals
from __future__ import absolute_import

import hashlib
from decimal import localcontext

from .algos import DigestAlgorithm, EncryptionAlgorithm
from .core import (
    Any,
    Choice,
    Integer,
    IntegerBitString,
    IntegerOctetString,
    Null,
    ObjectIdentifier,
    OctetBitString,
    OctetString,
    Sequence,
    SequenceOf,
    SetOf,
)

try:
    # Python 2
    str_cls = unicode  #pylint: disable=E0602
    byte_cls = str
    import cPickle as pickle  #pylint: disable=F0401

except NameError:
    # Python 3
    str_cls = str
    byte_cls = bytes
    import pickle



class OtherPrimeInfo(Sequence):
    """
    Source: https://tools.ietf.org/html/rfc3447#page-46
    """

    _fields = [
        ('prime', Integer),
        ('exponent', Integer),
        ('coefficient', Integer),
    ]


class OtherPrimeInfos(SequenceOf):
    """
    Source: https://tools.ietf.org/html/rfc3447#page-46
    """

    _child_spec = OtherPrimeInfo


class RSAPrivateKeyVersion(Integer):
    """
    Original Name: Version
    Source: https://tools.ietf.org/html/rfc3447#page-45
    """

    _map = {
        0: 'two-prime',
        1: 'multi',
    }


class RSAPrivateKey(Sequence):
    """
    Source: https://tools.ietf.org/html/rfc3447#page-45
    """

    _fields = [
        ('version', RSAPrivateKeyVersion),
        ('modulus', Integer),
        ('public_exponent', Integer),
        ('private_exponent', Integer),
        ('prime1', Integer),
        ('prime2', Integer),
        ('exponent1', Integer),
        ('exponent2', Integer),
        ('coefficient', Integer),
        ('other_prime_infos', OtherPrimeInfos, {'optional': True})
    ]


class RSAPublicKey(Sequence):
    """
    Source: https://tools.ietf.org/html/rfc3447#page-44
    """

    _fields = [
        ('modulus', Integer),
        ('public_exponent', Integer)
    ]


class DSAPrivateKey(Sequence):
    """
    The ASN1 structure that OpenSSL uses to store a DSA private key that is
    not part of a PKCS#8 structure. Reversed engineered from english-language
    description on linked OpenSSL documentation page.

    Original Name: None
    Source: https://www.openssl.org/docs/apps/dsa.html
    """

    _fields = [
        ('version', Integer),
        ('p', Integer),
        ('q', Integer),
        ('g', Integer),
        ('public_key', Integer),
        ('private_key', Integer),
    ]


class SpecifiedECDomainVersion(Integer):
    """
    Source: http://www.secg.org/sec1-v2.pdf page 104
    """
    _map = {
        1: 'ecdpVer1',
        2: 'ecdpVer2',
        3: 'ecdpVer3',
    }


class FieldType(ObjectIdentifier):
    """
    Original Name: None
    Source: http://www.secg.org/sec1-v2.pdf page 101
    """

    _map = {
        '1.2.840.10045.1.1': 'prime_field',
        '1.2.840.10045.1.2': 'characteristic_two_field',
    }


class CharacteristicTwoBasis(ObjectIdentifier):
    """
    Original Name: None
    Source: http://www.secg.org/sec1-v2.pdf page 102
    """

    _map = {
        '1.2.840.10045.1.2.1.1': 'gn_basis',
        '1.2.840.10045.1.2.1.2': 'tp_basis',
        '1.2.840.10045.1.2.1.3': 'pp_basis',
    }


class Pentanomial(Sequence):
    """
    Source: http://www.secg.org/sec1-v2.pdf page 102
    """

    _fields = [
        ('k1', Integer),
        ('k2', Integer),
        ('k3', Integer),
    ]


class CharacteristicTwo(Sequence):
    """
    Original Name: Characteristic-two
    Source: http://www.secg.org/sec1-v2.pdf page 101
    """

    _fields = [
        ('m', Integer),
        ('basis', CharacteristicTwoBasis),
        ('parameters', Any),
    ]

    _oid_pair = ('basis', 'parameters')
    _oid_specs = {
        'gn_basis': Null,
        'tp_basis': Integer,
        'pp_basis': Pentanomial,
    }


class FieldID(Sequence):
    """
    Source: http://www.secg.org/sec1-v2.pdf page 100
    """

    _fields = [
        ('field_type', FieldType),
        ('parameters', Any),
    ]

    _oid_pair = ('field_type', 'parameters')
    _oid_specs = {
        'prime_field': Integer,
        'characteristic_two_field': CharacteristicTwo,
    }


class Curve(Sequence):
    """
    Source: http://www.secg.org/sec1-v2.pdf page 104
    """

    _fields = [
        ('a', OctetString),
        ('b', OctetString),
        ('seed', OctetBitString, {'optional': True}),
    ]


class SpecifiedECDomain(Sequence):
    """
    Source: http://www.secg.org/sec1-v2.pdf page 103
    """

    _fields = [
        ('version', SpecifiedECDomainVersion),
        ('field_id', FieldID),
        ('curve', Curve),
        ('base', OctetString),
        ('order', Integer),
        ('cofactor', Integer, {'optional': True}),
        ('hash', DigestAlgorithm, {'optional': True}),
    ]


class NamedCurve(ObjectIdentifier):
    """
    Various named curves

    Original Name: None
    Source: https://tools.ietf.org/html/rfc3279#page-23,
            https://tools.ietf.org/html/rfc5480#page-5
    """

    _map = {
        # https://tools.ietf.org/html/rfc3279#page-23
        '1.2.840.10045.3.0.1': 'c2pnb163v1',
        '1.2.840.10045.3.0.2': 'c2pnb163v2',
        '1.2.840.10045.3.0.3': 'c2pnb163v3',
        '1.2.840.10045.3.0.4': 'c2pnb176w1',
        '1.2.840.10045.3.0.5': 'c2tnb191v1',
        '1.2.840.10045.3.0.6': 'c2tnb191v2',
        '1.2.840.10045.3.0.7': 'c2tnb191v3',
        '1.2.840.10045.3.0.8': 'c2onb191v4',
        '1.2.840.10045.3.0.9': 'c2onb191v5',
        '1.2.840.10045.3.0.10': 'c2pnb208w1',
        '1.2.840.10045.3.0.11': 'c2tnb239v1',
        '1.2.840.10045.3.0.12': 'c2tnb239v2',
        '1.2.840.10045.3.0.13': 'c2tnb239v3',
        '1.2.840.10045.3.0.14': 'c2onb239v4',
        '1.2.840.10045.3.0.15': 'c2onb239v5',
        '1.2.840.10045.3.0.16': 'c2pnb272w1',
        '1.2.840.10045.3.0.17': 'c2pnb304w1',
        '1.2.840.10045.3.0.18': 'c2tnb359v1',
        '1.2.840.10045.3.0.19': 'c2pnb368w1',
        '1.2.840.10045.3.0.20': 'c2tnb431r1',
        '1.2.840.10045.3.1.1': 'prime192v1',
        '1.2.840.10045.3.1.2': 'prime192v2',
        '1.2.840.10045.3.1.3': 'prime192v3',
        '1.2.840.10045.3.1.4': 'prime239v1',
        '1.2.840.10045.3.1.5': 'prime239v2',
        '1.2.840.10045.3.1.6': 'prime239v3',
        '1.2.840.10045.3.1.7': 'prime256v1',
        # https://tools.ietf.org/html/rfc5480#page-5
        '1.3.132.0.1': 'sect163k1',
        '1.3.132.0.15': 'sect163r2',
        '1.3.132.0.33': 'secp224r1',
        '1.3.132.0.26': 'sect233k1',
        '1.3.132.0.27': 'sect233r1',
        '1.3.132.0.16': 'sect283k1',
        '1.3.132.0.17': 'sect283r1',
        '1.3.132.0.34': 'secp384r1',
        '1.3.132.0.36': 'sect409k1',
        '1.3.132.0.37': 'sect409r1',
        '1.3.132.0.35': 'secp521r1',
        '1.3.132.0.38': 'sect571k1',
        '1.3.132.0.39': 'sect571r1',
    }


class ECDomainParameters(Choice):
    """
    Source: http://www.secg.org/sec1-v2.pdf page 102
    """

    _alternatives = [
        ('specified', SpecifiedECDomain),
        ('named', NamedCurve),
        ('implicit_ca', Null),
    ]


class ECPrivateKeyVersion(Integer):
    """
    Original Name: None
    Source: http://www.secg.org/sec1-v2.pdf page 108
    """

    _map = {
        1: 'ecPrivkeyVer1',
    }


class ECPrivateKey(Sequence):
    """
    Source: http://www.secg.org/sec1-v2.pdf page 108
    """

    _fields = [
        ('version', ECPrivateKeyVersion),
        ('private_key', IntegerOctetString),
        ('parameters', ECDomainParameters, {'tag_type': 'explicit', 'tag': 0, 'optional': True}),
        ('public_key', IntegerBitString, {'tag_type': 'explicit', 'tag': 1, 'optional': True}),
    ]



class DSAParams(Sequence):
    """
    Parameters for a DSA public or private key

    Original Name: Dss-Parms
    Source: https://tools.ietf.org/html/rfc3279#page-9
    """

    _fields = [
        ('p', Integer),
        ('q', Integer),
        ('g', Integer),
    ]


class Attribute(Sequence):
    """
    Source: https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-X.501-198811-S!!PDF-E&type=items page 8
    """

    _fields = [
        ('type', ObjectIdentifier),
        ('values', SetOf, {'spec': Any}),
    ]


class Attributes(SetOf):
    """
    Source: https://tools.ietf.org/html/rfc5208#page-3
    """

    _child_spec = Attribute


class PrivateKeyAlgorithmId(ObjectIdentifier):
    """
    These OIDs for various public keys are reused when storing private keys
    inside of a PKCS#8 structure

    Original Name: None
    Source: https://tools.ietf.org/html/rfc3279
    """

    _map = {
        # https://tools.ietf.org/html/rfc3279#page-19
        '1.2.840.113549.1.1.1': 'rsa',
        # https://tools.ietf.org/html/rfc3279#page-18
        '1.2.840.10040.4.1': 'dsa',
        # https://tools.ietf.org/html/rfc3279#page-13
        '1.2.840.10045.2.1': 'ecdsa',
    }


class PrivateKeyAlgorithm(Sequence):
    """
    Original Name: PrivateKeyAlgorithmIdentifier
    Source: https://tools.ietf.org/html/rfc5208#page-3
    """

    _fields = [
        ('algorithm', PrivateKeyAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]

    _oid_pair = ('algorithm', 'parameters')
    _oid_specs = {
        'rsa': Null,
        'dsa': DSAParams,
        'ecdsa': ECDomainParameters,
    }


class PrivateKeyInfo(Sequence):
    """
    Source: https://tools.ietf.org/html/rfc5208#page-3
    """

    _fields = [
        ('version', Integer),
        ('private_key_algorithm', PrivateKeyAlgorithm),
        ('private_key', OctetString),
        ('attributes', Attributes, {'tag_type': 'implicit', 'tag': 0, 'optional': True}),
    ]

    def _private_key_spec(self):
        algorithm = self['private_key_algorithm']['algorithm'].native
        return {
            'rsa': RSAPrivateKey,
            'dsa': Integer,
            'ecdsa': ECPrivateKey,
        }[algorithm]

    _spec_callbacks = {
        'private_key': _private_key_spec
    }

    _fingerprint = None

    @property
    def fingerprint(self):
        """
        Creates a fingerprint that can be compared with a public key to see if
        the two form a pair.

        This fingerprint is not compatiable with fingerprints generated by any
        other software.

        :raises:
            ValueError - when the private key is ECDSA, but the public_key field is empty

        :return:
            A byte string that is a sha256 hash of selected components (based
            on the key type)
        """

        if self._fingerprint is None:
            key_type = self['private_key_algorithm']['algorithm'].native
            params = self['private_key_algorithm']['parameters'].native
            key = self['private_key'].parsed

            if key_type == 'rsa':
                to_hash = '%d:%d' % (
                    key['modulus'].native,
                    key['public_exponent'].native,
                )

            elif key_type == 'dsa':
                # The private key structure for PKCS#8 does not include the
                # public key, so we must calculate it here
                with localcontext() as ctx:
                    ctx.prec = 200
                    public_key = ctx.power(params['g'].native, key.native, params['p'].native)

                to_hash = '%d:%d:%d:%d' % (
                    params['p'].native,
                    params['q'].native,
                    params['g'].native,
                    int(public_key),
                )

            elif key_type == 'ecdsa':
                public_key = key['public_key'].native
                if public_key is None:
                    raise ValueError('Unable to compute fingerprint of ecdsa private key since the public_key field is empty')

                if params.name == 'named':
                    to_hash = '%s:%d' % (
                        params.chosen.native,
                        public_key,
                    )

                elif params.named == 'implicit_ca':
                    to_hash = str_cls(public_key)

                elif params.named == 'specified':
                    to_hash = b'%s:%s' % (
                        pickle.dumps(params.native),
                        str_cls(public_key).encode('utf-8'),
                    )

            if isinstance(to_hash, str_cls):
                to_hash = to_hash.encode('utf-8')

            self._fingerprint = hashlib.sha256(to_hash).digest()

        return self._fingerprint


class EncryptedPrivateKeyInfo(Sequence):
    """
    Source: https://tools.ietf.org/html/rfc5208#page-4
    """

    _fields = [
        ('encryption_algorithm', EncryptionAlgorithm),
        ('encrypted_data', OctetString),
    ]


# These structures are from https://tools.ietf.org/html/rfc3279

class PublicKeyAlgorithmId(ObjectIdentifier):
    """
    Original Name: None
    Source: https://tools.ietf.org/html/rfc3279
    """

    _map = {
        # https://tools.ietf.org/html/rfc3279#page-19
        '1.2.840.113549.1.1.1': 'rsa',
        # https://tools.ietf.org/html/rfc3279#page-18
        '1.2.840.10040.4.1': 'dsa',
        # https://tools.ietf.org/html/rfc3279#page-13
        '1.2.840.10045.2.1': 'ecdsa',
    }


class PublicKeyAlgorithm(Sequence):
    """
    Original Name: AlgorithmIdentifier
    Source: https://tools.ietf.org/html/rfc5280#page-18
    """

    _fields = [
        ('algorithm', PublicKeyAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]

    _oid_pair = ('algorithm', 'parameters')
    _oid_specs = {
        'rsa': Null,
        'dsa': DSAParams,
        'ecdsa': ECDomainParameters,
    }


class PublicKeyInfo(Sequence):
    """
    Original Name: SubjectPublicKeyInfo
    Source: https://tools.ietf.org/html/rfc5280#page-17
    """

    _fields = [
        ('algorithm', PublicKeyAlgorithm),
        ('public_key', OctetBitString),
    ]

    def _public_key_spec(self):
        algorithm = self['algorithm']['algorithm'].native
        return {
            'rsa': RSAPublicKey,
            'dsa': Integer,
            # ECSDA's public key is an ECPoint, which is an OctetString. Since
            # we are using OctetBitString here, we don't need further parsing.
            'ecdsa': OctetString,
        }[algorithm]

    _spec_callbacks = {
        'public_key': _public_key_spec
    }

    _fingerprint = None

    @property
    def fingerprint(self):
        """
        Creates a fingerprint that can be compared with a private key to see if
        the two form a pair.

        This fingerprint is not compatiable with fingerprints generated by any
        other software.

        :return:
            A byte string that is a sha256 hash of selected components (based
            on the key type)
        """

        if self._fingerprint is None:
            key_type = self['algorithm']['algorithm'].native
            params = self['algorithm']['parameters'].native
            key = self['public_key'].parsed

            if key_type == 'rsa':
                to_hash = '%d:%d' % (
                    key['modulus'].native,
                    key['public_exponent'].native,
                )

            elif key_type == 'dsa':
                to_hash = '%d:%d:%d:%d' % (
                    params['p'].native,
                    params['q'].native,
                    params['g'].native,
                    key.native,
                )

            elif key_type == 'ecdsa':
                if params.name == 'named':
                    to_hash = '%s:%d' % (
                        params.chosen.native,
                        key.native,
                    )

                elif params.named == 'implicit_ca':
                    to_hash = str_cls(key.native)

                elif params.named == 'specified':
                    to_hash = b'%s:%s' % (
                        pickle.dumps(params.native),
                        str_cls(key.native).encode('utf-8'),
                    )

            if isinstance(to_hash, str_cls):
                to_hash = to_hash.encode('utf-8')

            self._fingerprint = hashlib.sha256(to_hash).digest()

        return self._fingerprint
