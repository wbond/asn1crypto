# coding: utf-8
from __future__ import unicode_literals
from __future__ import absolute_import

from .core import Any, Integer, ObjectIdentifier, OctetString, Sequence


# OID in this file are pulled from https://tools.ietf.org/html/rfc3279,
# https://tools.ietf.org/html/rfc4055 and https://tools.ietf.org/html/rfc5758

class AlgorithmIdentifier(Sequence):
    _fields = [
        ('algorithm', ObjectIdentifier),
        ('parameters', Any, {'optional': True}),
    ]


class HmacAlgorithmId(ObjectIdentifier):
    _map = {
        '1.3.14.3.2.10': 'des_mac',
        '1.2.840.113549.2.7': 'sha1',
        '1.2.840.113549.2.8': 'sha224',
        '1.2.840.113549.2.9': 'sha256',
        '1.2.840.113549.2.10': 'sha384',
        '1.2.840.113549.2.11': 'sha512',
        '1.2.840.113549.2.12': 'sha512_224',
        '1.2.840.113549.2.13': 'sha512_256',
    }


class HmacAlgorithm(Sequence):
    _fields = [
        ('algorithm', HmacAlgorithmId, {'default': 'sha1'}),
        ('parameters', Any, {'optional': True}),
    ]


class DigestAlgorithmId(ObjectIdentifier):
    _map = {
        '1.2.840.113549.2.2': 'md2',
        '1.2.840.113549.2.5': 'md5',
        '1.3.14.3.2.26': 'sha1',
        '2.16.840.1.101.3.4.2.4': 'sha224',
        '2.16.840.1.101.3.4.2.1': 'sha256',
        '2.16.840.1.101.3.4.2.2': 'sha384',
        '2.16.840.1.101.3.4.2.3': 'sha512',
        '2.16.840.1.101.3.4.2.5': 'sha512_224',
        '2.16.840.1.101.3.4.2.6': 'sha512_256',
    }


class DigestAlgorithm(Sequence):
    _fields = [
        ('algorithm', DigestAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]


# This structure is what is signed with a SignedDigestAlgorithm
class DigestInfo(Sequence):
    _fields = [
        ('digest_algorithm', DigestAlgorithm),
        ('digest', OctetString),
    ]


class SignedDigestAlgorithmId(ObjectIdentifier):
    _map = {
        '1.3.14.3.2.3': 'md5_rsa',
        '1.3.14.3.2.29': 'sha1_rsa',
        '1.3.14.7.2.3.1': 'md2_rsa',
        '1.2.840.113549.1.1.2': 'md2_rsa',
        '1.2.840.113549.1.1.4': 'md5_rsa',
        '1.2.840.113549.1.1.5': 'sha1_rsa',
        '1.2.840.113549.1.1.14': 'sha224_rsa',
        '1.2.840.113549.1.1.11': 'sha256_rsa',
        '1.2.840.113549.1.1.12': 'sha384_rsa',
        '1.2.840.113549.1.1.13': 'sha512_rsa',
        '1.2.840.10040.4.3': 'sha1_dsa',
        '1.3.14.3.2.13': 'sha1_dsa',
        '1.3.14.3.2.27': 'sha1_dsa',
        '2.16.840.1.101.3.4.3.1': 'sha224_dsa',
        '2.16.840.1.101.3.4.3.2': 'sha256_dsa',
        '1.2.840.10045.4.1': 'sha1_ecdsa',
        '1.2.840.10045.4.3.1': 'sha224_ecdsa',
        '1.2.840.10045.4.3.2': 'sha256_ecdsa',
        '1.2.840.10045.4.3.3': 'sha384_ecdsa',
        '1.2.840.10045.4.3.4': 'sha512_ecdsa',
        # For when the digest is specified elsewhere in a Sequence
        '1.2.840.113549.1.1.1': 'rsa',
        '1.2.840.10040.4.1': 'dsa',
        '1.2.840.10045.4': 'ecdsa',
    }


class SignedDigestAlgorithm(Sequence):
    _fields = [
        ('algorithm', SignedDigestAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]


class Rc2Params(Sequence):
    _fields = [
        ('rc2_parameter_version', Integer, {'optional': True}),
        ('iv', OctetString),
    ]


class Rc5ParamVersion(Integer):
    _map = {
        16: 'v1-0'
    }


class Rc5Params(Sequence):
    _fields = [
        ('version', Rc5ParamVersion),
        ('rounds', Integer),
        ('block_size_in_bits', Integer),
        ('iv', OctetString, {'optional': True}),
    ]


class EncryptionAlgorithmId(ObjectIdentifier):
    _map = {
        '1.3.14.3.2.7': 'des',
        '1.2.840.113549.3.7': 'tripledes_3key',
        '1.2.840.113549.3.2': 'rc2',
        '1.2.840.113549.3.9': 'rc5',
        '2.16.840.1.101.3.4.1.2': 'aes128',
        '2.16.840.1.101.3.4.1.22': 'aes192',
        '2.16.840.1.101.3.4.1.42': 'aes256',
    }


class EncryptionAlgorithm(Sequence):
    _fields = [
        ('algorithm', EncryptionAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]

    _oid_pair = ('algorithm', 'parameters')
    _oid_specs = {
        'des': OctetString,
        'tripledes_3key': OctetString,
        'rc2': Rc2Params,
        'rc5': Rc5Params,
        'aes128': OctetString,
        'aes192': OctetString,
        'aes256': OctetString,
    }
