# coding: utf-8
from __future__ import unicode_literals
from __future__ import absolute_import

from .algos import AlgorithmIdentifier, EncryptionAlgorithm, HmacAlgorithm
from .core import Any, Choice, Integer, ObjectIdentifier, OctetString, Sequence


# The structures in this file are taken from
# http://www.emc.com/collateral/white-papers/h11302-pkcs5v2-1-password-based-cryptography-standard-wp.pdf
# with extra OIDs from https://tools.ietf.org/html/rfc7292 (PKCS#12)


class Pbes1Params(Sequence):
    _fields = [
        ('salt', OctetString),
        ('iterations', Integer),
    ]


class Pbkdf2Salt(Choice):
    _fields = [
        ('specified', OctetString),
        ('other_source', AlgorithmIdentifier),
    ]


class Pbkdf2Params(Sequence):
    _fields = [
        ('salt', Pbkdf2Salt),
        ('iteration_count', Integer),
        ('key_length', Integer, {'optional': True}),
        ('prf', HmacAlgorithm, {'optional': True}),
    ]


class KdfAlgorithmId(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.5.12': 'pbkdf2'
    }


class KdfAlgorithm(Sequence):
    _fields = [
        ('algorithm', KdfAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]
    _oid_pair = ('algorithm', 'parameters')
    _oid_specs = {
        'pbkdf2': Pbkdf2Params
    }


class Pbes2Params(Sequence):
    _fields = [
        ('key_derivation_func', KdfAlgorithm),
        ('encryption_scheme', EncryptionAlgorithm),
    ]


class Pkcs5EncryptionId(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.5.13': 'pbes2',
        '1.2.840.113549.1.5.1': 'pbes1_md2_des',
        '1.2.840.113549.1.5.3': 'pbes1_md5_des',
        '1.2.840.113549.1.5.4': 'pbes1_md2_rc2',
        '1.2.840.113549.1.5.6': 'pbes1_md5_rc2',
        '1.2.840.113549.1.5.10': 'pbes1_sha1_des',
        '1.2.840.113549.1.5.11': 'pbes1_sha1_rc2',
        '1.2.840.113549.1.12.1.1': 'pkcs12_sha1_rc4_128',
        '1.2.840.113549.1.12.1.2': 'pkcs12_sha1_rc4_40',
        '1.2.840.113549.1.12.1.3': 'pkcs12_sha1_tripledes_3key',
        '1.2.840.113549.1.12.1.4': 'pkcs12_sha1_tripledes_2key',
        '1.2.840.113549.1.12.1.5': 'pkcs12_sha1_rc2_128',
        '1.2.840.113549.1.12.1.6': 'pkcs12_sha1_rc2_40',
    }


class Pkcs5EncryptionAlgorithm(Sequence):
    _fields = [
        ('algorithm', Pkcs5EncryptionId),
        ('parameters', Any),
    ]

    _oid_pair = ('algorithm', 'parameters')
    _oid_specs = {
        'pbes2': Pbes2Params,
        'pbes1_md2_des': Pbes1Params,
        'pbes1_md5_des': Pbes1Params,
        'pbes1_md2_rc2': Pbes1Params,
        'pbes1_md5_rc2': Pbes1Params,
        'pbes1_sha1_des': Pbes1Params,
        'pbes1_sha1_rc2': Pbes1Params,
        'pkcs12_sha1_rc4_128': Pbes1Params,
        'pkcs12_sha1_rc4_40': Pbes1Params,
        'pkcs12_sha1_tripledes_3key': Pbes1Params,
        'pkcs12_sha1_tripledes_2key': Pbes1Params,
        'pkcs12_sha1_rc2_128': Pbes1Params,
        'pkcs12_sha1_rc2_40': Pbes1Params,
    }

    @property
    def kdf(self):
        """
        Returns the name of the key derivation function to use.

        :return:
            A unicode from of one of the following: "pbkdf1", "pbkdf2", "pkcs12_kdf"
        """

        encryption_algo = self['algorithm'].native

        if encryption_algo == 'pbes2':
            return self['parameters'].parsed['key_derivation_func']['algorithm'].native

        if encryption_algo.find('.') == -1:
            encryption_algo, _ = self['algorithm'].native.split('_', 1)

            if encryption_algo == 'pbes1':
                return 'pbkdf1'

            if encryption_algo == 'pkcs12':
                return 'pkcs12_kdf'

        raise ValueError('Unrecognized encryption algorithm "%s", can not determine key derivation function' % encryption_algo)

    @property
    def kdf_hmac(self):
        """
        Returns the HMAC algorithm to use with the KDF.

        :return:
            A unicode string of one of the following: "md2", "md5", "sha1", "sha224", "sha256", "sha384", "sha512"
        """

        encryption_algo = self['algorithm'].native

        if encryption_algo == 'pbes2':
            return self['parameters'].parsed['key_derivation_func']['parameters']['prf']['algorithm'].native

        if encryption_algo.find('.') == -1:
            _, hmac_algo, _ = self['algorithm'].native.split('_', 2)
            return hmac_algo

        raise ValueError('Unrecognized encryption algorithm "%s", can not determine key derivation hmac algorithm' % encryption_algo)

    @property
    def kdf_salt(self):
        """
        Returns the byte string to use as the salt for the KDF.

        :return:
            A byte string
        """

        encryption_algo = self['algorithm'].native

        if encryption_algo == 'pbes2':
            salt = self['parameters'].parsed['key_derivation_func']['algorithm']['salt']

            if salt.name == 'other_source':
                raise ValueError('Can not determine key derivation salt - the reversed-for-future-use other source salt choice was specified in the PBKDF2 params structure')

            return salt.native

        if encryption_algo.find('.') == -1:
            return self['parameters']['salt'].native

        raise ValueError('Unrecognized encryption algorithm "%s", can not determine key derivation salt' % encryption_algo)

    @property
    def kdf_iterations(self):
        """
        Returns the number of iterations that should be run via the KDF.

        :return:
            An integer
        """

        encryption_algo = self['algorithm'].native

        if encryption_algo == 'pbes2':
            return self['parameters']['key_derivation_func']['algorithm']['iteration_count'].native

        if encryption_algo.find('.') == -1:
            return self['parameters']['iterations'].native

        raise ValueError('Unrecognized encryption algorithm "%s", can not determine key derivation iterations' % encryption_algo)

    @property
    def key_length(self):
        """
        Returns the key length to pass to the KDF/cipher. The PKCS#5 spec does
        not specify a way to store the RC5 key length, however this tends not
        to be a problem since OpenSSL does not support RC5 in PKCS#8 and OS X
        does not provide an RC5 cipher for use in the Security Transforms
        library.

        :raises:
            ValueError - when the key length can not be determined

        :return:
            An integer representing the length in bytes
        """

        encryption_algo = self['algorithm'].native

        if encryption_algo == 'pbes2':
            key_length = self['parameters']['key_derivation_func']['algorithm']['key_length'].native
            if key_length is not None:
                return key_length

            # If the KDF params don't specify the key size, we can infer it from
            # the encryption scheme for all schemes except for RC5. However, in
            # practical terms, neither OpenSSL or OS X support RC5 for PKCS#8
            # so it is unlikely to be an issue that is run into.

            return self['parameters']['encryption_scheme'].key_length

        if encryption_algo.find('.') == -1:
            return {
                'pbes1_md2_des': 8,
                'pbes1_md5_des': 8,
                'pbes1_md2_rc2': 8,
                'pbes1_md5_rc2': 8,
                'pbes1_sha1_des': 8,
                'pbes1_sha1_rc2': 8,
                'pkcs12_sha1_rc4_128': 16,
                'pkcs12_sha1_rc4_40': 5,
                'pkcs12_sha1_tripledes_3key': 24,
                'pkcs12_sha1_tripledes_2key': 16,
                'pkcs12_sha1_rc2_128': 16,
                'pkcs12_sha1_rc2_40': 5,
            }[encryption_algo]

        raise ValueError('Unrecognized encryption algorithm "%s", can not determine key derivation function key length' % encryption_algo)

    @property
    def encryption_cipher(self):
        """
        Returns the name of the symmetric encryption cipher to use. The key
        length can be retrieved via the .key_length property to disabiguate
        between different variations of TripleDES, AES, and the RC* ciphers.

        :return:
            A unicode string from one of the following: "rc2", "rc4", "rc5", "des", "tripledes", "aes"
        """

        encryption_algo = self['algorithm'].native

        if encryption_algo == 'pbes2':
            return self['parameters']['encryption_scheme'].encryption_cipher

        if encryption_algo.find('.') == -1:
            return {
                'pbes1_md2_des': 'des',
                'pbes1_md5_des': 'des',
                'pbes1_md2_rc2': 'rc2',
                'pbes1_md5_rc2': 'rc2',
                'pbes1_sha1_des': 'des',
                'pbes1_sha1_rc2': 'rc2',
                'pkcs12_sha1_rc4_128': 'rc4',
                'pkcs12_sha1_rc4_40': 'rc4',
                'pkcs12_sha1_tripledes_3key': 'tripledes',
                'pkcs12_sha1_tripledes_2key': 'tripledes',
                'pkcs12_sha1_rc2_128': 'rc2',
                'pkcs12_sha1_rc2_40': 'rc2',
            }[encryption_algo]

        raise ValueError('Unrecognized encryption algorithm "%s", can not determine encryption cipher' % encryption_algo)

    @property
    def encryption_block_size(self):
        """
        Returns the block size of the encryption cipher, in bytes. For RC4, a
        stream cipher, 0 is returned.

        :return:
            An integer that is the block size in bytes
        """

        encryption_algo = self['algorithm'].native

        if encryption_algo == 'pbes2':
            return self['parameters']['encryption_scheme'].encryption_block_size

        if encryption_algo.find('.') == -1:
            return {
                'pbes1_md2_des': 8,
                'pbes1_md5_des': 8,
                'pbes1_md2_rc2': 8,
                'pbes1_md5_rc2': 8,
                'pbes1_sha1_des': 8,
                'pbes1_sha1_rc2': 8,
                'pkcs12_sha1_rc4_128': 0,
                'pkcs12_sha1_rc4_40': 0,
                'pkcs12_sha1_tripledes_3key': 8,
                'pkcs12_sha1_tripledes_2key': 8,
                'pkcs12_sha1_rc2_128': 8,
                'pkcs12_sha1_rc2_40': 8,
            }[encryption_algo]

        raise ValueError('Unrecognized encryption algorithm "%s", can not determine encryption block size' % encryption_algo)

    @property
    def encryption_iv(self):
        """
        Returns the byte string of the initialization vector for the encryption
        scheme. Only the PBES2 stores the IV in the params. For PBES1, the IV
        is derived from the KDF and this property will return None.

        :return:
            A byte string or None
        """

        encryption_algo = self['algorithm'].native

        if encryption_algo == 'pbes2':
            return self['parameters']['encryption_scheme'].encryption_iv

        # All of the PBES1 algos use their KDF to create the IV. For the pbkdf1,
        # the KDF is told to generate a key that is an extra 8 bytes long, and
        # that is used for the IV. For the PKCS#12 KDF, it is called with an id
        # of 2 to generate the IV. In either case, we can't return the IV
        # without knowing the user's password.
        if encryption_algo.find('.') == -1:
            return None

        raise ValueError('Unrecognized encryption algorithm "%s", can not determine initialization vector' % encryption_algo)


class Pbmac1Params(Sequence):
    _fields = [
        ('key_derivation_func', KdfAlgorithm),
        ('message_auth_scheme', HmacAlgorithm),
    ]


class Pkcs5MacId(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.5.14': 'pbmac1',
    }


class Pkcs5MacAlgorithm(Sequence):
    _fields = [
        ('algorithm', Pkcs5MacId),
        ('parameters', Any),
    ]

    _oid_pair = ('algorithm', 'parameters')
    _oid_specs = {
        'pbmac1': Pbmac1Params,
    }
