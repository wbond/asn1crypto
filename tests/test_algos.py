# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import sys
import os

from asn1crypto import algos, core

from .unittest_data import data_decorator, data
from ._unittest_compat import patch

patch()

if sys.version_info < (3,):
    byte_cls = str
    num_cls = long  # noqa
else:
    byte_cls = bytes
    num_cls = int


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


@data_decorator
class AlgoTests(unittest.TestCase):

    def test_signed_digest_parameters(self):
        sha256_rsa = algos.SignedDigestAlgorithm({'algorithm': 'sha256_rsa'})
        self.assertEqual(core.Null, sha256_rsa['parameters'].__class__)

    def test_digest_parameters(self):
        sha1 = algos.DigestAlgorithm({'algorithm': 'sha1'})
        self.assertEqual(core.Null, sha1['parameters'].__class__)

    def test_ccm_parameters(self):
        with open(os.path.join(fixtures_dir, 'aesccm_algo.der'), 'rb') as f:
            # PBES2 AlgorithmIdentifier
            algo = algos.EncryptionAlgorithm().load(f.read())
        scheme = algo['parameters']['encryption_scheme']
        self.assertEqual(scheme['parameters'].__class__, algos.CcmParams)
        self.assertEqual(scheme['parameters']['aes_nonce'].__class__, core.OctetString)
        self.assertEqual(scheme['parameters']['aes_nonce'].native, b'z\xb7\xbd\xb7\xe1\xc6\xc0\x11\xc1?\xf00')
        self.assertEqual(scheme['parameters']['aes_icvlen'].__class__, core.Integer)
        self.assertEqual(scheme['parameters']['aes_icvlen'].native, 8)

    def test_scrypt_parameters(self):
        with open(os.path.join(fixtures_dir, 'scrypt_algo.der'), 'rb') as f:
            # PBES2 AlgorithmIdentifier
            algo = algos.EncryptionAlgorithm.load(f.read())
        kdf = algo['parameters']['key_derivation_func']
        self.assertEqual(kdf['parameters'].__class__, algos.ScryptParams)
        self.assertEqual(kdf['parameters']['salt'].__class__, core.OctetString)
        self.assertEqual(kdf['parameters']['salt'].native, b'c\x0c\x04\xb6\xe2^\xe0v')
        self.assertEqual(kdf['parameters']['cost_parameter'].__class__, core.Integer)
        self.assertEqual(kdf['parameters']['cost_parameter'].native, 16384)
        self.assertEqual(kdf['parameters']['block_size'].__class__, core.Integer)
        self.assertEqual(kdf['parameters']['block_size'].native, 8)
        self.assertEqual(kdf['parameters']['parallelization_parameter'].__class__, core.Integer)
        self.assertEqual(kdf['parameters']['parallelization_parameter'].native, 1)

    def test_rc2_parameters(self):
        with open(os.path.join(fixtures_dir, 'rc2_algo.der'), 'rb') as f:
            algo = algos.EncryptionAlgorithm.load(f.read())
        self.assertEqual(algo.encryption_block_size, 8)
        self.assertEqual(algo.encryption_iv, b'Q\xf1\xde\xc3\xc0l\xe8\xef')
        self.assertEqual(algo.encryption_cipher, 'rc2')
        self.assertEqual(algo.encryption_mode, 'cbc')
        self.assertEqual(algo.key_length, 16)

    def test_rc5_parameters(self):
        with open(os.path.join(fixtures_dir, 'rc5_algo.der'), 'rb') as f:
            algo = algos.EncryptionAlgorithm.load(f.read())
        self.assertEqual(algo.encryption_block_size, 16)
        self.assertEqual(algo.encryption_iv, b'abcd\0\1\2\3')
        self.assertEqual(algo.encryption_cipher, 'rc5')
        self.assertEqual(algo.encryption_mode, 'cbc')

        params = algo["parameters"]
        self.assertEqual(params["version"].native, 'v1-0')
        self.assertEqual(params["rounds"].native, 42)

    @staticmethod
    def sha3_algo_pairs():
        return [
            ('sha3_224_dsa', 'sha3_224', 'dsa'),
            ('sha3_256_dsa', 'sha3_256', 'dsa'),
            ('sha3_384_dsa', 'sha3_384', 'dsa'),
            ('sha3_512_dsa', 'sha3_512', 'dsa'),
            ('sha3_224_ecdsa', 'sha3_224', 'ecdsa'),
            ('sha3_256_ecdsa', 'sha3_256', 'ecdsa'),
            ('sha3_384_ecdsa', 'sha3_384', 'ecdsa'),
            ('sha3_512_ecdsa', 'sha3_512', 'ecdsa'),
            ('sha3_224_rsa', 'sha3_224', 'rsa'),
            ('sha3_256_rsa', 'sha3_256', 'rsa'),
            ('sha3_384_rsa', 'sha3_384', 'rsa'),
            ('sha3_512_rsa', 'sha3_512', 'rsa'),
        ]

    @data('sha3_algo_pairs', True)
    def sha3_algos_round_trip(self, digest_alg, sig_alg):
        alg_name = "%s_%s" % (digest_alg, sig_alg)
        original = algos.SignedDigestAlgorithm({'algorithm': alg_name})
        parsed = algos.SignedDigestAlgorithm.load(original.dump())
        self.assertEqual(parsed.hash_algo, digest_alg)
        self.assertEqual(
            parsed.signature_algo,
            'rsassa_pkcs1v15' if sig_alg == 'rsa' else sig_alg
        )
