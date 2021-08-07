# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import sys
import os

from asn1crypto import algos, core
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
