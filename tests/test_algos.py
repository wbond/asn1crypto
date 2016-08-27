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
