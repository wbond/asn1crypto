# coding: utf-8
from __future__ import unicode_literals

import unittest
import sys
import os

from asn1crypto import pem

from .unittest_data import DataDecorator, data

if sys.version_info < (3,):
    byte_cls = str
    num_cls = long  #pylint: disable=E0602
else:
    byte_cls = bytes
    num_cls = int


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


@DataDecorator
class PEMTests(unittest.TestCase):

    #pylint: disable=C0326
    @staticmethod
    def detect_files():
        return (
            ('keys/test-der.crt',       False),
            ('keys/test-inter-der.crt', False),
            ('keys/test-third-der.crt', False),
            ('keys/test.crt',           True),
            ('keys/test-inter.crt',     True),
            ('keys/test-third.crt',     True),
        )

    @data('detect_files')
    def detect(self, relative_path, is_pem):
        with open(os.path.join(fixtures_dir, relative_path), 'rb') as f:
            byte_string = f.read()
        self.assertEqual(is_pem, pem.detect(byte_string))

    #pylint: disable=C0326
    @staticmethod
    def unarmor_armor_files():
        return (
            ('keys/test.crt',        'keys/test-der.crt',         'CERTIFICATE',          {}),
            ('keys/test-inter.crt',  'keys/test-inter-der.crt',   'CERTIFICATE',          {}),
            ('keys/test-third.crt',  'keys/test-third-der.crt',   'CERTIFICATE',          {}),
            ('keys/test-pkcs8.key',  'keys/test-pkcs8-der.key',   'PRIVATE KEY',          {}),
            ('test-third.csr',       'test-third-der.csr',        'CERTIFICATE REQUEST',  {}),
            ('keys/test-aes128.key', 'keys/test-aes128-der.key',  'RSA PRIVATE KEY',      {'Proc-Type': '4,ENCRYPTED', 'DEK-Info': 'AES-128-CBC,01F6EE04516C912788B11BD7377626C2'}),
        )

    @data('unarmor_armor_files')
    def unarmor(self, relative_path, expected_bytes_filename, expected_type_name, expected_headers):
        with open(os.path.join(fixtures_dir, relative_path), 'rb') as f:
            byte_string = f.read()

        type_name, headers, decoded_bytes = pem.unarmor(byte_string)
        self.assertEqual(expected_type_name, type_name)
        self.assertEqual(expected_headers, headers)
        with open(os.path.join(fixtures_dir, expected_bytes_filename), 'rb') as f:
            expected_bytes = f.read()
            self.assertEqual(expected_bytes, decoded_bytes)

    @data('unarmor_armor_files')
    def armor(self, expected_bytes_filename, relative_path, type_name, headers):
        with open(os.path.join(fixtures_dir, relative_path), 'rb') as f:
            byte_string = f.read()

        encoded_bytes = pem.armor(type_name, byte_string, headers=headers)
        with open(os.path.join(fixtures_dir, expected_bytes_filename), 'rb') as f:
            expected_bytes = f.read()
            self.assertEqual(expected_bytes, encoded_bytes)
