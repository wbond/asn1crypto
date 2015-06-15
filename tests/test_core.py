# coding: utf-8
from __future__ import unicode_literals

import unittest
import os

from asn1crypto import core

from .unittest_data import DataDecorator, data


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


@DataDecorator
class CoreTests(unittest.TestCase):

    #pylint: disable=C0326
    @staticmethod
    def type_info():
        return (
            ('universal/object_identifier.der',    core.ObjectIdentifier,    '1.2.840.113549.1.1.1'),
        )

    @data('type_info')
    def parse_universal_type(self, input_filename, type_class, native):
        with open(os.path.join(fixtures_dir, input_filename), 'rb') as f:
            der = f.read()
            parsed = type_class.load(der)

        self.assertEqual(native, parsed.native)
        self.assertEqual(der, parsed.dump(force=True))
