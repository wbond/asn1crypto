# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import sys
import os
from datetime import date, datetime, time

from asn1crypto import util

from .unittest_data import data_decorator
from ._unittest_compat import patch

patch()

if sys.version_info < (3,):
    py2 = True
    byte_cls = str
    num_cls = long  # noqa
else:
    py2 = False
    byte_cls = bytes
    num_cls = int


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')
utc = util.timezone.utc


@data_decorator
class UtilTests(unittest.TestCase):

    def test_int_to_bytes(self):
        self.assertEqual(util.int_to_bytes(0, False, 0), b'')
        self.assertEqual(util.int_to_bytes(0, False), b'\x00')
        self.assertEqual(util.int_to_bytes(0, False, 3), b'\x00\x00\x00')
        self.assertEqual(util.int_to_bytes(0, True, 0), b'')
        self.assertEqual(util.int_to_bytes(0, True), b'\x00')
        self.assertEqual(util.int_to_bytes(0, True, 3), b'\x00\x00\x00')

        self.assertEqual(util.int_to_bytes(128, False), b'\x80')
        self.assertEqual(util.int_to_bytes(128, False, 3), b'\x00\x00\x80')
        self.assertEqual(util.int_to_bytes(-128, True), b'\x80')
        self.assertEqual(util.int_to_bytes(-128, True, 3), b'\xff\xff\x80')

        self.assertEqual(util.int_to_bytes(255, False), b'\xff')
        self.assertEqual(util.int_to_bytes(255, False, 3), b'\x00\x00\xff')
        self.assertEqual(util.int_to_bytes(-1, True), b'\xff')
        self.assertEqual(util.int_to_bytes(-1, True, 3), b'\xff\xff\xff')

        self.assertEqual(util.int_to_bytes(12345678, False), b'\xbc\x61\x4e')
        self.assertEqual(util.int_to_bytes(12345678, False, 3), b'\xbc\x61\x4e')
        self.assertEqual(util.int_to_bytes(12345678, False, 5), b'\x00\x00\xbc\x61\x4e')
        self.assertEqual(util.int_to_bytes(12345678 - 2 ** 24, True), b'\xbc\x61\x4e')
        self.assertEqual(util.int_to_bytes(12345678 - 2 ** 24, True, 3), b'\xbc\x61\x4e')
        self.assertEqual(util.int_to_bytes(12345678 - 2 ** 24, True, 5), b'\xff\xff\xbc\x61\x4e')

        with self.assertRaises(OverflowError):
            util.int_to_bytes(123456789, width=3)
        with self.assertRaises(OverflowError):
            util.int_to_bytes(50000, signed=True, width=2)

    def test_int_from_bytes(self):
        self.assertEqual(util.int_from_bytes(b'', False), 0)
        self.assertEqual(util.int_from_bytes(b'', True), 0)
        self.assertEqual(util.int_from_bytes(b'\x00', False), 0)
        self.assertEqual(util.int_from_bytes(b'\x00', True), 0)
        self.assertEqual(util.int_from_bytes(b'\x80', False), 128)
        self.assertEqual(util.int_from_bytes(b'\x80', True), -128)
        self.assertEqual(util.int_from_bytes(b'\xff', False), 255)
        self.assertEqual(util.int_from_bytes(b'\xff', True), -1)
        self.assertEqual(util.int_from_bytes(b'\xbc\x61\x4e', False), 12345678)
        self.assertEqual(util.int_from_bytes(b'\xbc\x61\x4e', True), 12345678 - 2 ** 24)

    def test_int_fromto_bytes(self):
        for i in range(-300, 301):
            self.assertEqual(i, util.int_from_bytes(util.int_to_bytes(i, True), True))
        for i in range(0, 301):
            self.assertEqual(i, util.int_from_bytes(util.int_to_bytes(i, False), False))

    def test_extended_date_strftime(self):
        self.assertEqual('0000-01-01', util.extended_date(0, 1, 1).strftime('%Y-%m-%d'))
        self.assertEqual('Sat Saturday Jan January', util.extended_date(0, 1, 1).strftime('%a %A %b %B'))
        self.assertEqual('Tue Tuesday Feb February 29', util.extended_date(0, 2, 29).strftime('%a %A %b %B %d'))
        if sys.platform == 'win32' and sys.version_info < (3, 5):
            self.assertEqual('01/01/00 00:00:00', util.extended_date(0, 1, 1).strftime('%c'))
        else:
            self.assertEqual('Sat Jan  1 00:00:00 0000', util.extended_date(0, 1, 1).strftime('%c'))
        self.assertEqual('01/01/00', util.extended_date(0, 1, 1).strftime('%x'))

    def test_extended_datetime_strftime(self):
        self.assertEqual('0000-01-01 00:00:00', util.extended_datetime(0, 1, 1).strftime('%Y-%m-%d %H:%M:%S'))
        self.assertEqual('Sat Saturday Jan January', util.extended_datetime(0, 1, 1).strftime('%a %A %b %B'))
        self.assertEqual('Tue Tuesday Feb February 29', util.extended_datetime(0, 2, 29).strftime('%a %A %b %B %d'))
        if sys.platform == 'win32' and sys.version_info < (3, 5):
            self.assertEqual('01/01/00 00:00:00', util.extended_datetime(0, 1, 1).strftime('%c'))
        else:
            self.assertEqual('Sat Jan  1 00:00:00 0000', util.extended_datetime(0, 1, 1).strftime('%c'))
        self.assertEqual('01/01/00', util.extended_datetime(0, 1, 1).strftime('%x'))

    def test_extended_date_compare(self):
        self.assertTrue(util.extended_date(0, 1, 1) < date(1, 1, 1))
        self.assertTrue(util.extended_date(0, 1, 1) <= date(1, 1, 1))
        self.assertTrue(util.extended_date(0, 1, 1) != date(1, 1, 1))
        self.assertFalse(util.extended_date(0, 1, 1) == date(1, 1, 1))
        self.assertFalse(util.extended_date(0, 1, 1) >= date(1, 1, 1))
        self.assertFalse(util.extended_date(0, 1, 1) > date(1, 1, 1))

        self.assertFalse(util.extended_date(0, 1, 1) < util.extended_date(0, 1, 1))
        self.assertTrue(util.extended_date(0, 1, 1) <= util.extended_date(0, 1, 1))
        self.assertFalse(util.extended_date(0, 1, 1) != util.extended_date(0, 1, 1))
        self.assertTrue(util.extended_date(0, 1, 1) == util.extended_date(0, 1, 1))
        self.assertTrue(util.extended_date(0, 1, 1) >= util.extended_date(0, 1, 1))
        self.assertFalse(util.extended_date(0, 1, 1) > util.extended_date(0, 1, 1))

        self.assertTrue(util.extended_date(0, 1, 1) < util.extended_date(0, 1, 2))
        self.assertTrue(util.extended_date(0, 1, 1) <= util.extended_date(0, 1, 2))
        self.assertTrue(util.extended_date(0, 1, 1) != util.extended_date(0, 1, 2))
        self.assertFalse(util.extended_date(0, 1, 1) == util.extended_date(0, 1, 2))
        self.assertFalse(util.extended_date(0, 1, 1) >= util.extended_date(0, 1, 2))
        self.assertFalse(util.extended_date(0, 1, 1) > util.extended_date(0, 1, 2))

        self.assertFalse(util.extended_date(0, 1, 3) < util.extended_date(0, 1, 2))
        self.assertFalse(util.extended_date(0, 1, 3) <= util.extended_date(0, 1, 2))
        self.assertTrue(util.extended_date(0, 1, 3) != util.extended_date(0, 1, 2))
        self.assertFalse(util.extended_date(0, 1, 3) == util.extended_date(0, 1, 2))
        self.assertTrue(util.extended_date(0, 1, 3) >= util.extended_date(0, 1, 2))
        self.assertTrue(util.extended_date(0, 1, 3) > util.extended_date(0, 1, 2))

    def test_extended_datetime_compare(self):
        self.assertTrue(util.extended_datetime(0, 1, 1) < datetime(1, 1, 1))
        self.assertTrue(util.extended_datetime(0, 1, 1) <= datetime(1, 1, 1))
        self.assertTrue(util.extended_datetime(0, 1, 1) != datetime(1, 1, 1))
        self.assertFalse(util.extended_datetime(0, 1, 1) == datetime(1, 1, 1))
        self.assertFalse(util.extended_datetime(0, 1, 1) >= datetime(1, 1, 1))
        self.assertFalse(util.extended_datetime(0, 1, 1) > datetime(1, 1, 1))

        self.assertFalse(util.extended_datetime(0, 1, 1) < util.extended_datetime(0, 1, 1))
        self.assertTrue(util.extended_datetime(0, 1, 1) <= util.extended_datetime(0, 1, 1))
        self.assertFalse(util.extended_datetime(0, 1, 1) != util.extended_datetime(0, 1, 1))
        self.assertTrue(util.extended_datetime(0, 1, 1) == util.extended_datetime(0, 1, 1))
        self.assertTrue(util.extended_datetime(0, 1, 1) >= util.extended_datetime(0, 1, 1))
        self.assertFalse(util.extended_datetime(0, 1, 1) > util.extended_datetime(0, 1, 1))

        self.assertTrue(util.extended_datetime(0, 1, 1) < util.extended_datetime(0, 1, 2))
        self.assertTrue(util.extended_datetime(0, 1, 1) <= util.extended_datetime(0, 1, 2))
        self.assertTrue(util.extended_datetime(0, 1, 1) != util.extended_datetime(0, 1, 2))
        self.assertFalse(util.extended_datetime(0, 1, 1) == util.extended_datetime(0, 1, 2))
        self.assertFalse(util.extended_datetime(0, 1, 1) >= util.extended_datetime(0, 1, 2))
        self.assertFalse(util.extended_datetime(0, 1, 1) > util.extended_datetime(0, 1, 2))

        self.assertFalse(util.extended_datetime(0, 1, 3) < util.extended_datetime(0, 1, 2))
        self.assertFalse(util.extended_datetime(0, 1, 3) <= util.extended_datetime(0, 1, 2))
        self.assertTrue(util.extended_datetime(0, 1, 3) != util.extended_datetime(0, 1, 2))
        self.assertFalse(util.extended_datetime(0, 1, 3) == util.extended_datetime(0, 1, 2))
        self.assertTrue(util.extended_datetime(0, 1, 3) >= util.extended_datetime(0, 1, 2))
        self.assertTrue(util.extended_datetime(0, 1, 3) > util.extended_datetime(0, 1, 2))

    def test_extended_datetime_compare_tzinfo(self):
        with self.assertRaises(TypeError):
            self.assertTrue(util.extended_datetime(0, 1, 1, tzinfo=utc) < datetime(1, 1, 1))
        with self.assertRaises(TypeError):
            self.assertTrue(util.extended_datetime(0, 1, 1) < datetime(1, 1, 1, tzinfo=utc))

    def test_extended_datetime_date_time(self):
        self.assertEqual(util.extended_date(0, 1, 1), util.extended_datetime(0, 1, 1).date())
        self.assertEqual(util.extended_date(0, 2, 29), util.extended_datetime(0, 2, 29).date())
        self.assertEqual(time(0, 0, 0), util.extended_datetime(0, 1, 1).time())

    def test_iri_to_uri(self):
        self.assertEqual(
            b'ldap://ldap.e-szigno.hu/CN=Microsec%20e-Szigno%20Root%20CA,OU=e-Szigno%20CA,'
            b'O=Microsec%20Ltd.,L=Budapest,C=HU?certificateRevocationList;binary',
            util.iri_to_uri(
                'ldap://ldap.e-szigno.hu/CN=Microsec e-Szigno Root CA,'
                'OU=e-Szigno CA,O=Microsec Ltd.,L=Budapest,C=HU?certificateRevocationList;binary'
            )
        )
        self.assertEqual(
            b'ldap://directory.d-trust.net/CN=D-TRUST%20Root%20Class%203%20CA%202%202009,'
            b'O=D-Trust%20GmbH,C=DE?certificaterevocationlist',
            util.iri_to_uri(
                'ldap://directory.d-trust.net/CN=D-TRUST Root Class 3 CA 2 2009,'
                'O=D-Trust GmbH,C=DE?certificaterevocationlist'
            )
        )
        self.assertEqual(
            b'ldap://directory.d-trust.net/CN=D-TRUST%20Root%20Class%203%20CA%202%20EV%202009,'
            b'O=D-Trust%20GmbH,C=DE?certificaterevocationlist',
            util.iri_to_uri(
                'ldap://directory.d-trust.net/CN=D-TRUST Root Class 3 CA 2 EV 2009,'
                'O=D-Trust GmbH,C=DE?certificaterevocationlist'
            )
        )
