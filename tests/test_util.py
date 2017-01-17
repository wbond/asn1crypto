# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import sys
import os
from datetime import date, datetime, time

from asn1crypto import util

from .unittest_data import data_decorator, data
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

    def test_extended_date_strftime(self):
        def do_run():
            self.assertEqual('0000-01-01', util.extended_date(0, 1, 1).strftime('%Y-%m-%d'))
            self.assertEqual('Sat Saturday Jan January', util.extended_date(0, 1, 1).strftime('%a %A %b %B'))
            self.assertEqual('Tue Tuesday Feb February 29', util.extended_date(0, 2, 29).strftime('%a %A %b %B %d'))
            self.assertEqual('Sat Jan  1 00:00:00 0000', util.extended_date(0, 1, 1).strftime('%c'))
            self.assertEqual('01/01/00', util.extended_date(0, 1, 1).strftime('%x'))
        # Python 2 doesn't allow strftime on years before 1900
        if py2:
            with self.assertRaises(ValueError):
                do_run()
        else:
            do_run()

    def test_extended_datetime_strftime(self):
        def do_run():
            self.assertEqual('0000-01-01 00:00:00', util.extended_datetime(0, 1, 1).strftime('%Y-%m-%d %H:%M:%S'))
            self.assertEqual('Sat Saturday Jan January', util.extended_datetime(0, 1, 1).strftime('%a %A %b %B'))
            self.assertEqual('Tue Tuesday Feb February 29', util.extended_datetime(0, 2, 29).strftime('%a %A %b %B %d'))
            self.assertEqual('Sat Jan  1 00:00:00 0000', util.extended_datetime(0, 1, 1).strftime('%c'))
            self.assertEqual('01/01/00', util.extended_datetime(0, 1, 1).strftime('%x'))
        # Python 2 doesn't allow strftime on years before 1900
        if py2:
            with self.assertRaises(ValueError):
                do_run()
        else:
            do_run()

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
