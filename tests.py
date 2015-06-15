# coding: utf-8
from __future__ import unicode_literals

import sys
import unittest
import re

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes

from tests.test_cms import CMSTests  #pylint: disable=E0611
from tests.test_crl import CRLTests  #pylint: disable=E0611
from tests.test_keys import KeysTests  #pylint: disable=E0611
from tests.test_ocsp import OCSPTests  #pylint: disable=E0611
from tests.test_tsp import TSPTests  #pylint: disable=E0611
from tests.test_x509 import X509Tests  #pylint: disable=E0611
from tests.test_core import CoreTests  #pylint: disable=E0611


test_classes = [CMSTests, CRLTests, KeysTests, OCSPTests, TSPTests, X509Tests, CoreTests]


if __name__ == '__main__':
    matcher = None
    if len(sys.argv) > 1:
        matcher = sys.argv[1]
        if isinstance(matcher, byte_cls):
            matcher = matcher.decode('utf-8')

    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for test_class in test_classes:
        if matcher:
            names = loader.getTestCaseNames(test_class)
            for name in names:
                if re.search(matcher, name):
                    suite.addTest(test_class(name))
        else:
            suite.addTest(loader.loadTestsFromTestCase(test_class))
    unittest.TextTestRunner().run(suite)
