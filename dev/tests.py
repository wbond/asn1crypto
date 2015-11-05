# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import re

from tests.test_cms import CMSTests
from tests.test_crl import CRLTests
from tests.test_csr import CSRTests
from tests.test_keys import KeysTests
from tests.test_ocsp import OCSPTests
from tests.test_pem import PEMTests
from tests.test_tsp import TSPTests
from tests.test_x509 import X509Tests
from tests.test_core import CoreTests


test_classes = [CMSTests, CRLTests, CSRTests, KeysTests, OCSPTests, PEMTests, TSPTests, X509Tests, CoreTests]


def run(matcher=None):
    """
    Runs the tests

    :param matcher:
        A unicode string containing a regular expression to use to filter test
        names by. A value of None will cause no filtering.

    :return:
        A bool - if the tests succeeded
    """

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
    verbosity = 2 if matcher else 1
    result = unittest.TextTestRunner(verbosity=verbosity).run(suite)
    return result.wasSuccessful()
