# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest


def make_suite():
    """
    Constructs a unittest.TestSuite() of all tests for the package. For use
    with setuptools.

    :return:
        A unittest.TestSuite() object
    """

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for test_class in test_classes():
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    return suite


def test_classes():
    """
    Returns a list of unittest.TestCase classes for the package

    :return:
        A list of unittest.TestCase classes
    """

    from .test_algos import AlgoTests
    from .test_cms import CMSTests
    from .test_crl import CRLTests
    from .test_csr import CSRTests
    from .test_keys import KeysTests
    from .test_ocsp import OCSPTests
    from .test_pem import PEMTests
    from .test_tsp import TSPTests
    from .test_x509 import X509Tests
    from .test_core import CoreTests

    return [
        AlgoTests,
        CMSTests,
        CRLTests,
        CSRTests,
        KeysTests,
        OCSPTests,
        PEMTests,
        TSPTests,
        X509Tests,
        CoreTests
    ]
