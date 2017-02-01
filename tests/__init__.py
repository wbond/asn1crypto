# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import imp
import os
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

    # Make sure the module is loaded from this source folder
    module_name = 'asn1crypto'
    src_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
    module_info = imp.find_module(module_name, [src_dir])
    imp.load_module(module_name, *module_info)

    from .test_algos import AlgoTests
    from .test_cms import CMSTests
    from .test_crl import CRLTests
    from .test_csr import CSRTests
    from .test_keys import KeysTests
    from .test_ocsp import OCSPTests
    from .test_pem import PEMTests
    from .test_tsp import TSPTests
    from .test_x509 import X509Tests
    from .test_util import UtilTests
    from .test_parser import ParserTests
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
        UtilTests,
        ParserTests,
        X509Tests,
        CoreTests
    ]
