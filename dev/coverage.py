# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import coverage
import imp
import os
import unittest


def run(write_xml=False):
    """
    Runs the tests while measuring coverage

    :return:
        A bool - if the tests ran successfully
    """

    cov = coverage.Coverage(include='asn1crypto/*.py')
    cov.start()

    from .tests import run as run_tests
    result = run_tests()
    print()

    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for package_name in ['oscrypto', 'certbuilder', 'certvalidator', 'crlbuilder', 'csrbuild', 'ocspbuilder']:
        for test_class in _load_package_tests(package_name):
            suite.addTest(loader.loadTestsFromTestCase(test_class))

    if suite.countTestCases() > 0:
        print('Running tests from other modularcrypto packages')
        other_result = unittest.TextTestRunner(verbosity=1).run(suite).wasSuccessful()
        print()
    else:
        other_result = True

    cov.stop()
    cov.save()

    cov.report(show_missing=False)
    if write_xml:
        cov.xml_report()

    return result and other_result


def _load_package_tests(name):
    """
    Load the test classes from another modularcrypto package

    :param name:
        A unicode string of the other package name

    :return:
        A list of unittest.TestCase classes of the tests for the package
    """

    package_dir = os.path.join('..', name)
    if not os.path.exists(package_dir):
        return []

    tests_module_info = imp.find_module('tests', [package_dir])
    tests_module = imp.load_module('%s.tests' % name, *tests_module_info)
    return tests_module.test_classes()
