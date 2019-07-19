# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import unittest
import re
import sys

from tests import test_classes
import asn1crypto


def run(matcher=None, ci=False):
    """
    Runs the tests

    :param matcher:
        A unicode string containing a regular expression to use to filter test
        names by. A value of None will cause no filtering.

    :return:
        A bool - if the tests succeeded
    """

    if not ci:
        print('Python ' + sys.version.replace('\n', ''))
        print('\nasn1crypto: %s, %s\n' % (asn1crypto.__version__, os.path.dirname(asn1crypto.__file__)))

    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for test_class in test_classes():
        if matcher:
            names = loader.getTestCaseNames(test_class)
            for name in names:
                if re.search(matcher, name):
                    suite.addTest(test_class(name))
        else:
            suite.addTest(loader.loadTestsFromTestCase(test_class))
    verbosity = 2 if matcher else 1
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=verbosity).run(suite)
    return result.wasSuccessful()
