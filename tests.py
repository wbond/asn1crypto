# coding: utf-8
from __future__ import unicode_literals

import unittest

from tests.test_cms import CMSTests  #pylint: disable=E0611,W0611
from tests.test_crl import CRLTests  #pylint: disable=E0611,W0611
from tests.test_keys import KeysTests  #pylint: disable=E0611,W0611
from tests.test_ocsp import OCSPTests  #pylint: disable=E0611,W0611
from tests.test_tsa import TSATests  #pylint: disable=E0611,W0611
from tests.test_x509 import X509Tests  #pylint: disable=E0611,W0611


if __name__ == '__main__':
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for test_class in [CMSTests, CRLTests, KeysTests, OCSPTests, TSATests, X509Tests]:
        suite.addTest(loader.loadTestsFromTestCase(test_class))
    unittest.TextTestRunner().run(suite)
