# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import sys
import unittest

if sys.version_info < (3, 5):
    import imp
else:
    import importlib
    import importlib.abc
    import importlib.util


__version__ = '1.5.1'
__version_info__ = (1, 5, 1)


if sys.version_info >= (3, 5):
    class ModCryptoMetaFinder(importlib.abc.MetaPathFinder):
        def setup(self):
            self.modules = {}
            sys.meta_path.insert(0, self)

        def add_module(self, package_name, package_path):
            if package_name not in self.modules:
                self.modules[package_name] = package_path

        def find_spec(self, fullname, path, target=None):
            name_parts = fullname.split('.')
            if name_parts[0] not in self.modules:
                return None

            package = name_parts[0]
            package_path = self.modules[package]

            fullpath = os.path.join(package_path, *name_parts[1:])

            if os.path.isdir(fullpath):
                filename = os.path.join(fullpath, "__init__.py")
                submodule_locations = [fullpath]
            else:
                filename = fullpath + ".py"
                submodule_locations = None

            if not os.path.exists(filename):
                return None

            return importlib.util.spec_from_file_location(
                fullname,
                filename,
                loader=None,
                submodule_search_locations=submodule_locations
            )


    CUSTOM_FINDER = ModCryptoMetaFinder()
    CUSTOM_FINDER.setup()


def _import_from(mod, path, mod_dir=None):
    """
    Imports a module from a specific path

    :param mod:
        A unicode string of the module name

    :param path:
        A unicode string to the directory containing the module

    :param mod_dir:
        If the sub directory of "path" is different than the "mod" name,
        pass the sub directory as a unicode string

    :return:
        None if not loaded, otherwise the module
    """

    if mod in sys.modules:
        return sys.modules[mod]

    if mod_dir is None:
        full_mod = mod
    else:
        full_mod = mod_dir.replace(os.sep, '.')

    if mod_dir is None:
        mod_dir = mod.replace('.', os.sep)

    if not os.path.exists(path):
        return None

    source_path = os.path.join(path, mod_dir, '__init__.py')
    if not os.path.exists(source_path):
        source_path = os.path.join(path, mod_dir + '.py')

    if not os.path.exists(source_path):
        return None

    if os.sep in mod_dir:
        append, mod_dir = mod_dir.rsplit(os.sep, 1)
        path = os.path.join(path, append)

    try:
        if sys.version_info < (3, 5):
            mod_info = imp.find_module(mod_dir, [path])
            return imp.load_module(mod, *mod_info)

        else:
            package = mod.split('.', 1)[0]
            package_dir = full_mod.split('.', 1)[0]
            package_path = os.path.join(path, package_dir)
            CUSTOM_FINDER.add_module(package, package_path)

            return importlib.import_module(mod)

    except ImportError:
        return None


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

    # If we are in a source folder and these tests aren't installed as a
    # package, we want to load asn1crypto from this source folder
    tests_dir = os.path.dirname(os.path.abspath(__file__))

    asn1crypto = None
    if os.path.basename(tests_dir) == 'tests':
        asn1crypto = _import_from(
            'asn1crypto',
            os.path.join(tests_dir, '..')
        )
    if asn1crypto is None:
        import asn1crypto

    if asn1crypto.__version__ != __version__:
        raise AssertionError(
            ('asn1crypto_tests version %s can not be run with ' % __version__) +
            ('asn1crypto version %s' % asn1crypto.__version__)
        )

    from .test_algos import AlgoTests
    from .test_cms import CMSTests
    from .test_crl import CRLTests
    from .test_csr import CSRTests
    from .test_init import InitTests
    from .test_keys import KeysTests
    from .test_ocsp import OCSPTests
    from .test_pem import PEMTests
    from .test_pkcs12 import PKCS12Tests
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
        InitTests,
        KeysTests,
        OCSPTests,
        PEMTests,
        PKCS12Tests,
        TSPTests,
        UtilTests,
        ParserTests,
        X509Tests,
        CoreTests
    ]
