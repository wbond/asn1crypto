# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys
import os

from . import build_root, package_name, package_root

if sys.version_info < (3, 5):
    import imp
else:
    import importlib
    import importlib.abc
    import importlib.util


if sys.version_info < (3,):
    getcwd = os.getcwdu
else:
    getcwd = os.getcwd


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


if sys.version_info >= (3, 5):
    CUSTOM_FINDER = ModCryptoMetaFinder()
    CUSTOM_FINDER.setup()


def _import_from(mod, path, mod_dir=None, allow_error=False):
    """
    Imports a module from a specific path

    :param mod:
        A unicode string of the module name

    :param path:
        A unicode string to the directory containing the module

    :param mod_dir:
        If the sub directory of "path" is different than the "mod" name,
        pass the sub directory as a unicode string

    :param allow_error:
        If an ImportError should be raised when the module can't be imported

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
        if allow_error:
            raise
        return None


def _preload(require_oscrypto, print_info):
    """
    Preloads asn1crypto and optionally oscrypto from a local source checkout,
    or from a normal install

    :param require_oscrypto:
        A bool if oscrypto needs to be preloaded

    :param print_info:
        A bool if info about asn1crypto and oscrypto should be printed
    """

    if print_info:
        print('Working dir: ' + getcwd())
        print('Python ' + sys.version.replace('\n', ''))

    asn1crypto = None
    oscrypto = None

    if require_oscrypto:
        # Some CI services don't use the package name for the dir
        if package_name == 'oscrypto':
            oscrypto_dir = package_root
        else:
            oscrypto_dir = os.path.join(build_root, 'oscrypto')
        oscrypto_tests = None
        if os.path.exists(oscrypto_dir):
            oscrypto_tests = _import_from('oscrypto_tests', oscrypto_dir, 'tests')
        if oscrypto_tests is None:
            import oscrypto_tests
        asn1crypto, oscrypto = oscrypto_tests.local_oscrypto()

    else:
        if package_name == 'asn1crypto':
            asn1crypto_dir = package_root
        else:
            asn1crypto_dir = os.path.join(build_root, 'asn1crypto')
        if os.path.exists(asn1crypto_dir):
            asn1crypto = _import_from('asn1crypto', asn1crypto_dir)
        if asn1crypto is None:
            import asn1crypto

    if print_info:
        print(
            '\nasn1crypto: %s, %s' % (
                asn1crypto.__version__,
                os.path.dirname(asn1crypto.__file__)
            )
        )
        if require_oscrypto:
            backend = oscrypto.backend()
            if backend == 'openssl':
                from oscrypto._openssl._libcrypto import libcrypto_version
                backend = '%s (%s)' % (backend, libcrypto_version)

            print(
                'oscrypto: %s, %s backend, %s' % (
                    oscrypto.__version__,
                    backend,
                    os.path.dirname(oscrypto.__file__)
                )
            )
