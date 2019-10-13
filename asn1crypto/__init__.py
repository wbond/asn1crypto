# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from .version import __version__, __version_info__

__all__ = [
    '__version__',
    '__version_info__',
    'load_order',
]


def load_order():
    """
    Returns a list of the module and sub-module names for asn1crypto in
    dependency load order, for the sake of live reloading code

    :return:
        A list of unicode strings of module names, as they would appear in
        sys.modules, ordered by which module should be reloaded first
    """

    return [
        'asn1crypto._errors',  # none
        'asn1crypto._int',  # none
        'asn1crypto._ordereddict',  # none
        'asn1crypto._teletex_codec',  # none
        'asn1crypto._types',  # none
        'asn1crypto._inet',  # _errors, _types
        'asn1crypto._iri',  # _errors, _types
        'asn1crypto.version',  # none
        'asn1crypto.pem',  # _errors, _types
        'asn1crypto.util',  # _errors, _inet, _iri, _ordereddict, _types
        'asn1crypto.parser',  # _types, util
        'asn1crypto.core',  # _errors, _ordereddict, _teletex_codec, _types, parser, util
        'asn1crypto.algos',  # _errors, _int, core, util
        'asn1crypto.keys',  # _errors, _types, algos, core, util
        'asn1crypto.x509',  # _errors, _iri, _ordereddict, _types, algos, core, keys, util
        'asn1crypto.crl',  # algos, core, x509
        'asn1crypto.csr',  # algos, core, keys, x509
        'asn1crypto.ocsp',  # _errors, algos, core, crl, keys, x509
        'asn1crypto.cms',  # algos, core, crl, keys, ocsp, x509
        'asn1crypto.pdf',  # cms, core, crl, ocsp, x509
        'asn1crypto.pkcs12',  # algos, cms, core, keys, x509
        'asn1crypto.tsp',  # algos, cms, core, crl, x509
        'asn1crypto',  # version
    ]
