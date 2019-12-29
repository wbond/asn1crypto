# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os


package_name = "asn1crypto"

other_packages = [
    "oscrypto",
    "certbuilder",
    "certvalidator",
    "crlbuilder",
    "csrbuilder",
    "ocspbuilder"
]

task_keyword_args = []

requires_oscrypto = False
has_tests_package = True

package_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
build_root = os.path.abspath(os.path.join(package_root, '..'))

md_source_map = {}

definition_replacements = {}
