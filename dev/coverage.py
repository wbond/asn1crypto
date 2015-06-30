# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import coverage



def run():
    cov = coverage.Coverage(include='asn1crypto/*.py')
    cov.start()

    from .tests import run as run_tests
    run_tests()
    print()

    cov.stop()
    cov.save()

    cov.report(show_missing=False)
