# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import coverage


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

    cov.stop()
    cov.save()

    cov.report(show_missing=False)
    if write_xml:
        cov.xml_report()

    return result
