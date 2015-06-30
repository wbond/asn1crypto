# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os

from pylint.lint import Run


cur_dir = os.path.dirname(__file__)
rc_path = os.path.join(cur_dir, '..', '.pylintrc')


def run():
    print('Running pylint...')

    files = []
    for root, _, filenames in os.walk('../asn1crypto/'):
        for filename in filenames:
            if not filename.endswith('.py'):
                continue
            files.append(os.path.join(root, filename))

    args = ['--rcfile=%s' % rc_path] + files

    Run(args)
