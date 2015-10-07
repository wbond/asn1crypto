# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os

from flake8.engine import get_style_guide


cur_dir = os.path.dirname(__file__)
config_file = os.path.join(cur_dir, '..', '.pep8')


def run():
    print('Running flake8...')

    flake8_style = get_style_guide(config_file=config_file)

    paths = []
    for root, _, filenames in os.walk('asn1crypto'):
        for filename in filenames:
            if not filename.endswith('.py'):
                continue
            paths.append(os.path.join(root, filename))
    flake8_style.check_files(paths)
