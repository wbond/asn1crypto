# coding: utf-8
from __future__ import unicode_literals

import os

from pylint.lint import Run


cur_dir = os.path.dirname(__file__)
rc_path = os.path.join(cur_dir, './.pylintrc')

print('Running pylint...')

files = [
    '__init__.py',
    'algos.py',
    'cms.py',
    'core.py',
    'crl.py',
    'keys.py',
    'ocsp.py',
    'pdf.py',
    'pkcs12.py',
    'teletex_codec.py',
    'tsa.py',
    'x509.py',
]

args = ['--rcfile=%s' % rc_path]
args += ['asn1crypto/' + f for f in files]

Run(args)
