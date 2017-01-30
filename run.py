#!/usr/bin/env python
# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes


def show_usage():
    print('Usage: run.py (lint | tests [regex] | coverage | deps | ci | release)', file=sys.stderr)
    sys.exit(1)


def get_arg(num):
    if len(sys.argv) < num + 1:
        return None, num
    arg = sys.argv[num]
    if isinstance(arg, byte_cls):
        arg = arg.decode('utf-8')
    return arg, num + 1


if len(sys.argv) < 2 or len(sys.argv) > 3:
    show_usage()

task, next_arg = get_arg(1)

if task not in set(['lint', 'tests', 'coverage', 'deps', 'ci', 'release']):
    show_usage()

if task != 'tests' and len(sys.argv) == 3:
    show_usage()

params = []
if task == 'lint':
    from dev.lint import run

elif task == 'tests':
    from dev.tests import run
    matcher, next_arg = get_arg(next_arg)
    if matcher:
        params.append(matcher)

elif task == 'coverage':
    from dev.coverage import run

elif task == 'deps':
    from dev.deps import run

elif task == 'ci':
    from dev.ci import run

elif task == 'release':
    from dev.release import run

result = run(*params)
sys.exit(int(not result))
