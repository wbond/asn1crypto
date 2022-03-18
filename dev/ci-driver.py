# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import platform
import sys
import subprocess


run_args = [
    {
        'name': 'cffi',
        'kwarg': 'cffi',
    },
    {
        'name': 'openssl',
        'kwarg': 'openssl',
    },
    {
        'name': 'winlegacy',
        'kwarg': 'winlegacy',
    },
]


def _write_env(env, key, value):
    sys.stdout.write("%s: %s\n" % (key, value))
    sys.stdout.flush()
    if sys.version_info < (3,):
        env[key.encode('utf-8')] = value.encode('utf-8')
    else:
        env[key] = value


def run(**_):
    """
    Runs CI, setting various env vars

    :return:
        A bool - if the CI ran successfully
    """

    env = os.environ.copy()
    options = set(sys.argv[2:])

    newline = False
    if 'cffi' not in options:
        _write_env(env, 'OSCRYPTO_USE_CTYPES', 'true')
        newline = True
    if 'openssl' in options and sys.platform == 'darwin':
        mac_version_info = tuple(map(int, platform.mac_ver()[0].split('.')[:2]))
        if mac_version_info < (10, 15):
            _write_env(env, 'OSCRYPTO_USE_OPENSSL', '/usr/lib/libcrypto.dylib,/usr/lib/libssl.dylib')
        else:
            _write_env(env, 'OSCRYPTO_USE_OPENSSL', '/usr/lib/libcrypto.35.dylib,/usr/lib/libssl.35.dylib')
        newline = True
    if 'openssl3' in options and sys.platform == 'darwin':
        _write_env(
            env,
            'OSCRYPTO_USE_OPENSSL',
            '/usr/local/opt/openssl@3/lib/libcrypto.dylib,/usr/local/opt/openssl@3/lib/libssl.dylib'
        )
    if 'winlegacy' in options:
        _write_env(env, 'OSCRYPTO_USE_WINLEGACY', 'true')
        newline = True

    if newline:
        sys.stdout.write("\n")

    proc = subprocess.Popen(
        [
            sys.executable,
            'run.py',
            'ci',
        ],
        env=env
    )
    proc.communicate()
    return proc.returncode == 0
