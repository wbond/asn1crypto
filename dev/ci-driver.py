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


# DigiCert Global Root CA.  This root has been removed from some newer Linux
# distributions (e.g. Ubuntu 22.04) but is still needed by the test fixtures in
# sibling modularcrypto repos.  It is installed into the system trust store so
# that oscrypto's trust_list.get_list() can find it.
_digicert_global_root_ca_pem = """\
-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB
CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97
nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt
43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P
T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4
gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO
BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR
TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw
DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr
hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg
06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF
PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls
YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk
CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=
-----END CERTIFICATE-----
"""


def _is_ubuntu():
    """
    Determines if the current operating system is Ubuntu

    :return:
        A bool - if the OS is Ubuntu
    """

    if sys.platform != 'linux':
        return False
    try:
        with open('/etc/os-release', 'r') as f:
            contents = f.read()
    except (IOError, OSError):
        return False
    for line in contents.splitlines():
        parts = line.split('=', 1)
        if len(parts) == 2 and parts[0] in ('ID', 'ID_LIKE'):
            values = parts[1].strip().strip('"').split()
            if 'ubuntu' in values:
                return True
    return False


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

    # Some newer Ubuntu releases (e.g. 22.04) have removed the DigiCert
    # Global Root CA that the test fixtures still rely on.  The PEM is
    # written to the system CA directory and registered via
    # update-ca-certificates so that oscrypto's trust_list.get_list() can
    # find it.
    if _is_ubuntu():
        print('Installing DigiCert Global Root CA for Ubuntu\n')
        sys.stdout.flush()
        ca_dir = '/usr/local/share/ca-certificates'
        ca_path = os.path.join(ca_dir, 'digicert-global-root-ca.crt')
        try:
            if not os.path.exists(ca_dir):
                os.makedirs(ca_dir)
            with open(ca_path, 'w') as f:
                f.write(_digicert_global_root_ca_pem)
        except (IOError, OSError) as e:
            print('Unable to write CA file %s: %s' % (ca_path, e))
        else:
            subprocess.call(['update-ca-certificates'])

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
