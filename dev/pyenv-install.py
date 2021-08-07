# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import subprocess
import sys


run_args = [
    {
        'name': 'version',
        'kwarg': 'version',
    },
]


def _write_env(env, key, value):
    sys.stdout.write("%s: %s\n" % (key, value))
    sys.stdout.flush()
    if sys.version_info < (3,):
        env[key.encode('utf-8')] = value.encode('utf-8')
    else:
        env[key] = value


def run(version=None):
    """
    Installs a version of Python on Mac using pyenv

    :return:
        A bool - if Python was installed successfully
    """

    if sys.platform == 'win32':
        raise ValueError('pyenv-install is not designed for Windows')

    if version not in set(['2.6', '3.3']):
        raise ValueError('Invalid version: %r' % version)

    python_path = os.path.expanduser('~/.pyenv/versions/%s/bin' % version)
    if os.path.exists(os.path.join(python_path, 'python')):
        print(python_path)
        return True

    stdout = ""
    stderr = ""

    proc = subprocess.Popen(
        'command -v pyenv',
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    proc.communicate()
    if proc.returncode != 0:
        proc = subprocess.Popen(
            ['brew', 'install', 'pyenv'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        so, se = proc.communicate()
        stdout += so.decode('utf-8')
        stderr += se.decode('utf-8')
        if proc.returncode != 0:
            print(stdout)
            print(stderr, file=sys.stderr)
            return False

    pyenv_script = './%s' % version
    try:
        with open(pyenv_script, 'wb') as f:
            if version == '2.6':
                contents = '#require_gcc\n' \
                    'install_package "openssl-1.0.2k" "https://www.openssl.org/source/old/1.0.2/openssl-1.0.2k.tar.gz' \
                    '#6b3977c61f2aedf0f96367dcfb5c6e578cf37e7b8d913b4ecb6643c3cb88d8c0" mac_openssl\n' \
                    'install_package "readline-8.0" "https://ftpmirror.gnu.org/readline/readline-8.0.tar.gz' \
                    '#e339f51971478d369f8a053a330a190781acb9864cf4c541060f12078948e461" mac_readline' \
                    ' --if has_broken_mac_readline\n' \
                    'install_package "Python-2.6.9" "https://www.python.org/ftp/python/2.6.9/Python-2.6.9.tgz' \
                    '#7277b1285d8a82f374ef6ebaac85b003266f7939b3f2a24a3af52f9523ac94db" standard verify_py26'
            elif version == '3.3':
                contents = '#require_gcc\n' \
                    'install_package "openssl-1.0.2k" "https://www.openssl.org/source/old/1.0.2/openssl-1.0.2k.tar.gz' \
                    '#6b3977c61f2aedf0f96367dcfb5c6e578cf37e7b8d913b4ecb6643c3cb88d8c0" mac_openssl\n' \
                    'install_package "readline-8.0" "https://ftpmirror.gnu.org/readline/readline-8.0.tar.gz' \
                    '#e339f51971478d369f8a053a330a190781acb9864cf4c541060f12078948e461" mac_readline' \
                    ' --if has_broken_mac_readline\n' \
                    'install_package "Python-3.3.7" "https://www.python.org/ftp/python/3.3.7/Python-3.3.7.tar.xz' \
                    '#85f60c327501c36bc18c33370c14d472801e6af2f901dafbba056f61685429fe" standard verify_py33'
            f.write(contents.encode('utf-8'))

        args = ['pyenv', 'install', pyenv_script]
        stdin = None
        stdin_contents = None
        env = os.environ.copy()

        if version == '2.6':
            _write_env(env, 'PYTHON_CONFIGURE_OPTS', '--enable-ipv6')
            stdin = subprocess.PIPE
            stdin_contents = '--- configure  2021-08-05 20:17:26.000000000 -0400\n' \
                '+++ configure   2021-08-05 20:21:30.000000000 -0400\n' \
                '@@ -10300,17 +10300,8 @@\n' \
                ' rm -f core conftest.err conftest.$ac_objext \\\n' \
                '     conftest$ac_exeext conftest.$ac_ext\n' \
                ' \n' \
                '-if test "$buggygetaddrinfo" = "yes"; then\n' \
                '-\tif test "$ipv6" = "yes"; then\n' \
                '-\t\techo \'Fatal: You must get working getaddrinfo() function.\'\n' \
                '-\t\techo \'       or you can specify "--disable-ipv6"\'.\n' \
                '-\t\texit 1\n' \
                '-\tfi\n' \
                '-else\n' \
                '-\n' \
                ' $as_echo "#define HAVE_GETADDRINFO 1" >>confdefs.h\n' \
                ' \n' \
                '-fi\n' \
                ' for ac_func in getnameinfo\n' \
                ' do :\n' \
                '   ac_fn_c_check_func "$LINENO" "getnameinfo" "ac_cv_func_getnameinfo"'
            stdin_contents = stdin_contents.encode('ascii')
            args.append('--patch')

        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=stdin,
            env=env
        )
        so, se = proc.communicate(stdin_contents)
        stdout += so.decode('utf-8')
        stderr += se.decode('utf-8')

        if proc.returncode != 0:
            print(stdout)
            print(stderr, file=sys.stderr)
            return False

    finally:
        if os.path.exists(pyenv_script):
            os.unlink(pyenv_script)

    print(python_path)
    return True
