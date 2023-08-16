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


def _shell_subproc(args):
    proc = subprocess.Popen(
        args,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    so, se = proc.communicate()
    stdout = so.decode('utf-8')
    stderr = se.decode('utf-8')
    return proc.returncode == 0, stdout, stderr


def run(version=None):
    """
    Installs a version of Python on Mac using pyenv

    :return:
        A bool - if Python was installed successfully
    """

    if sys.platform == 'win32':
        raise ValueError('pyenv-install is not designed for Windows')

    if version not in set(['2.6', '2.7', '3.3']):
        raise ValueError('Invalid version: %r' % version)

    python_path = os.path.expanduser('~/.pyenv/versions/%s/bin' % version)
    if os.path.exists(os.path.join(python_path, 'python')):
        print(python_path)
        return True

    stdout = ""
    stderr = ""

    has_pyenv, _, _ = _shell_subproc('command -v pyenv')
    if not has_pyenv:
        success, stdout, stderr = _shell_subproc('brew install pyenv')
        if not success:
            print(stdout)
            print(stderr, file=sys.stderr)
            return False

    has_zlib, _, _ = _shell_subproc('brew list zlib')
    if not has_zlib:
        success, stdout, stderr = _shell_subproc('brew install zlib')
        if not success:
            print(stdout)
            print(stderr, file=sys.stderr)
            return False

    success, stdout, stderr = _shell_subproc('brew --prefix zlib')
    if not success:
        print(stdout)
        print(stderr, file=sys.stderr)
        return False
    zlib_prefix = stdout.strip()

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
            elif version == '2.7':
                contents = '#require_gcc\n' \
                    'export PYTHON_BUILD_HOMEBREW_OPENSSL_FORMULA="openssl@1.1 openssl@1.0 openssl"\n' \
                    'install_package "openssl-1.0.2q" "https://www.openssl.org/source/old/1.0.2/openssl-1.0.2q.tar.gz' \
                    '#5744cfcbcec2b1b48629f7354203bc1e5e9b5466998bbccc5b5fcde3b18eb684" mac_openssl ' \
                    '--if has_broken_mac_openssl\n' \
                    'install_package "readline-8.0" "https://ftpmirror.gnu.org/readline/readline-8.0.tar.gz' \
                    '#e339f51971478d369f8a053a330a190781acb9864cf4c541060f12078948e461" mac_readline ' \
                    '--if has_broken_mac_readline\n' \
                    'install_package "Python-2.7.18" "https://www.python.org/ftp/python/2.7.18/Python-2.7.18.tgz' \
                    '#da3080e3b488f648a3d7a4560ddee895284c3380b11d6de75edb986526b9a814" standard verify_py27 ' \
                    'copy_python_gdb ensurepip\n'
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

        _write_env(env, 'CFLAGS', '-I' + zlib_prefix + '/include')
        _write_env(env, 'LDFLAGS', '-L' + zlib_prefix + '/lib')

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
        elif version == '3.3':
            stdin = subprocess.PIPE
            stdin_contents = '--- configure\n' \
                '+++ configure\n' \
                '@@ -3391,7 +3391,7 @@ $as_echo "#define _BSD_SOURCE 1" >>confdefs.h\n' \
                '   # has no effect, don\'t bother defining them\n' \
                '   Darwin/[6789].*)\n' \
                '     define_xopen_source=no;;\n' \
                '-  Darwin/1[0-9].*)\n' \
                '+  Darwin/[12][0-9].*)\n' \
                '     define_xopen_source=no;;\n' \
                '   # On AIX 4 and 5.1, mbstate_t is defined only when _XOPEN_SOURCE == 500 but\n' \
                '   # used in wcsnrtombs() and mbsnrtowcs() even if _XOPEN_SOURCE is not defined\n' \
                '--- configure.ac\n' \
                '+++ configure.ac\n' \
                '@@ 480,7 +480,7 @@ case $ac_sys_system/$ac_sys_release in\n' \
                '   # has no effect, don\'t bother defining them\n' \
                '   Darwin/@<:@6789@:>@.*)\n' \
                '     define_xopen_source=no;;\n' \
                '-  Darwin/1@<:@0-9@:>@.*)\n' \
                '+  Darwin/@<:@[12]@:>@@<:@0-9@:>@.*)\n' \
                '     define_xopen_source=no;;\n' \
                '   # On AIX 4 and 5.1, mbstate_t is defined only when _XOPEN_SOURCE == 500 but\n' \
                '   # used in wcsnrtombs() and mbsnrtowcs() even if _XOPEN_SOURCE is not defined\n'
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
