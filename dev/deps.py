# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import imp
import os
import subprocess
import sys
import warnings
import shutil
import tempfile
import platform
import site
import re
import json

if sys.version_info < (3,):
    str_cls = unicode  # noqa
else:
    str_cls = str


OTHER_PACKAGES = [
    'https://github.com/wbond/oscrypto.git',
    'https://github.com/wbond/certbuilder.git',
    'https://github.com/wbond/certvalidator.git',
    'https://github.com/wbond/crlbuilder.git',
    'https://github.com/wbond/csrbuilder.git',
    'https://github.com/wbond/ocspbuilder.git',
]


def run():
    """
    Ensures a recent version of pip is installed, then uses that to install
    required development dependencies. Uses git to checkout other modularcrypto
    repos for more accurate coverage data.
    """

    package_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    build_root = os.path.abspath(os.path.join(package_root, '..'))
    try:
        tmpdir = None
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")

            major_minor = '%s.%s' % sys.version_info[0:2]
            tmpdir = tempfile.mkdtemp()
            _pip = _bootstrap_pip(tmpdir)

            print("Using pip to install dependencies")
            _pip(['install', '-q', '--upgrade', '-r', os.path.join(package_root, 'requires', 'ci')])

            if OTHER_PACKAGES:
                print("Checking out modularcrypto packages for coverage")
                for pkg_url in OTHER_PACKAGES:
                    pkg_name = os.path.basename(pkg_url).replace('.git', '')
                    pkg_dir = os.path.join(build_root, pkg_name)
                    if os.path.exists(pkg_dir):
                        print("%s is already present" % pkg_name)
                        continue
                    print("Cloning %s" % pkg_url)
                    _execute(['git', 'clone', pkg_url], build_root)
                print()

    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)

    return True

def _download(url, dest):
    """
    Downloads a URL to a directory

    :param url:
        The URL to download

    :param dest:
        The path to the directory to save the file in

    :return:
        The filesystem path to the saved file
    """

    print('Downloading %s' % url)
    filename = os.path.basename(url)
    dest_path = os.path.join(dest, filename)

    if sys.platform == 'win32':
        system_root = os.environ.get('SystemRoot')
        powershell_exe = os.path.join('system32\\WindowsPowerShell\\v1.0\\powershell.exe')
        code = "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;"
        code += "(New-Object Net.WebClient).DownloadFile('%s', '%s');" % (url, dest_path)
        _execute([powershell_exe, '-Command', code], dest)

    else:
        _execute(['curl', '-L', '--silent', '--show-error', '-O', url], dest)

    return dest_path


def _tuple_from_ver(version_string):
    """
    :param version_string:
        A unicode dotted version string

    :return:
        A tuple of integers
    """

    return tuple(map(int, version_string.split('.')))


def _is_pip_10(pip_module):
    return tuple(map(int, pip_module.__version__.split('.'))) >= (10, )


def _pip_main(pip_module, args):
    if _is_pip_10(pip_module):
        return pip_module._internal.main(args)
    return pip_module.main(args)


def _install_requirements(_pip, tmpdir, path):
    """
    Installs requirements without using Python to download, since
    different services are limiting to TLS 1.2, and older version of
    Python do not support that

    :param _pip:
        A function that will execute pip

    :param tmpdir:
        A unicode path to a temporary diretory to use for downloads

    :param path:
        A unicoe filesystem path to a requirements file
    """

    import pip

    if _is_pip_10(pip):
        from pip._internal.pep425tags import get_supported
    else:
        from pip.pep425tags import get_supported

    valid_tags = tuple(get_supported()) + (('py2.py3', 'none', 'any'),)

    packages = _parse_requires(path)
    for p in packages:
        pkg = p['pkg']
        if p['type'] == 'url':
            if pkg.endswith('.zip') or pkg.endswith('.tar.gz') or pkg.endswith('.whl'):
                url = pkg
            else:
                raise Exception('Unable to install package from URL that is not an archive')
        else:
            pypi_json_url = 'https://pypi.python.org/pypi/%s/json' % pkg
            json_dest = _download(pypi_json_url, tmpdir)
            with open(json_dest, 'rb') as f:
                pkg_info = json.loads(f.read().decode('utf-8'))
            latest = pkg_info['info']['version']
            if p['type'] == '>=':
                if _tuple_from_ver(p['ver']) > _tuple_from_ver(latest):
                    raise Exception('Unable to find version %s of %s, newest is %s' % (p['ver'], pkg, latest))
                version = latest
            elif p['type'] == '==':
                if p['ver'] not in pkg_info['releases']:
                    raise Exception('Unable to find version %s of %s' % (p['ver'], pkg))
                version = p['ver']
            else:
                version = latest

            whl = None
            tar_bz2 = None
            tar_gz = None
            for download in pkg_info['releases'][version]:
                if download['url'].endswith('.whl'):
                    parts = os.path.basename(download['url']).split('-')
                    tag_python = parts[-3]
                    tag_abi = parts[-2]
                    tag_platform = parts[-1].split('.')[0]
                    if (tag_python, tag_abi, tag_platform) not in valid_tags:
                        continue
                    whl = download['url']
                    break
                if download['url'].endswith('.tar.bz2'):
                    tar_bz2 = download['url']
                if download['url'].endswith('.tar.gz'):
                    tar_gz = download['url']
            if whl:
                url = whl
            elif tar_bz2:
                url = tar_bz2
            elif tar_gz:
                url = tar_gz
            else:
                raise Exception('Unable to find suitable download for %s' % pkg)

        local_path = _download(url, tmpdir)
        args = ['install', '-q', '--upgrade']
        if sys.platform == 'darwin' and sys.version_info[0:2] in [(2, 6), (2, 7)]:
            args.append('--user')
        args.append(local_path)
        _pip(args)
        os.remove(local_path)


def _parse_requires(path):
    """
    Does basic parsing of pip requirements files, to allow for
    using something other than Python to do actual TLS requests

    :param path:
        A path to a requirements file

    :return:
        A list of dict objects containing the keys:
         - 'type' ('any', 'url', '==', '>=')
         - 'pkg'
         - 'ver' (if 'type' == '==' or 'type' == '>=')
    """

    python_version = '.'.join(map(str_cls, sys.version_info[0:2]))

    packages = []

    with open(path, 'rb') as f:
        contents = f.read().decode('utf-8')

    for line in re.split(r'\r?\n', contents):
        line = line.strip()
        if not len(line):
            continue
        if re.match(r'^\s*#', line):
            continue
        if ';' in line:
            package, cond = line.split(';', 1)
            package = package.strip()
            cond = cond.strip()
            cond = cond.replace('python_version', repr(python_version))
            if not eval(cond):
                continue
        else:
            package = line.strip()


        if re.match(r'^\s*-r\s*', package):
            sub_req_file = re.sub(r'^\s*-r\s*', '', package)
            sub_req_file = os.path.abspath(os.path.join(os.path.dirname(path), sub_req_file))
            packages.extend(_parse_requires(sub_req_file))
            continue

        if re.match(r'https?://', package):
            packages.append({'type': 'url', 'pkg': package})
            continue

        if '>=' in package:
            parts = package.split('>=')
            package = parts[0].strip()
            ver = parts[1].strip()
            packages.append({'type': '>=', 'pkg': package, 'ver': ver})
            continue

        if '==' in package:
            parts = package.split('==')
            package = parts[0].strip()
            ver = parts[1].strip()
            packages.append({'type': '==', 'pkg': package, 'ver': ver})
            continue

        if re.search(r'[^ a-zA-Z0-9\-]', package):
            raise Exception('Unsupported requirements format version constraint: %s' % package)

        packages.append({'type': 'any', 'pkg': package})

    return packages


def _execute(params, cwd):
    """
    Executes a subprocess

    :param params:
        A list of the executable and arguments to pass to it

    :param cwd:
        The working directory to execute the command in

    :return:
        A 2-element tuple of (stdout, stderr)
    """

    proc = subprocess.Popen(
        params,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd
    )
    stdout, stderr = proc.communicate()
    code = proc.wait()
    if code != 0:
        e = OSError('subprocess exit code was non-zero')
        e.stdout = stdout
        e.stderr = stderr
        raise e
    return (stdout, stderr)


def _get_pip_main(download_dir):
    """
    Executes get-pip.py in the current Python interpreter

    :param download_dir:
        The directory that contains get-pip.py
    """

    module_info = imp.find_module('get-pip', [download_dir])
    get_pip_module = imp.load_module('_cideps.get-pip', *module_info)

    orig_sys_exit = sys.exit
    orig_sys_argv = sys.argv
    sys.exit = lambda c: None
    # Don't put pip in arv[0] or Windows builds get fussy
    sys.argv = ['get.py', '--user', '-q']

    get_pip_module.main()

    sys.exit = orig_sys_exit
    sys.argv = orig_sys_argv

    # Unload pip modules that came from the zip file
    module_names = sorted(sys.modules.keys())
    end_token = os.sep + 'pip.zip'
    mid_token = end_token + os.sep + 'pip'
    for module_name in module_names:
        try:
            module_path = sys.modules[module_name].__file__
            if mid_token in module_path or module_path.endswith(end_token):
                del sys.modules[module_name]
        except AttributeError:
            pass

    if sys.path[0].endswith('pip.zip'):
        sys.path = sys.path[1:]

    if site.USER_SITE not in sys.path:
        sys.path.append(site.USER_SITE)


def _bootstrap_pip(tmpdir):
    """
    Bootstraps the current version of pip for use in the current Python
    interpreter

    :param tmpdir:
        A temporary directory to download get-pip.py and cacert.pem

    :return:
        A function that invokes pip. Accepts one arguments, a list of parameters
        to pass to pip.
    """

    print("Downloading cacert.pem from curl")
    certs_path = _download('https://curl.haxx.se/ca/cacert.pem', tmpdir)

    try:
        import pip

        print('Upgrading pip')
        _pip_main(pip, ['install', '-q', '--upgrade', 'pip'])

    except ImportError:

        if sys.platform == 'darwin' and sys.version_info[0:2] == (2, 6):
            path = _download('https://github.com/wbond/pip-9.0.3-py26-mac/releases/download/9.0.3%2Bsecuretransport.py26/pip-9.0.3-py2.py3-none-any.whl', tmpdir)
            sys.path.insert(1, os.path.join(tmpdir, 'pip-9.0.3-py2.py3-none-any.whl'))

            import pip
            _pip_main(pip, ['--cert', certs_path, 'install', '--user', 'setuptools<37', 'wheel<0.30'])
        else:
            print("Downloading get-pip.py")
            if sys.version_info[0:2] == (3, 2):
                path = _download('https://bootstrap.pypa.io/3.2/get-pip.py', tmpdir)
            else:
                path = _download('https://bootstrap.pypa.io/get-pip.py', tmpdir)

            print("Running get-pip.py")
            _get_pip_main(tmpdir)

        import pip

    def _pip(args):
        base_args = ['--disable-pip-version-check']
        if sys.platform == 'win32':
            base_args.append('--no-warn-script-location')
        if certs_path:
            base_args += ['--cert', certs_path]
        if sys.platform == 'darwin' and sys.version_info[0:2] in [(2, 6), (2, 7)]:
            new_args = []
            for arg in args:
                new_args.append(arg)
                if arg == 'install':
                    new_args.append('--user')
            args = new_args
        _pip_main(pip, base_args + args)

    return _pip
