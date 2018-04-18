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
import tarfile
import zipfile
import platform
import ctypes

if sys.version_info >= (2, 7):
    import sysconfig

if sys.version_info < (3,):
    str_cls = unicode  # noqa
else:
    str_cls = str


def run():
    """
    Installs required development dependencies. Uses git to checkout other
    modularcrypto repos for more accurate coverage data.
    """

    package_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    build_root = os.path.abspath(os.path.join(package_root, '..'))

    deps_dir = os.path.join(build_root, 'modularcrypto-deps')
    if os.path.exists(deps_dir):
        shutil.rmtree(deps_dir, ignore_errors=True)
    os.mkdir(deps_dir)

    with open(os.path.join(os.path.dirname(__file__), 'modularcrypto.json'), 'rb') as f:
        modularcrypto_packages = json.loads(f.read().decode('utf-8'))

    try:
        print("Staging ci dependencies")
        _stage_requirements(deps_dir, os.path.join(package_root, 'requires', 'ci'))

        print("Checking out modularcrypto packages for coverage")
        for pkg_name in modularcrypto_packages:
            pkg_url = 'https://github.com/wbond/%s.git' % pkg_name
            pkg_dir = os.path.join(build_root, pkg_name)
            if os.path.exists(pkg_dir):
                print("%s is already present" % pkg_name)
                continue
            print("Cloning %s" % pkg_url)
            _execute(['git', 'clone', pkg_url], build_root)
        print()

    except (Exception):
        if os.path.exists(deps_dir):
            shutil.rmtree(deps_dir, ignore_errors=True)
        raise

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


def _pep425_implementation():
    """
    :return:
        A 2 character unicode string of the implementation - 'cp' for cpython
        or 'pp' for PyPy
    """

    return 'pp' if hasattr(sys, 'pypy_version_info') else 'cp'


def _pep425_version():
    """
    :return:
        A tuple of integers representing the Python version number
    """

    if hasattr(sys, 'pypy_version_info'):
        return (sys.version_info[0], sys.pypy_version_info.major,
                sys.pypy_version_info.minor)
    else:
        return (sys.version_info[0], sys.version_info[1])


def _pep425_supports_manylinux():
    """
    :return:
        A boolean indicating if the machine can use manylinux1 packages
    """

    try:
        import _manylinux
        return bool(_manylinux.manylinux1_compatible)
    except (ImportError, AttributeError):
        pass

    # Check for glibc 2.5
    try:
        proc = ctypes.CDLL(None)
        gnu_get_libc_version = proc.gnu_get_libc_version
        gnu_get_libc_version.restype = ctypes.c_char_p

        ver = gnu_get_libc_version()
        if not isinstance(ver, str_cls):
            ver = ver.decode('ascii')
        match = re.match(r'(\d+)\.(\d+)', ver)
        return match and match.group(1) == '2' and int(match.group(2)) >= 5

    except (AttributeError):
        return False


def _pep425_get_abi():
    """
    :return:
        A unicode string of the system abi. Will be something like: "cp27m",
        "cp33m", etc.
    """

    try:
        soabi = sysconfig.get_config_var('SOABI')
        if soabi:
            if soabi.startswith('cpython-'):
                return 'cp%s' % soabi.split('-')[1]
            return soabi.replace('.', '_').replace('-', '_')
    except (IOError, NameError):
        pass

    impl = _pep425_implementation()
    suffix = ''
    if impl == 'cp':
        suffix += 'm'
    if sys.maxunicode == 0x10ffff and sys.version_info < (3, 3):
        suffix += 'u'
    return '%s%s%s' % (impl, ''.join(map(str_cls, _pep425_version())), suffix)


def _pep425tags():
    """
    :return:
        A list of 3-element tuples with unicode strings or None:
         [0] implementation tag - cp33, pp27, cp26, py2, py2.py3
         [1] abi tag - cp26m, None
         [2] arch tag - linux_x86_64, macosx_10_10_x85_64, etc
    """

    tags = []

    versions = []
    version_info = _pep425_version()
    major = version_info[:-1]
    for minor in range(version_info[-1], -1, -1):
        versions.append(''.join(map(str, major + (minor,))))

    impl = _pep425_implementation()

    abis = []
    abi = _pep425_get_abi()
    if abi:
        abis.append(abi)
    abi3s = set()
    for suffix in imp.get_suffixes():
        if suffix[0].startswith('.abi'):
            abi3s.add(suffix[0].split('.', 2)[1])
    abis.extend(sorted(list(abi3s)))
    abis.append('none')

    if sys.platform == 'darwin':
        plat_ver = platform.mac_ver()
        ver_parts = plat_ver[0].split('.')
        minor = int(ver_parts[1])
        arch = plat_ver[2]
        if sys.maxsize == 2147483647:
            arch = 'i386'
        arches = []
        while minor > 5:
            arches.append('macosx_10_%s_%s' % (minor, arch))
            arches.append('macosx_10_%s_intel' % (minor,))
            arches.append('macosx_10_%s_universal' % (minor,))
            minor -= 1
    else:
        if sys.platform == 'win32':
            if 'amd64' in sys.version.lower():
                arches = ['win_amd64']
            arches = [sys.platform]
        elif hasattr(os, 'uname'):
            (plat, _, _, _, machine) = os.uname()
            plat = plat.lower().replace('/', '')
            machine.replace(' ', '_').replace('/', '_')
            if plat == 'linux' and sys.maxsize == 2147483647:
                machine = 'i686'
            arch = '%s_%s' % (plat, machine)
            if _pep425_supports_manylinux():
                arches = [arch.replace('linux', 'manylinux1'), arch]
            else:
                arches = [arch]

    for abi in abis:
        for arch in arches:
            tags.append(('%s%s' % (impl, versions[0]), abi, arch))

    for version in versions[1:]:
        for abi in abi3s:
            for arch in arches:
                tags.append(('%s%s' % (impl, version), abi, arch))

    for arch in arches:
        tags.append(('py%s' % (versions[0][0]), 'none', arch))

    tags.append(('%s%s' % (impl, versions[0]), 'none', 'any'))
    tags.append(('%s%s' % (impl, versions[0][0]), 'none', 'any'))

    for i, version in enumerate(versions):
        tags.append(('py%s' % (version,), 'none', 'any'))
        if i == 0:
            tags.append(('py%s' % (version[0]), 'none', 'any'))

    tags.append(('py2.py3', 'none', 'any'))

    return tags


def _open_archive(path):
    """
    :param path:
        A unicode string of the filesystem path to the archive

    :return:
        An archive object
    """

    if path.endswith('.zip'):
        return zipfile.ZipFile(path, 'r')
    return tarfile.open(path, 'r')


def _list_archive_members(archive):
    """
    :param archive:
        An archive from _open_archive()

    :return:
        A list of info objects to be used with _info_name() and _extract_info()
    """

    if isinstance(archive, zipfile.ZipFile):
        return archive.infolist()
    return archive.getmembers()


def _archive_single_dir(archive):
    """
    Check if all members of the archive are in a single top-level directory

    :param archive:
        An archive from _open_archive()

    :return:
        None if not a single top level directory in archive, otherwise a
        unicode string of the top level directory name
    """

    common_root = None
    for info in _list_archive_members(archive):
        fn = _info_name(info)
        if fn in set(['.', '/']):
            continue
        sep = None
        if '/' in fn:
            sep = '/'
        elif '\\' in fn:
            sep = '\\'
        if sep is None:
            root_dir = fn
        else:
            root_dir, _ = fn.split(sep, 1)
        if common_root is None:
            common_root = root_dir
        else:
            if common_root != root_dir:
                return None
    return common_root


def _info_name(info):
    """
    Returns a normalized file path for an archive info object

    :param info:
        An info object from _list_archive_members()

    :return:
        A unicode string with all directory separators normalized to "/"
    """

    if isinstance(info, zipfile.ZipInfo):
        return info.filename.replace('\\', '/')
    return info.name.replace('\\', '/')


def _extract_info(archive, info):
    """
    Extracts the contents of an archive info object

    ;param archive:
        An archive from _open_archive()

    :param info:
        An info object from _list_archive_members()

    :return:
        None, or a byte string of the file contents
    """

    if isinstance(archive, zipfile.ZipFile):
        fn = info.filename
        is_dir = fn.endswith('/') or fn.endswith('\\')
        out = archive.read(info)
        if is_dir and out == b'':
            return None
        return out

    info_file = archive.extractfile(info)
    if info_file:
        return info_file.read()
    return None


def _extract_package(deps_dir, pkg_path):
    """
    Extract a .whl, .zip, .tar.gz or .tar.bz2 into a package path to
    use when running CI tasks

    :param deps_dir:
        A unicode string of the directory the package should be extracted to

    :param pkg_path:
        A unicode string of the path to the archive
    """

    if pkg_path.endswith('.whl'):
        try:
            zf = None
            zf = zipfile.ZipFile(pkg_path, 'r')
            # Wheels contain exactly what we need and nothing else
            zf.extractall(deps_dir)
        finally:
            if zf:
                zf.close()
        return

    # Source archives may contain a bunch of other things.
    # The following code works for the packages coverage and
    # configparser, which are the two we currently require that
    # do not provide wheels

    try:
        ar = None
        ar = _open_archive(pkg_path)

        pkg_name = None
        base_path = _archive_single_dir(ar) or ''
        if len(base_path):
            if '-' in base_path:
                pkg_name, _ = base_path.split('-', 1)
            base_path += '/'

        base_pkg_path = None
        if pkg_name is not None:
            base_pkg_path = base_path + pkg_name + '/'
        src_path = base_path + 'src/'

        members = []
        for info in _list_archive_members(ar):
            fn = _info_name(info)
            if base_pkg_path is not None and fn.startswith(base_pkg_path):
                dst_path = fn[len(base_pkg_path) - len(pkg_name) - 1:]
                members.append((info, dst_path))
                continue
            if fn.startswith(src_path):
                members.append((info, fn[len(src_path):]))
                continue

        for info, path in members:
            info_data = _extract_info(ar, info)
            # Dirs won't return a file
            if info_data is not None:
                dst_path = os.path.join(deps_dir, path)
                dst_dir = os.path.dirname(dst_path)
                if not os.path.exists(dst_dir):
                    os.makedirs(dst_dir)
                with open(dst_path, 'wb') as f:
                    f.write(info_data)
    finally:
        if ar:
            ar.close()


def _stage_requirements(deps_dir, path):
    """
    Installs requirements without using Python to download, since
    different services are limiting to TLS 1.2, and older version of
    Python do not support that

    :param deps_dir:
        A unicode path to a temporary diretory to use for downloads

    :param path:
        A unicoe filesystem path to a requirements file
    """

    valid_tags = _pep425tags()

    packages = _parse_requires(path)
    for p in packages:
        pkg = p['pkg']
        if p['type'] == 'url':
            if pkg.endswith('.zip') or pkg.endswith('.tar.gz') or pkg.endswith('.tar.bz2') or pkg.endswith('.whl'):
                url = pkg
            else:
                raise Exception('Unable to install package from URL that is not an archive')
        else:
            pypi_json_url = 'https://pypi.org/pypi/%s/json' % pkg
            json_dest = _download(pypi_json_url, deps_dir)
            with open(json_dest, 'rb') as f:
                pkg_info = json.loads(f.read().decode('utf-8'))
            if os.path.exists(json_dest):
                os.remove(json_dest)

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

            wheels = {}
            whl = None
            tar_bz2 = None
            tar_gz = None
            for download in pkg_info['releases'][version]:
                if download['url'].endswith('.whl'):
                    parts = os.path.basename(download['url']).split('-')
                    tag_impl = parts[-3]
                    tag_abi = parts[-2]
                    tag_arch = parts[-1].split('.')[0]
                    wheels[(tag_impl, tag_abi, tag_arch)] = download['url']
                if download['url'].endswith('.tar.bz2'):
                    tar_bz2 = download['url']
                if download['url'].endswith('.tar.gz'):
                    tar_gz = download['url']

            # Find the most-specific wheel possible
            for tag in valid_tags:
                if tag in wheels:
                    whl = wheels[tag]
                    break

            if whl:
                url = whl
            elif tar_bz2:
                url = tar_bz2
            elif tar_gz:
                url = tar_gz
            else:
                raise Exception('Unable to find suitable download for %s' % pkg)

        local_path = _download(url, deps_dir)

        _extract_package(deps_dir, local_path)

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
