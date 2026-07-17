# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import re
import subprocess
import sys
import tempfile

from . import build_root, package_name, other_packages


run_args = [
    {
        'name': 'container',
        'kwarg': 'container',
        'required': True,
    },
]


def _is_slim_image(container):
    """
    Determines if a docker container is a python:*-slim image

    :param container:
        A unicode string of the docker image name

    :return:
        A bool - if the image is a slim variant
    """

    return bool(re.match(r'^python:.*slim', container))


def _is_python_312_or_newer(container):
    """
    Determines if a docker container is a python:X.Y image that is
    version 3.12 or newer

    :param container:
        A unicode string of the docker image name

    :return:
        A bool - if the image is python 3.12 or newer
    """

    match = re.match(r'^python:(\d+)\.(\d+)', container)
    if not match:
        return False

    return (int(match.group(1)), int(match.group(2))) >= (3, 12)


def _is_ubuntu_image(container):
    """
    Determines if a docker container is an ubuntu:* image

    :param container:
        A unicode string of the docker image name

    :return:
        A bool - if the image is an ubuntu variant
    """

    return bool(re.match(r'^ubuntu:', container))


def run(container=None):
    """
    Runs CI inside of a docker container

    :param container:
        A unicode string of the docker image to run CI inside of

    :return:
        A bool - if the CI ran successfully
    """

    if sys.platform == 'win32':
        raise ValueError('ci-docker is not designed for Windows')

    if not container:
        raise ValueError('A container image name is required')

    mount_path = '/root/work'
    workdir = os.path.join(mount_path, package_name)

    print('Running CI inside docker container: %s' % container)
    print('Mounting %s -> %s' % (build_root, mount_path))

    docker_args = [
        'docker', 'run', '--rm',
        '-v', '%s:%s' % (build_root, mount_path),
        '-w', workdir,
    ]

    # Mount any sibling modularcrypto packages that exist locally so that
    # coverage data can be collected from their source checkouts
    for other_package in other_packages:
        pkg_dir = os.path.join(build_root, other_package)
        if os.path.exists(pkg_dir):
            container_path = os.path.join(mount_path, other_package)
            print('Mounting %s -> %s' % (pkg_dir, container_path))
            docker_args.extend(['-v', '%s:%s' % (pkg_dir, container_path)])

    print('Working directory: %s\n' % workdir)
    sys.stdout.flush()

    command = 'python3 run.py deps && python3 run.py ci-driver'

    prep_commands = []

    if _is_ubuntu_image(container):
        print('Installing Python 3 and setuptools for ubuntu image\n')
        sys.stdout.flush()
        prep_commands.append('dev/ubuntu.sh py3')

    else:
        if _is_slim_image(container):
            print('Installing tools for slim image\n')
            sys.stdout.flush()
            prep_commands.append('apt-get update && apt-get install -y curl ca-certificates git')

        if _is_python_312_or_newer(container):
            print('Installing setuptools for Python 3.12+\n')
            sys.stdout.flush()
            prep_commands.append('python3 -m pip install --root-user-action ignore setuptools')

    if prep_commands:
        command = ' && '.join(prep_commands) + ' && ' + command

    cidfile = os.path.join(tempfile.gettempdir(), '%s-docker.cid' % package_name)
    if os.path.exists(cidfile):
        os.remove(cidfile)

    docker_args.extend(['--cidfile', cidfile, container, 'sh', '-c', command])

    proc = None
    try:
        proc = subprocess.Popen(docker_args)
        proc.communicate()
        return proc.returncode == 0

    except KeyboardInterrupt:
        print('\nInterrupted, killing docker container')
        sys.stdout.flush()
        if os.path.exists(cidfile):
            with open(cidfile, 'r') as f:
                container_id = f.read().strip()
            if container_id:
                subprocess.call(['docker', 'kill', container_id])
        if proc is not None:
            proc.terminate()
            proc.wait()
        return False

    finally:
        if os.path.exists(cidfile):
            os.remove(cidfile)
