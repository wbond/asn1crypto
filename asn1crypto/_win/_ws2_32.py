# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import socket

from .._ffi import (
    buffer_from_bytes,
    bytes_from_buffer,
    cast_void_p,
    FFIEngineError,
    is_null,
    string_from_buffer,
    unicode_buffer,
)

try:
    from ._ws2_32_cffi import ws2_32
except (FFIEngineError):
    from ._ws2_32_ctypes import ws2_32


AF_INET = 2
AF_INET6 = 23


def inet_ntop(address_family, packed_ip):
    """
    Windows compatiblity shim for socket.inet_ntop().

    :param address_family:
        socket.AF_INET for IPv4 or socket.AF_INET6 for IPv6

    :param packed_ip:
        A byte string of the network form of an IP address

    :return:
        A unicode string of the IP address
    """

    family = {
        socket.AF_INET: AF_INET,
        socket.AF_INET6: AF_INET6,
    }[address_family]

    buffer_size = 46 if family == AF_INET6 else 16
    buffer = unicode_buffer(buffer_size)
    packed_ip_buffer = buffer_from_bytes(packed_ip)
    result = ws2_32.InetNtopW(family, cast_void_p(packed_ip_buffer), buffer, buffer_size)
    if is_null(result):
        raise OSError('Windows error %s calling InetNtop' % ws2_32.WSAGetLastError())

    return string_from_buffer(buffer)


def inet_pton(address_family, ip_string):
    """
    Windows compatiblity shim for socket.inet_ntop().

    :param address_family:
        socket.AF_INET for IPv4 or socket.AF_INET6 for IPv6

    :param ip_string:
        A unicode string of an IP address

    :return:
        A byte string of the network form of the IP address
    """

    family = {
        socket.AF_INET: AF_INET,
        socket.AF_INET6: AF_INET6,
    }[address_family]

    buffer_size = 16 if family == AF_INET6 else 4
    buffer = buffer_from_bytes(buffer_size)
    result = ws2_32.InetPtonW(family, ip_string, buffer)
    if result != 1:
        raise OSError('Windows error %s calling InetPtob' % ws2_32.WSAGetLastError())

    return bytes_from_buffer(buffer, buffer_size)
