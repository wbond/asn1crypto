# coding: utf-8

"""
ctypes interface for IP translation functions in Windows. Exports the
following items:

 - ws2_32
    - InetNtop()
    - InetPton()
    - WSAGetLastError()
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from ctypes import windll, wintypes, c_size_t, c_void_p, c_int

from .._ffi import FFIEngineError


try:
    ws2_32 = windll.ws2_32

    ws2_32.InetNtopW.argtypes = [wintypes.INT, c_void_p, wintypes.LPWSTR, c_size_t]
    ws2_32.InetNtopW.restype = wintypes.LPCWSTR

    ws2_32.InetPtonW.argtypes = [wintypes.INT, wintypes.LPCWSTR, c_void_p]
    ws2_32.InetPtonW.restype = wintypes.INT

    ws2_32.WSAGetLastError.argtypes = []
    ws2_32.WSAGetLastError.restype = c_int

except (AttributeError):
    raise FFIEngineError('Error initializing ctypes')
