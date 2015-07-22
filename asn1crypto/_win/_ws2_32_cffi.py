# coding: utf-8

"""
cffi interface for IP translation functions in Windows. Exports the
following items:

 - ws2_32
    - InetNtop()
    - InetPton()
    - WSAGetLastError()
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from .._ffi import FFIEngineError

try:
    from cffi import FFI

except (ImportError):
    raise FFIEngineError('Error importing cffi')


try:
    ffi = FFI()
    ffi.set_unicode(True)
    ffi.cdef("""
        LPCWSTR InetNtopW(INT Family, void *pAddr, LPWSTR pStringBuf, size_t StringBufSize);
        INT InetPtonW(INT Family, LPCWSTR pszAddrString, void *pAddrBuf);
        int WSAGetLastError(void);
    """)

    ws2_32 = ffi.dlopen('ws2_32.dll')

except (AttributeError):
    raise FFIEngineError('Error initializing ctypes')
