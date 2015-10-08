# coding: utf-8

"""
Exceptions for help trying to use cffi, then ctypes for shared library access.
Also includes helper compatibility functions. Exports the following items:

 - LibraryNotFoundError
 - FFIEngineError
 - bytes_from_buffer()
 - buffer_from_bytes()
 - null()
"""

from __future__ import unicode_literals, division, absolute_import, print_function


try:
    import cffi

    ffi = cffi.FFI()

    def buffer_from_bytes(initializer):
        return ffi.new('char[]', initializer)

    def unicode_buffer(initializer):
        return ffi.new('wchar_t[]', initializer)

    def bytes_from_buffer(buffer, maxlen=None):
        return ffi.buffer(buffer, maxlen)[:]

    def null():
        return ffi.NULL

    def cast_void_p(value):
        return ffi.cast('void *', value)

    def is_null(point):
        if point == ffi.NULL:
            return True
        if point[0] == ffi.NULL:
            return True
        return False

    def string_from_buffer(buffer):
        return ffi.string(buffer)

except (ImportError):

    from ctypes import create_string_buffer, create_unicode_buffer, cast, c_void_p

    def buffer_from_bytes(initializer):
        return create_string_buffer(initializer)

    def unicode_buffer(initializer):
        return create_unicode_buffer(initializer)

    def bytes_from_buffer(buffer, maxlen=None):
        return buffer.raw

    def null():
        return None

    def cast_void_p(value):
        return cast(value, c_void_p)

    def is_null(point):
        return not bool(point)

    def string_from_buffer(buffer):
        return buffer.value


class LibraryNotFoundError(Exception):

    """
    An exception when trying to find a shared library
    """

    pass


class FFIEngineError(Exception):

    """
    An exception when trying to instantiate ctypes or cffi
    """

    pass
