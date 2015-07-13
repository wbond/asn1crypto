# coding: utf-8

"""
ctypes interface for BN_mod_inverse() function from OpenSSL. Exports the
following items:

 - buffer_from_bytes()
 - bytes_from_buffer()
 - libcrypto
    - BN_bin2bin()
    - BN_CTX_free()
    - BN_CTX_new()
    - BN_free()
    - BN_mod_inverse()
    - BN_new()
    - BN_num_bits()
    - BN_set_negative()
 - null()

Will raise asn1crypto._ffi.LibraryNotFoundError() if libcrypto can not be
found. Will raise asn1crypto._ffi.FFIEngineError() if there is an error
interfacing with libcrypto.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from ctypes.util import find_library
from ctypes import CDLL, c_int, c_char_p, c_void_p, create_string_buffer

from ._ffi import LibraryNotFoundError, FFIEngineError


try:
    libcrypto_path = find_library('crypto')
    if not libcrypto_path:
        raise LibraryNotFoundError('The library libcrypto could not be found')

    libcrypto = CDLL(libcrypto_path)

    libcrypto.BN_new.argtypes = []
    libcrypto.BN_new.restype = c_void_p

    libcrypto.BN_bin2bn.argtypes = [c_char_p, c_int, c_void_p]
    libcrypto.BN_bin2bn.restype = c_void_p

    libcrypto.BN_bn2bin.argtypes = [c_void_p, c_char_p]
    libcrypto.BN_bn2bin.restype = c_int

    libcrypto.BN_set_negative.argtypes = [c_void_p, c_int]
    libcrypto.BN_set_negative.restype = None

    libcrypto.BN_num_bits.argtypes = [c_void_p]
    libcrypto.BN_num_bits.restype = c_int

    libcrypto.BN_free.argtypes = [c_void_p]
    libcrypto.BN_free.restype = None

    libcrypto.BN_CTX_new.argtypes = []
    libcrypto.BN_CTX_new.restype = c_void_p

    libcrypto.BN_CTX_free.argtypes = [c_void_p]
    libcrypto.BN_CTX_free.restype = None

    libcrypto.BN_mod_inverse.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p]
    libcrypto.BN_mod_inverse.restype = c_void_p

    def buffer_from_bytes(initializer):
        return create_string_buffer(initializer)

    def bytes_from_buffer(buffer, maxlen=None):  #pylint: disable=W0613
        return buffer.raw

    def null():
        return None

except (AttributeError):
    raise FFIEngineError('Error initializing ctypes')
