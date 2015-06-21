# coding: utf-8

"""
cffi interface for BN_mod_inverse() function from OpenSSL. Exports the
following items:

 - buffer_from_bytes()
 - bytes_from_buffer()
 - libcrypto
    - BN_new()
    - BN_bin2bin()
    - BN_set_negative()
    - BN_num_bits()
    - BN_free()
    - BN_CTX_new()
    - BN_CTX_free()
    - BN_mod_inverse()
 - null()

Will raise asn1crypto._ffi.LibraryNotFoundError() if libcrypto can not be
found. Will raise asn1crypto._ffi.FFIEngineError() if cffi is not instaled
or there is an error interfacing with libcrypto.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from ctypes.util import find_library

from ._ffi import LibraryNotFoundError, FFIEngineError

try:
    from cffi import FFI

except (ImportError):
    raise FFIEngineError('Error importing cffi')


try:
    ffi = FFI()
    ffi.cdef("""
        typedef void BIGNUM;
        typedef void BN_CTX;

        BIGNUM *BN_new(void);

        int BN_bn2bin(const BIGNUM *a, unsigned char *to);
        BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);

        void BN_set_negative(BIGNUM *a, int n);

        int BN_num_bits(const BIGNUM *a);

        void BN_free(BIGNUM *a);

        BN_CTX *BN_CTX_new(void);
        void BN_CTX_free(BN_CTX *c);

        BIGNUM *BN_mod_inverse(BIGNUM *r, BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);
    """)

    libcrypto_path = find_library('libcrypto')
    if not libcrypto_path:
        raise LibraryNotFoundError('The library libcrypto could not be found')

    libcrypto = ffi.dlopen(libcrypto_path)

    def buffer_from_bytes(initializer):
        return ffi.new('char[]', initializer)

    def bytes_from_buffer(buffer, maxlen=None):
        return ffi.buffer(buffer, maxlen)[:]

    def null():
        return ffi.NULL

except (AttributeError):
    raise FFIEngineError('Error initializing ctypes')
