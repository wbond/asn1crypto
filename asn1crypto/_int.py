# coding: utf-8

"""
Functions for converting integers to and from bytes, and calculating the modular
inverse. Exports the following items:

 - int_from_bytes()
 - int_to_bytes()
 - inverse_mod()

Some of the following source code is derived from
http://webpages.charter.net/curryfans/peter/downloads.html, but has been heavily
modified to fit into this projects lint settings. The original project license
is listed below:

Copyright (c) 2014 Peter Pearson

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import sys
import math

from ._ffi import LibraryNotFoundError, FFIEngineError, buffer_from_bytes, bytes_from_buffer, null



# Python 2
if sys.version_info <= (3,):

    def int_to_bytes(value, signed=False, width=None):
        """
        Converts an integer to a byte string

        :param value:
            The integer to convert

        :param signed:
            If the byte string should be encoded using two's complement

        :param width:
            None == auto, otherwise an integer of the byte width for the return
            value

        :return:
            A byte string
        """

        # Handle negatives in two's complement
        is_neg = False
        if signed and value < 0:
            is_neg = True
            bits = int(math.ceil(len('%x' % abs(value)) / 2.0) * 8)
            value = (value + (1 << bits)) % (1 << bits)

        hex_str = '%x' % value
        if len(hex_str) & 1:
            hex_str = '0' + hex_str

        output = hex_str.decode('hex')

        if signed and not is_neg and ord(output[0:1]) & 0x80:
            output = b'\x00' + output

        if width is not None:
            if is_neg:
                pad_char = b'\xFF'
            else:
                pad_char = b'\x00'
            output = (pad_char * (width - len(output))) + output
        elif is_neg and ord(output[0:1]) & 0x80 == 0:
            output = b'\xFF' + output

        return output

    def int_from_bytes(value, signed=False):
        """
        Converts a byte string to an integer

        :param value:
            The byte string to convert

        :param signed:
            If the byte string should be interpreted using two's complement

        :return:
            An integer
        """

        num = long(value.encode("hex"), 16)  #pylint: disable=E0602

        if not signed:
            return num

        # Check for sign bit and handle two's complement
        if ord(value[0:1]) & 0x80:
            bit_len = len(value) * 8
            return num - (1 << bit_len)

        return num

# Python 3
else:

    def int_to_bytes(value, signed=False, width=None):
        """
        Converts an integer to a byte string

        :param value:
            The integer to convert

        :param signed:
            If the byte string should be encoded using two's complement

        :param width:
            None == auto, otherwise an integer of the byte width for the return
            value

        :return:
            A byte string
        """

        if width is None:
            width_ = math.ceil(value.bit_length() / 8) or 1
            try:
                return value.to_bytes(width_, byteorder='big', signed=signed)
            except (OverflowError):
                return value.to_bytes(width_ + 1, byteorder='big', signed=signed)
        else:
            return value.to_bytes(width_, byteorder='big', signed=signed)

    def int_from_bytes(value, signed=False):
        """
        Converts a byte string to an integer

        :param value:
            The byte string to convert

        :param signed:
            If the byte string should be interpreted using two's complement

        :return:
            An integer
        """

        return int.from_bytes(value, 'big', signed=signed)


# First try to use ctypes or cffi with OpenSSL for better performance
try:
    try:
        from ._perf._big_num_cffi import libcrypto
    except (FFIEngineError) as e:
        from ._perf._big_num_ctypes import libcrypto

    def inverse_mod(a, p):
        """
        Compute the modular inverse of a (mod p)

        :param a:
            An integer

        :param p:
            An integer

        :return:
            An integer
        """

        ctx = libcrypto.BN_CTX_new()

        a_bytes = int_to_bytes(abs(a))
        p_bytes = int_to_bytes(abs(p))

        a_buf = buffer_from_bytes(a_bytes)
        a_bn = libcrypto.BN_bin2bn(a_buf, len(a_bytes), null())
        if a < 0:
            libcrypto.BN_set_negative(a_bn, 1)

        p_buf = buffer_from_bytes(p_bytes)
        p_bn = libcrypto.BN_bin2bn(p_buf, len(p_bytes), null())
        if p < 0:
            libcrypto.BN_set_negative(p_bn, 1)

        r_bn = libcrypto.BN_mod_inverse(null(), a_bn, p_bn, ctx)
        r_len_bits = libcrypto.BN_num_bits(r_bn)
        r_len = int(math.ceil(r_len_bits / 8))
        r_buf = buffer_from_bytes(r_len)
        libcrypto.BN_bn2bin(r_bn, r_buf)
        r_bytes = bytes_from_buffer(r_buf, r_len)
        result = int_from_bytes(r_bytes)

        libcrypto.BN_free(a_bn)
        libcrypto.BN_free(p_bn)
        libcrypto.BN_free(r_bn)
        libcrypto.BN_CTX_free(ctx)

        return result

# If there was an issue using OpenSSL, we fall back to pure python
except (LibraryNotFoundError, FFIEngineError):

    def inverse_mod(a, p):
        """
        Compute the modular inverse of a (mod p)

        :param a:
            An integer

        :param p:
            An integer

        :return:
            An integer
        """

        if a < 0 or p <= a:
            a = a % p

        # From Ferguson and Schneier, roughly:

        c, d = a, p
        uc, vc, ud, vd = 1, 0, 0, 1
        while c != 0:
            q, c, d = divmod(d, c) + (c,)
            uc, vc, ud, vd = ud - q*uc, vd - q*vc, uc, vc

        # At this point, d is the GCD, and ud*a+vd*p = d.
        # If d == 1, this means that ud is a inverse.

        assert d == 1
        if ud > 0:
            return ud
        else:
            return ud + p
