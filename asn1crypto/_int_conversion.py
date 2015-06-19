# coding: utf-8

"""
Functions to convert from integers to byte string and byte string to integers.
Exports the following items:

 - int_from_bytes()
 - int_to_bytes()
"""

from __future__ import unicode_literals

import sys


# Python 2
if sys.version_info <= (3,):

    def int_to_bytes(value, signed=False):
        """
        Converts an integer to a byte string

        :param value:
            The integer to convert

        :param signed:
            If the byte string should be encoded using two's complement

        :return:
            A byte string
        """

        # Handle negatives in two's complement
        if signed and value < 0:
            value = (~value) + 1

        hex_str = '%x' % value
        if len(hex_str) & 1:
            hex_str = '0' + hex_str
        return hex_str.decode('hex')

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

    def int_to_bytes(value, signed=False):
        """
        Converts an integer to a byte string

        :param value:
            The integer to convert

        :param signed:
            If the byte string should be encoded using two's complement

        :return:
            A byte string
        """

        result = value.to_bytes((value.bit_length() // 8) + 1, byteorder='big', signed=signed)
        if not signed:
            return result.lstrip(b'\x00')
        return result

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
