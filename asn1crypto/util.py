# coding: utf-8

"""
Functions for converting integers to and from bytes. Exports the following
items:

 - int_from_bytes()
 - int_to_bytes()
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import sys
import math



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
            return value.to_bytes(width, byteorder='big', signed=signed)

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
