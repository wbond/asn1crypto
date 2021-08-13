# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest

from asn1crypto import parser

from ._unittest_compat import patch

patch()


class ParserTests(unittest.TestCase):

    def test_parser(self):
        result = parser.parse(b'\x02\x01\x00')
        self.assertIsInstance(result, tuple)
        self.assertEqual(0, result[0])
        self.assertEqual(0, result[1])
        self.assertEqual(2, result[2])
        self.assertEqual(b'\x02\x01', result[3])
        self.assertEqual(b'\x00', result[4])
        self.assertEqual(b'', result[5])

    def test_peek(self):
        self.assertEqual(3, parser.peek(b'\x02\x01\x00\x00'))

    def test_parse_indef_nested(self):
        data = b'\x24\x80\x24\x80\x24\x80\x04\x00\x00\x00\x00\x00\x00\x00'
        result = parser.parse(data)
        self.assertEqual(b'\x24\x80', result[3])
        self.assertEqual(b'\x24\x80\x24\x80\x04\x00\x00\x00\x00\x00', result[4])
        self.assertEqual(b'\x00\x00', result[5])

    def test_parser_strict(self):
        with self.assertRaises(ValueError):
            parser.parse(b'\x02\x01\x00\x00', strict=True)

    def test_emit(self):
        self.assertEqual(b'\x02\x01\x00', parser.emit(0, 0, 2, b'\x00'))

    def test_emit_type_errors(self):
        with self.assertRaises(TypeError):
            parser.emit('0', 0, 2, b'\x00')

        with self.assertRaises(ValueError):
            parser.emit(-1, 0, 2, b'\x00')

        with self.assertRaises(TypeError):
            parser.emit(0, '0', 2, b'\x00')

        with self.assertRaises(ValueError):
            parser.emit(0, 5, 2, b'\x00')

        with self.assertRaises(TypeError):
            parser.emit(0, 0, '2', b'\x00')

        with self.assertRaises(ValueError):
            parser.emit(0, 0, -1, b'\x00')

        with self.assertRaises(TypeError):
            parser.emit(0, 0, 2, '\x00')

    def test_parser_large_tag(self):
        # One extra byte
        result = parser.parse(b'\x7f\x49\x00')
        self.assertEqual(1, result[0])
        self.assertEqual(1, result[1])
        self.assertEqual(73, result[2])
        self.assertEqual(b'\x7f\x49\x00', result[3])
        self.assertEqual(b'', result[4])
        self.assertEqual(b'', result[5])

        # Two extra bytes
        result = parser.parse(b'\x7f\x81\x49\x00')
        self.assertEqual(1, result[0])
        self.assertEqual(1, result[1])
        self.assertEqual(201, result[2])
        self.assertEqual(b'\x7f\x81\x49\x00', result[3])
        self.assertEqual(b'', result[4])
        self.assertEqual(b'', result[5])

        # Three extra bytes
        result = parser.parse(b'\x7f\x81\x80\x00\x00')
        self.assertEqual(1, result[0])
        self.assertEqual(1, result[1])
        self.assertEqual(16384, result[2])
        self.assertEqual(b'\x7f\x81\x80\x00\x00', result[3])
        self.assertEqual(b'', result[4])
        self.assertEqual(b'', result[5])

    def test_parser_insufficient_data(self):
        # No tag
        with self.assertRaises(ValueError):
            parser.parse(b'')

        # Long-form tag is truncated
        with self.assertRaises(ValueError):
            parser.parse(b'\xbf')
        with self.assertRaises(ValueError):
            parser.parse(b'\xbf\x81')

        # No length
        with self.assertRaises(ValueError):
            parser.parse(b'\x04')
        with self.assertRaises(ValueError):
            parser.parse(b'\xbf\x1f')

        # Long-form length is truncated
        with self.assertRaises(ValueError):
            parser.parse(b'\x04\x81')
        with self.assertRaises(ValueError):
            parser.parse(b'\x04\x82\x01')

        # Contents are truncated
        with self.assertRaises(ValueError):
            parser.parse(b'\x04\x02\x00')
        with self.assertRaises(ValueError):
            parser.parse(b'\x04\x81\x80' + (b'\x00' * 127))

    def test_parser_bounded_recursion(self):
        with self.assertRaises(ValueError):
            parser.parse(b'\x30\x80' * 1000)

    def test_parser_indef_missing_eoc(self):
        with self.assertRaises(ValueError):
            parser.parse(b'\x30\x80')
        with self.assertRaises(ValueError):
            parser.parse(b'\x30\x80\x30\x80\x00\x00')

    def test_parser_indef_long_zero_length(self):
        # The parser should not confuse the long-form zero length for an EOC.
        result = parser.parse(b'\x30\x80\x30\x82\x00\x00\x00\x00')
        self.assertIsInstance(result, tuple)
        self.assertEqual(0, result[0])
        self.assertEqual(1, result[1])
        self.assertEqual(16, result[2])
        self.assertEqual(b'\x30\x80', result[3])
        self.assertEqual(b'\x30\x82\x00\x00', result[4])
        self.assertEqual(b'\x00\x00', result[5])

    def test_parser_indef_primitive(self):
        with self.assertRaises(ValueError):
            parser.parse(b'\x04\x80\x00\x00')

    def test_parse_nonminimal_tag(self):
        with self.assertRaises(ValueError):
            # Should be b'\x04\x00'
            parser.parse(b'\x1f\x04\x00')

        with self.assertRaises(ValueError):
            # Should be b'\xbf\x1f\x00'
            parser.parse(b'\xbf\x80\x1f\x00')
