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
