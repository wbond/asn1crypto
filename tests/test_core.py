# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import os
from datetime import datetime

from asn1crypto import core, util

from .unittest_data import data_decorator, data
from ._unittest_compat import patch

patch()

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class NamedBits(core.BitString):
    _map = {
        0: 'zero',
        1: 'one',
        2: 'two',
        3: 'three',
        4: 'four',
        6: 'six',
        7: 'seven',
    }


class SequenceOfInts(core.SequenceOf):
    _child_spec = core.Integer


class SequenceAny(core.SequenceOf):
    _child_spec = core.Any


class Seq(core.Sequence):
    _fields = [
        ('id', core.ObjectIdentifier),
        ('value', core.Any),
    ]

    _oid_pair = ('id', 'value')
    _oid_specs = {
        '1.2.3': core.Integer,
        '2.3.4': core.OctetString,
    }


class CopySeq(core.Sequence):
    _fields = [
        ('name', core.UTF8String),
        ('pair', Seq),
    ]


class Enum(core.Enumerated):
    _map = {
        0: 'a',
        1: 'b',
    }


class NumChoice(core.Choice):
    _alternatives = [
        ('one', core.Integer, {'tag_type': 'explicit', 'tag': 0}),
        ('two', core.Integer, {'tag_type': 'implicit', 'tag': 1}),
        ('three', core.Integer, {'tag_type': 'explicit', 'tag': 2}),
    ]


class SeqChoice(core.Choice):
    _alternatives = [
        ('one', CopySeq, {'tag_type': 'explicit', 'tag': 0}),
        ('two', CopySeq, {'tag_type': 'implicit', 'tag': 1}),
    ]


class SetTest(core.Set):
    _fields = [
        ('two', core.Integer, {'tag_type': 'implicit', 'tag': 2}),
        ('one', core.Integer, {'tag_type': 'implicit', 'tag': 1}),
    ]


class SetOfTest(core.SetOf):
    _child_spec = core.Integer


class ConcatTest(core.Concat):
    _child_specs = [Seq, core.Integer]


class MyOids(core.ObjectIdentifier):
    _map = {
        '1.2.3': 'abc',
        '4.5.6': 'def',
    }


@data_decorator
class CoreTests(unittest.TestCase):

    def test_sequence_spec(self):
        seq = Seq()
        seq['id'] = '1.2.3'
        self.assertEqual(core.Integer, seq.spec('value'))
        seq['id'] = '2.3.4'
        self.assertEqual(core.OctetString, seq.spec('value'))

    def test_sequence_of_spec(self):
        seq = SequenceAny()
        self.assertEqual(core.Any, seq.spec())

    @staticmethod
    def compare_primitive_info():
        return (
            (core.ObjectIdentifier('1.2.3'), core.ObjectIdentifier('1.2.3'), True),
            (core.Integer(1), Enum(1), False),
            (core.Integer(1), core.Integer(1, tag_type='implicit', tag=5), True),
            (core.Integer(1), core.Integer(1, tag_type='explicit', tag=5), True),
            (core.Integer(1), core.Integer(2), False),
            (core.OctetString(b''), core.OctetString(b''), True),
            (core.OctetString(b''), core.OctetString(b'1'), False),
            (core.OctetString(b''), core.OctetBitString(b''), False),
            (core.ParsableOctetString(b'12'), core.OctetString(b'12'), True),
            (core.ParsableOctetBitString(b'12'), core.OctetBitString(b'12'), True),
            (core.UTF8String('12'), core.UTF8String('12'), True),
            (core.UTF8String('12'), core.UTF8String('1'), False),
            (core.UTF8String('12'), core.IA5String('12'), False),
        )

    @data('compare_primitive_info')
    def compare_primitive(self, one, two, equal):
        if equal:
            self.assertEqual(one, two)
        else:
            self.assertNotEqual(one, two)

    @staticmethod
    def integer_info():
        return (
            (0, b'\x02\x01\x00'),
            (255, b'\x02\x02\x00\xFF'),
            (128, b'\x02\x02\x00\x80'),
            (127, b'\x02\x01\x7F'),
            (-127, b'\x02\x01\x81'),
            (-127, b'\x02\x01\x81'),
            (32768, b'\x02\x03\x00\x80\x00'),
            (-32768, b'\x02\x02\x80\x00'),
            (-32769, b'\x02\x03\xFF\x7F\xFF'),
        )

    @data('integer_info')
    def integer(self, native, der_bytes):
        i = core.Integer(native)
        self.assertEqual(der_bytes, i.dump())
        self.assertEqual(native, core.Integer.load(der_bytes).native)

    @staticmethod
    def utctime_info():
        return (
            (datetime(2030, 12, 31, 8, 30, 0, tzinfo=util.timezone.utc), b'\x17\x0D301231083000Z'),
            (datetime(2049, 12, 31, 8, 30, 0, tzinfo=util.timezone.utc), b'\x17\x0D491231083000Z'),
            (datetime(1950, 12, 31, 8, 30, 0, tzinfo=util.timezone.utc), b'\x17\x0D501231083000Z'),
        )

    @data('utctime_info')
    def utctime(self, native, der_bytes):
        u = core.UTCTime(native)
        self.assertEqual(der_bytes, u.dump())
        self.assertEqual(native, core.UTCTime.load(der_bytes).native)

    @staticmethod
    def type_info():
        return (
            ('universal/object_identifier.der', core.ObjectIdentifier, '1.2.840.113549.1.1.1'),
        )

    @data('type_info')
    def parse_universal_type(self, input_filename, type_class, native):
        with open(os.path.join(fixtures_dir, input_filename), 'rb') as f:
            der = f.read()
            parsed = type_class.load(der)

        self.assertEqual(native, parsed.native)
        self.assertEqual(der, parsed.dump(force=True))

    @staticmethod
    def bit_string_info():
        return (
            ((0, 1, 1), b'\x03\x02\x05\x60'),
            ((0, 1, 1, 0, 0, 0, 0, 0), b'\x03\x02\x00\x60'),
        )

    @data('bit_string_info')
    def bit_string(self, native, der_bytes):
        bs = core.BitString(native)
        self.assertEqual(der_bytes, bs.dump())
        self.assertEqual(native, core.BitString.load(der_bytes).native)

    def test_bit_string_item_access(self):
        named = core.BitString()
        named[0] = True
        self.assertEqual(False, named[2])
        self.assertEqual(False, named[1])
        self.assertEqual(True, named[0])

    @staticmethod
    def mapped_bit_string_info():
        return (
            (
                (0, 1, 1),
                b'\x03\x02\x05\x60',
                set(['one', 'two'])
            ),
            (
                (0,),
                b'\x03\x02\x07\x00',
                set()
            ),
            (
                set(['one', 'two']),
                b'\x03\x02\x05\x60',
                set(['one', 'two'])
            )
        )

    @data('mapped_bit_string_info')
    def mapped_bit_string(self, input_native, der_bytes, native):
        named = NamedBits(input_native)
        self.assertEqual(der_bytes, named.dump())
        self.assertEqual(native, NamedBits.load(der_bytes).native)

    def test_mapped_bit_string_item_access(self):
        named = NamedBits()
        named['one'] = True
        self.assertEqual(False, named['two'])
        self.assertEqual(True, named['one'])
        self.assertEqual(True, 'one' in named.native)

    def test_mapped_bit_string_unset_bit(self):
        named = NamedBits(set(['one', 'two']))
        named['one'] = False
        self.assertEqual(True, named['two'])
        self.assertEqual(set(['two']), named.native)

    def test_mapped_bit_string_sparse(self):
        named = NamedBits((0, 0, 0, 0, 0, 1))
        self.assertEqual(False, named['two'])
        self.assertEqual(True, named[5])
        self.assertEqual(True, 5 in named.native)

    def test_mapped_bit_string_numeric(self):
        named = NamedBits()
        named[1] = True
        self.assertEqual(True, named['one'])
        self.assertEqual(set(['one']), named.native)

    def test_get_sequence_value(self):
        seq = SequenceOfInts([1, 2])
        self.assertEqual(2, seq[1].native)

    def test_replace_sequence_value(self):
        seq = SequenceOfInts([1, 2])
        self.assertEqual([1, 2], seq.native)
        seq[0] = 5
        self.assertEqual([5, 2], seq.native)

    def test_add_to_end_sequence_value(self):
        seq = SequenceOfInts([1, 2])
        self.assertEqual([1, 2], seq.native)
        seq[2] = 5
        self.assertEqual([1, 2, 5], seq.native)
        seq.append(6)
        self.assertEqual([1, 2, 5, 6], seq.native)

    def test_delete_sequence_value(self):
        seq = SequenceOfInts([1, 2])
        self.assertEqual([1, 2], seq.native)
        del seq[0]
        self.assertEqual([2], seq.native)

    def test_sequence_any_asn1value(self):
        seq = SequenceAny()
        seq.append(core.Integer(5))
        self.assertEqual([5], seq.native)

    def test_sequence_any_native_value(self):
        seq = SequenceAny()
        with self.assertRaises(ValueError):
            seq.append(5)

    def test_copy(self):
        a = core.Integer(200)
        b = a.copy()
        self.assertNotEqual(id(a), id(b))
        self.assertEqual(a.contents, b.contents)
        self.assertEqual(a.dump(), b.dump())

    def test_copy_mutable(self):
        a = CopySeq({'name': 'foo', 'pair': {'id': '1.2.3', 'value': 5}})
        # Cache the native representation so it is copied during the copy operation
        a.native
        b = a.copy()
        self.assertNotEqual(id(a), id(b))
        self.assertNotEqual(id(a['pair']), id(b['pair']))
        self.assertEqual(a.contents, b.contents)
        self.assertEqual(a.dump(), b.dump())

        self.assertEqual(a['pair']['value'].native, b['pair']['value'].native)
        a['pair']['value'] = 6
        self.assertNotEqual(a['pair']['value'].native, b['pair']['value'].native)

        a.native['pair']['value'] = 6
        self.assertNotEqual(a.native['pair']['value'], b.native['pair']['value'])

        self.assertNotEqual(a.contents, b.contents)
        self.assertNotEqual(a.dump(), b.dump())

    def test_retag(self):
        a = core.Integer(200)
        b = a.retag('explicit', 0)
        self.assertNotEqual(id(a), id(b))
        self.assertEqual(a.contents, b.contents)
        self.assertNotEqual(a.dump(), b.dump())

    def test_untag(self):
        a = core.Integer(200, tag_type='explicit', tag=0)
        b = a.untag()
        self.assertNotEqual(id(a), id(b))
        self.assertEqual(a.contents, b.contents)
        self.assertNotEqual(a.dump(), b.dump())

    def test_fix_tagging_choice(self):
        correct = core.Integer(200, tag_type='explicit', tag=2)
        choice = NumChoice(
            name='three',
            value=core.Integer(200, tag_type='explicit', tag=1)
        )
        self.assertEqual(correct.dump(), choice.dump())
        self.assertEqual(correct.tag_type, choice.chosen.tag_type)
        self.assertEqual(correct.explicit_tag, choice.chosen.explicit_tag)

    def test_copy_choice_mutate(self):
        a = CopySeq({'name': 'foo', 'pair': {'id': '1.2.3', 'value': 5}})
        choice = SeqChoice(
            name='one',
            value=a
        )
        choice.dump()
        choice_copy = choice.copy()
        choice.chosen['name'] = 'bar'
        self.assertNotEqual(choice.chosen['name'], choice_copy.chosen['name'])

    def test_concat(self):
        child1 = Seq({
            'id': '1.2.3',
            'value': 1
        })
        child2 = core.Integer(0)
        parent = ConcatTest([
            child1,
            child2
        ])
        self.assertEqual(child1, parent[0])
        self.assertEqual(child2, parent[1])
        self.assertEqual(child1.dump() + child2.dump(), parent.dump())

    def test_oid_map_unmap(self):
        self.assertEqual('abc', MyOids.map('1.2.3'))
        self.assertEqual('def', MyOids.map('4.5.6'))
        self.assertEqual('7.8.9', MyOids.map('7.8.9'))
        self.assertEqual('1.2.3', MyOids.unmap('abc'))
        self.assertEqual('4.5.6', MyOids.unmap('def'))
        self.assertEqual('7.8.9', MyOids.unmap('7.8.9'))

        with self.assertRaises(ValueError):
            MyOids.unmap('no_such_mapping')

    def test_dump_set(self):
        st = SetTest({'two': 2, 'one': 1})
        self.assertEqual(b'1\x06\x81\x01\x01\x82\x01\x02', st.dump())

    def test_dump_set_of(self):
        st = SetOfTest([3, 2, 1])
        self.assertEqual(b'1\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03', st.dump())
