# coding: utf-8
from __future__ import unicode_literals
from __future__ import absolute_import

import sys
import re
from collections import OrderedDict
from datetime import datetime, timedelta, tzinfo
from pprint import pprint

from . import teletex_codec

# Python 2
if sys.version_info <= (3,):
    str_cls = unicode  #pylint: disable=E0602
    byte_cls = str
    py2 = True
    chr_cls = chr
    range = xrange  #pylint: disable=E0602,W0622

    def int_to_bytes(value, signed=False):
        # Handle negatives in two's complement
        if signed and value < 0:
            value = (~value) + 1

        hex_str = '%x' % value
        if len(hex_str) & 1:
            hex_str = '0' + hex_str
        return hex_str.decode('hex')

    def int_from_bytes(value, signed=False):
        num = long(value.encode("hex"), 16)  #pylint: disable=E0602

        if not signed:
            return num

        # Check for sign bit and handle two's complement
        if ord(value[0:1]) & 0x80:
            bit_len = len(value) * 8
            return num - (1 << bit_len)

        return num

    class utc(tzinfo):

        def tzname(self, _):
            return 'UTC+00:00'

        def utcoffset(self, _):
            return timedelta(0)

        def dst(self, _):
            return None

    class timezone():

        utc = utc()

# Python 3
else:
    str_cls = str
    byte_cls = bytes
    py2 = False

    def chr_cls(num):
        return bytes([num])

    def int_to_bytes(value, signed=False):
        result = value.to_bytes((value.bit_length() // 8) + 1, byteorder='big', signed=signed)
        if not signed:
            return result.lstrip(b'\x00')
        return result

    def int_from_bytes(value, signed=False):
        return int.from_bytes(value, 'big', signed=signed)

    from datetime import timezone



teletex_codec.register()


CLASS_NUM_TO_NAME_MAP = {
    0: 'universal',
    1: 'application',
    2: 'context',
    3: 'private',
}

CLASS_NAME_TO_NUM_MAP = {
    'universal': 0,
    'application': 1,
    'context': 2,
    'private': 3,
    0: 0,
    1: 1,
    2: 2,
    3: 3,
}

METHOD_NUM_TO_NAME_MAP = {
    0: 'primitive',
    1: 'constructed',
}


# A global tracker to ensure that _setup() is called for every class, even
# if is has been called for a parent class. This allows different _fields
# definitions for child classes. Without such a construct, the child classes
# would just see the parent class attributes and would use them.
_SETUP_CLASSES = {}


class Asn1Value():
    """
    The basis of all ASN.1 values
    """

    # The integer 0 for primitive, 1 for constructed
    method = None

    # An integer 0 through 3 - see CLASS_NUM_TO_NAME_MAP for value
    class_ = None

    # An integer 1 or greater indicating the tag number
    tag = None

    # A unicode string or None - "explicit" or "implicit" for
    # tagged values, None for normal
    tag_type = None

    # If "explicit"ly tagged, the class and tag for the wrapped header
    explicit_class = None
    explicit_tag = None

    # The BER/DER header bytes
    header = None

    # Raw encoded value bytes not including class, method, tag, length header
    contents = None

    # The BER/DER trailer bytes
    trailer = b''

    # The native python representation of the value
    _native = None

    @classmethod
    def load(cls, encoded_data, **kwargs):
        """
        Loads a BER/DER-encoded byte string using the current class as the spec

        :param encoded_data:
            A byte string of BER or DER encoded data

        :return:
            A instance of the current class
        """

        spec = None
        if cls.tag is not None:
            spec = cls

        value, _ = _parse_build(encoded_data, spec=spec, spec_params=kwargs)
        return value

    #pylint: disable=W0613
    def __init__(self, tag_type=None, class_=None, tag=None, optional=None, default=None):
        """
        The optional parameter is not used, but rather included so we don't
        have to delete it from the parameter dictionary when passing as keyword
        args

        :param tag_type:
            None for normal values, or one of "implicit", "explicit" for tagged
            values

        :param class_:
            The class for the value - defaults to "universal" if tag_type is
            None, otherwise defaults to "context". Valid values include:
             - "universal"
             - "application"
             - "context"
             - "private"

        :param tag:
            The integer tag to override - usually this is used with tag_type or
            class_

        :param optional:
            Dummy parameter that allows "optional" key in spec param dicts

        :param default:
            The default value to use if the value is currently None

        :raises:
            ValueError - when tag_type, class_ or tag are invalid values
        """

        if self.__class__ not in _SETUP_CLASSES:
            cls = self.__class__
            if hasattr(cls, '_setup'):
                self._setup()
            _SETUP_CLASSES[cls] = True

        if tag_type is not None:
            if tag_type not in ('implicit', 'explicit'):
                raise ValueError('tag_type must be one of "implicit", "explicit" - is %s' % repr(tag_type))
            self.tag_type = tag_type

            if class_ is None:
                class_ = 'context'
            if class_ not in CLASS_NAME_TO_NUM_MAP:
                raise ValueError('class_ must be one of "universal", "application", "context", "private" - is %s' % repr(class_))
            class_ = CLASS_NAME_TO_NUM_MAP[class_]

            if tag is not None:
                if not isinstance(tag, int):
                    raise ValueError('tag must be an integer, not %s' % tag.__class__.__name__)

            if tag_type == 'implicit':
                self.class_ = class_
                self.tag = tag
            else:
                self.explicit_class = class_
                self.explicit_tag = tag
        else:
            if class_ is not None:
                if class_ not in CLASS_NUM_TO_NAME_MAP:
                    raise ValueError('class_ must be one of "universal", "application", "context", "private" - is %s' % repr(class_))
                self.class_ = CLASS_NAME_TO_NUM_MAP[class_]

            if tag is not None:
                self.tag = tag

        if default is not None:
            self.set(default)

    def __str__(self):
        """
        Since str is differnt in Python 2 and 3, this calls the appropriate
        method, __unicode__() or __bytes__()

        :return:
            A unicode string
        """

        if py2:
            return self.__bytes__()
        else:
            return self.__unicode__()

    def __repr__(self):
        """
        :return:
            A unicode string
        """
        return '<%s %s>' % (self.__class__.__name__, repr(self.contents))

    def dump(self, force=False, normal_tagging=False):
        """
        Encodes the value using DER

        :param force:
            If the encoded contents already exist, clear them and regenerate
            to ensure they are in DER format instead of BER format

        :param normal_tagging:
            Ignore implicit or explicit tagging when serializing

        :return:
            A byte string of the DER-encoded value
        """

        if (self.header is None) or normal_tagging:
            header = b''
            trailer = b''

            id_num = 0
            id_num |= self.class_ << 6
            id_num |= self.method << 5

            if normal_tagging:
                tag = self.__class__.tag
            else:
                tag = self.tag

            if tag >= 31:
                header += chr_cls(id_num | 31)
                while tag > 0:
                    continuation_bit = 0x80 if tag > 0x7F else 0
                    header += chr_cls(continuation_bit | (tag & 0x7F))
                    tag = tag >> 7
            else:
                header += chr_cls(id_num | tag)

            length = len(self.contents)
            if length <= 127:
                header += chr_cls(length)
            else:
                length_bytes = int_to_bytes(length)
                header += chr_cls(0x80 | len(length_bytes))
                header += length_bytes

            if self.tag_type == 'explicit' and not normal_tagging:
                container = Asn1Value()
                container.method = 1
                container.class_ = self.explicit_class
                container.tag = self.explicit_tag
                container.contents = header + self.contents + trailer
                # Force the container to generate the header and footer
                container.dump()
                header = container.header + header
                trailer += container.trailer

            if not normal_tagging:
                self.header = header
                self.trailer = trailer

        else:
            header = self.header
            trailer = self.trailer

        return header + self.contents + trailer

    def pprint(self):
        """
        Pretty prints the native representation of the value
        """

        pprint(self.native)


class ValueMap():
    """
    Basic functionality that allows for mapping values from ints or OIDs to
    python unicode strings
    """

    # A dict from primitive value (int or OID) to unicode string. This needs
    # to be defined in the source code
    _map = None

    # A dict from unicode string to int/OID. This is automatically generated
    # from _map the first time it is needed
    _reverse_map = None

    #pylint: disable=W0212
    def _setup(self):
        """
        Generates _reverse_map from _map
        """

        cls = self.__class__
        if cls._map is None:
            return
        cls._reverse_map = {}
        for key, value in cls._map.items():
            cls._reverse_map[value] = key


class NoValue(Asn1Value):
    """
    A representation of an optional value that is not present. Has .native
    property and .dump() method to be compatible with other value classes.
    """

    def __len__(self):
        return 0

    @property
    def native(self):
        """
        The a native Python datatype representation of this value

        :return:
            None
        """

        return None

    def dump(self, force=False, normal_tagging=False):
        """
        Encodes the value using DER

        :param force:
            If the encoded contents already exist, clear them and regenerate
            to ensure they are in DER format instead of BER format

        :param normal_tagging:
            Ignore implicit or explicit tagging when serializing

        :return:
            A byte string of the DER-encoded value
        """

        return b''



class Any(Asn1Value):
    """
    A value class that can contain any value, and allows for easy parsing of
    the underlying encoded value using a spec. This is normally contained in
    a Structure that has an ObjectIdentifier field and _oid_pair and _oid_specs
    defined.
    """

    # The parsed value object
    _parsed = None

    @property
    def native(self):
        """
        The a native Python datatype representation of this value

        :return:
            The .native value from the parsed value object
        """

        if self._parsed is None:
            self.parse()

        return self._parsed[0].native

    @property
    def parsed(self):
        """
        Returns the parsed object from .parse()

        :return:
            The object returned by .parse()
        """

        if self._parsed is None:
            self.parse()

        return self._parsed[0]

    def parse(self, spec=None, spec_params=None):
        """
        Parses the contents generically, or using a spec with optional params

        :param spec:
            A class derived from Asn1Value that defines what class_ and tag the
            value should have, and the semantics of the encoded value. The
            return value will be of this type. If omitted, the encoded value
            will be decoded using the standard universal tag based on the
            encoded tag number.

        :param spec_params:
            A dict of params to pass to the spec object

        :return:
            An object of the type spec, or if not present, a child of Asn1Value
        """

        if self._parsed is None or self._parsed[1:3] != (spec, spec_params):
            parsed_value, _ = _parse_build(self.header + self.contents + self.trailer, spec=spec, spec_params=spec_params)
            self._parsed = (parsed_value, spec, spec_params)
        return self._parsed[0]

    def dump(self, force=False, normal_tagging=False):
        """
        Encodes the value using DER

        :param force:
            If the encoded contents already exist, clear them and regenerate
            to ensure they are in DER format instead of BER format

        :param normal_tagging:
            Ignore implicit or explicit tagging when serializing

        :return:
            A byte string of the DER-encoded value
        """

        if self._parsed is None:
            self.parse()

        return self._parsed[0].dump(force=force, normal_tagging=normal_tagging)


class Choice(Asn1Value):
    """
    A class to handle when a value may be one of several options
    """

    # The index in _alternatives of the validated alternative
    _choice = None

    # The name of the chosen alternative
    _name = None

    # The Asn1Value object for the chosen alternative
    _parsed = None

    # A list of tuples in one of the following forms.
    #
    # Option 1, a unicode string field name and a value class
    #
    # ("name", Asn1ValueClass)
    #
    # Option 2, same as Option 1, but with a dict of class params
    #
    # ("name", Asn1ValueClass, {'tag_type': 'explicit', 'tag': 5})
    _alternatives = None

    # A dict that maps tuples of (class_, tag) to an index in _alternatives
    _id_map = None

    # A dict that maps alternative names to an index in _alternatives
    _name_map = None

    #pylint: disable=W0212
    def _setup(self):
        """
        Generates _id_map from _alternatives to allow validating contents
        """

        cls = self.__class__
        cls._id_map = {}
        cls._name_map = {}
        for index, info in enumerate(cls._alternatives):
            params = info[2] if len(info) > 2 else {}
            id_ = _build_id_tuple(params, info[1])
            cls._id_map[id_] = index
            cls._name_map[info[0]] = index

    def __init__(self, name=None, value=None, tag_type=None, **kwargs):
        """
        Checks to ensure implicit tagging is not being used since it is
        incompatible with Choice, then forwards on to Asn1Value.__init__()

        :param name:
            The name of the alternative to be set - used with value

        :param value:
            The alternative value to set - used with name

        :param tag_type:
            The tag_type of the value - None, "implicit" or "explicit"

        :raises:
            ValueError - when tag_type is "implicit"
        """

        if tag_type == 'implicit':
            raise ValueError('The Choice type can not be implicitly tagged even if in an implicit module - due to its nature any tagging must be explicit')
        kwargs['tag_type'] = tag_type
        Asn1Value.__init__(self, **kwargs)

        if name is not None:
            if name not in self._name_map:
                raise ValueError('The name specified, "%s", is not a valid alternative for %s' % (name, self.__class__.__name__))

            self._choice = self._name_map[name]
            info = self._alternatives[self._choice]
            spec = info[1]
            params = {} if len(info) < 3 else info[2]

            if not isinstance(value, spec):
                value = spec(value, **params)
            self._parsed = value

    @property
    def name(self):
        """
        :return:
            A unicode string of the field name of the chosen alternative
        """
        if not self._name:
            self._name = self._alternatives[self._choice][0]
        return self._name

    def parse(self):
        """
        Parses the detected alternative

        :return:
            An Asn1Value object of the chosen alternative
        """

        if self._parsed is not None:
            return self._parsed

        try:
            info = self._alternatives[self._choice]
            params = info[2] if len(info) > 2 else {}
            self._parsed, _ = _parse_build(self.header + self.contents + self.trailer, spec=info[1], spec_params=params)
        except (ValueError) as e:
            args = e.args[1:]
            e.args = (e.args[0] + '\n    while parsing %s' % self.__class__.__name__,) + args
            raise e

    @property
    def chosen(self):
        """
        :return:
            An Asn1Value object of the chosen alternative
        """

        return self.parse()

    @property
    def native(self):
        """
        The a native Python datatype representation of this value

        :return:
            The .native value from the contained value object
        """

        return self.chosen.native

    def validate(self, class_, tag):
        """
        Ensures that the class and tag specified exist as an alternative

        :param class_:
            The integer class_ from the encoded value header

        :param tag:
            The interger tag from the encoded value header

        :raises:
            ValueError - when value is not a valid alternative
        """

        id_ = (class_, tag)

        if id_ in self._id_map:
            self._choice = self._id_map[id_]
            return

        # This means the Choice was implicitly tagged
        if self.class_ is not None and self.tag is not None:
            if len(self._alternatives) > 1:
                raise ValueError('%s was implicitly tagged, but more than one alternative exists' % self.__class__.__name__)
            if id_ == (self.class_, self.tag):
                self._choice = 0
                return

        asn1 = self._format_class_tag(class_, tag)
        asn1s = [self._format_class_tag(id_[0], id_[1]) for id_ in self._id_map]

        raise ValueError('Value %s did not match the class and tag of any of the alternatives in %s: %s' % (asn1, self.__class__.__name__, '. '.join(asn1s)))

    def _format_class_tag(self, class_, tag):
        """
        :return:
            A unicode string of a human-friendly representation of the class and tag
        """

        return '[%s %s]' % (CLASS_NUM_TO_NAME_MAP[class_].upper(), tag)

    def dump(self, force=False, normal_tagging=False):
        """
        Encodes the value using DER

        :param force:
            If the encoded contents already exist, clear them and regenerate
            to ensure they are in DER format instead of BER format

        :param normal_tagging:
            Ignore implicit or explicit tagging when serializing

        :return:
            A byte string of the DER-encoded value
        """

        return self.chosen.dump(force=force, normal_tagging=normal_tagging)


class Primitive(Asn1Value):
    """
    Sets the class_ and method attributes for primitive, universal values
    """

    class_ = 0

    method = 0

    def __init__(self, value=None, default=None, **kwargs):
        """
        Sets the value of the object before passing to Asn1Value.__init__()

        :param value:
            A native Python datatype to initialize the object value with

        :param default:
            The default value if no value is specified
        """

        Asn1Value.__init__(self, **kwargs)

        if value is not None:
            self.set(value)

        elif default is not None:
            self.set(default)

    def set(self, value):
        """
        Sets the value of the object

        :param value:
            A byte string
        """

        if not isinstance(value, byte_cls):
            raise ValueError('%s value must be a byte string, not %s' % (self.__class__.__name__, value.__class__.__name__))

        self._native = value
        self.contents = value
        self.header = None
        if self.trailer != b'':
            self.trailer = b''

    def dump(self, force=False, normal_tagging=False):
        """
        Encodes the value using DER

        :param force:
            If the encoded contents already exist, clear them and regenerate
            to ensure they are in DER format instead of BER format

        :param normal_tagging:
            Ignore implicit or explicit tagging when serializing

        :return:
            A byte string of the DER-encoded value
        """

        if force:
            native = self.native
            self.contents = None
            self.set(native)

        return Asn1Value.dump(self, normal_tagging=normal_tagging)


class AbstractString(Primitive):
    """
    A base class for all strings that have a known encoding. In general, we do
    not worry ourselves with confirming that the decoded values match a specific
    set of characters, only that they are decoded into a Python unicode string
    """

    # The Python encoding name to use when decoding or encoded the contents
    _encoding = 'latin1'

    def set(self, value):
        """
        Sets the value of the string

        :param value:
            A unicode string
        """

        if not isinstance(value, str_cls):
            raise ValueError('%s value must be a unicode string, not %s' % (self.__class__.__name__, value.__class__.__name__))

        self._native = value
        self.contents = value.encode(self._encoding)
        self.header = None
        if self.trailer != b'':
            self.trailer = b''

    def __unicode__(self):
        """
        :return:
            A unicode string
        """
        return self.contents.decode(self._encoding)

    @property
    def native(self):
        """
        The a native Python datatype representation of this value

        :return:
            A unicode string or None
        """

        if self.contents is None:
            return None

        if self._native is None:
            self._native = self.__unicode__()
        return self._native


class Boolean(Primitive):
    """
    Represents a boolean in both ASN.1 and Python
    """

    tag = 1

    def set(self, value):
        """
        Sets the value of the object

        :param value:
            True, False or another value that works with bool()
        """

        self._native = bool(value)
        self.contents = b'\x00' if not value else b'\xff'
        self.header = None
        if self.trailer != b'':
            self.trailer = b''

    # Python 2
    def __nonzero__(self):
        """
        :return:
            True or False
        """
        return self.__bool__()

    def __bool__(self):
        """
        :return:
            True or False
        """
        return self.contents != b'\x00'

    @property
    def native(self):
        """
        The a native Python datatype representation of this value

        :return:
            True, False or None
        """

        if self.contents is None:
            return None

        if self._native is None:
            self._native = self.__bool__()
        return self._native


class Integer(Primitive, ValueMap):
    """
    Represents an integer in both ASN.1 and Python
    """

    tag = 2

    def set(self, value):
        """
        Sets the value of the object

        :param value:
            An integer, or a unicode string if _map is set

        :raises:
            ValueError - when an invalid value is passed
        """

        if isinstance(value, str_cls):
            if self._map is None:
                raise ValueError('%s value is a unicode string, but no _map provided' % self.__class__.__name__)

            if value not in self._reverse_map:
                raise ValueError('%s value, %s, is not present in the _map' % (self.__class__.__name__, value))

            value = self._reverse_map[value]

        elif not isinstance(value, int):
            raise ValueError('%s value must be an integer or unicode string when a name_map is provided' % self.__class__.__name__)

        self._native = self._map[value] if self._map and value in self._map else value

        self.contents = int_to_bytes(value, signed=True)
        self.header = None
        if self.trailer != b'':
            self.trailer = b''

    def __int__(self):
        """
        :return:
            An integer
        """
        return int_from_bytes(self.contents, signed=True)

    @property
    def native(self):
        """
        The a native Python datatype representation of this value

        :return:
            An integer or None
        """

        if self.contents is None:
            return None

        if self._native is None:
            self._native = self.__int__()
            if self._map is not None and self._native in self._map:
                self._native = self._map[self._native]
        return self._native


class BitString(Primitive, ValueMap, object):
    """
    Represents a bit string from ASN.1 as a Python tuple of 1s and 0s
    """

    tag = 3

    def set(self, value):
        """
        Sets the value of the object

        :param value:
            An integer or a tuple of integers 0 and 1

        :raises:
            ValueError - when an invalid value is passed
        """

        if not isinstance(value, int) and not isinstance(value, tuple):
            raise ValueError('%s value must be an integer or a tuple of ones and zeros, not %s' % (self.__class__.__name__, value.__class__.__name__))

        if isinstance(value, tuple):
            self._native = value
            value = ''.join(map(str_cls, value))

        elif isinstance(value, int):
            value = '{0:b}'.format(value)
            self._native = tuple(map(int, tuple(value)))

        size = max(self._map.keys()) + 1
        if len(value) != size:
            raise ValueError('%s value must be %s bits long, specified was only %s long' % (self.__class__.__name__, size, len(value)))

        extra_bits = (size % 8)
        if extra_bits != 0:
            value += '0' * extra_bits

        self.contents = int_to_bytes(extra_bits) + int_to_bytes(int(value, 2))
        self.header = None
        if self.trailer != b'':
            self.trailer = b''

    def __getattr__(self, key):
        """
        Retrieves one of the bits based on a name from the _map

        :param key:
            The unicode string of one of the bit names

        :raises:
            ValueError - when _map is not set or the key name is invalid

        :return:
            A 1 or a 0
        """

        if not isinstance(self._map, dict):
            raise ValueError('%s bit map has not been defined' % self.__class__.__name__)

        if key not in self._map:
            raise ValueError('%s map does not contain an entry for "%s"' % (self.__class__.__name__, key))

        if self._native is None:
            _ = self.native

        return self._native[self._reverse_map[key]]

    def __setattr__(self, key, value):
        """
        Sets one of the bits based on a name from the _map

        :param key:
            The unicode string of one of the bit names

        :param value:
            A 1 or a 0

        :raises:
            ValueError - when _map is not set or the key name is invalid
        """

        if not isinstance(self._map, dict) or key not in self._map:
            return super(BitString, self).__setattr__(key, value)

        if self._native is None:
            _ = self.native

        self._native[self._reverse_map[key]] = 1 if value else 0
        self.set(self._native)

    @property
    def native(self):
        """
        The a native Python datatype representation of this value

        :return:
            The tuple of integers 1 and 0, or None
        """

        # For BitString we default the value to be all zeros
        if self.contents is None:
            size = max(self._map.keys()) + 1
            self.set((0,) * size)

        if self._native is None:
            extra_bits = int_from_bytes(self.contents[0:1])
            bit_string = '{0:b}'.format(int_from_bytes(self.contents[1:]))
            if extra_bits > 0:
                bit_string = bit_string[0:0-extra_bits]
            self._native = tuple(map(int, tuple(bit_string)))
        return self._native


class OctetBitString(Primitive):
    """
    Represents a bit string in ASN.1 as a Python byte string
    """

    tag = 3

    _parsed = None

    def set(self, value):
        """
        Sets the value of the object

        :param value:
            A byte string

        :raises:
            ValueError - when an invalid value is passed
        """

        if not isinstance(value, byte_cls):
            raise ValueError('%s value must be a byte string, not %s' % (self.__class__.__name__, value.__class__.__name__))

        self._native = value
        # Set the unused bits to 0
        self.contents = b'\x00' + value
        self.header = None
        if self.trailer != b'':
            self.trailer = b''

    def parse(self, spec=None, spec_params=None):
        """
        Parses the contents generically, or using a spec with optional params

        :param spec:
            A class derived from Asn1Value that defines what class_ and tag the
            value should have, and the semantics of the encoded value. The
            return value will be of this type. If omitted, the encoded value
            will be decoded using the standard universal tag based on the
            encoded tag number.

        :param spec_params:
            A dict of params to pass to the spec object

        :return:
            An object of the type spec, or if not present, a child of Asn1Value
        """

        if self._parsed is None or self._parsed[1:3] != (spec, spec_params):
            parsed_value, _ = _parse_build(self.__bytes__(), spec=spec, spec_params=spec_params)
            self._parsed = (parsed_value, spec, spec_params)
        return self._parsed[0]

    def __bytes__(self):
        """
        :return:
            A byte string
        """

        # Whenever dealing with octet-based bit strings, we really want the
        # bytes, so we just ignore the unused bits portion since it isn't
        # applicable to the current use case
        # unused_bits = struct.unpack('>B', self.contents[0:1])[0]
        return self.contents[1:]

    @property
    def native(self):
        """
        The a native Python datatype representation of this value

        :return:
            A byte string or None
        """

        if self.contents is None:
            return None

        if self._native is None:
            if self._parsed is not None:
                self._native = self._parsed[0].native
            else:
                self._native = self.__bytes__()
        return self._native

    @property
    def parsed(self):
        """
        Returns the parsed object from .parse()

        :return:
            The object returned by .parse()
        """

        if self._parsed is None:
            self.parse()

        return self._parsed[0]

    def dump(self, force=False, normal_tagging=False):
        """
        Encodes the value using DER

        :param force:
            If the encoded contents already exist, clear them and regenerate
            to ensure they are in DER format instead of BER format

        :param normal_tagging:
            Ignore implicit or explicit tagging when serializing

        :return:
            A byte string of the DER-encoded value
        """

        if force:
            if self._parsed is not None:
                native = self.parsed.dump(force=force)
            else:
                native = self.native
            self.contents = None
            self.set(native)

        return Asn1Value.dump(self, normal_tagging=normal_tagging)


class IntegerBitString(Primitive):
    """
    Represents a bit string in ASN.1 as a Python integer
    """

    tag = 3

    def set(self, value):
        """
        Sets the value of the object

        :param value:
            An integer

        :raises:
            ValueError - when an invalid value is passed
        """

        if not isinstance(value, int):
            raise ValueError('%s value must be an integer, not %s' % (self.__class__.__name__, value.__class__.__name__))

        self._native = value
        # Set the unused bits to 0
        self.contents = b'\x00' + int_to_bytes(value)
        self.header = None
        if self.trailer != b'':
            self.trailer = b''

    @property
    def native(self):
        """
        The a native Python datatype representation of this value

        :return:
            An integer or None
        """

        if self.contents is None:
            return None

        if self._native is None:
            extra_bits = int_from_bytes(self.contents[0:1])
            if extra_bits > 0:
                bit_string = '{0:b}'.format(int_from_bytes(self.contents[1:]))
                bit_string = bit_string[0:0-extra_bits]
                self._native = int(bit_string, 2)
            else:
                self._native = int_from_bytes(self.contents[1:])
        return self._native


class OctetString(Primitive):
    """
    Represents a byte string in both ASN.1 and Python
    """

    tag = 4

    _parsed = None

    def parse(self, spec=None, spec_params=None):
        """
        Parses the contents generically, or using a spec with optional params

        :param spec:
            A class derived from Asn1Value that defines what class_ and tag the
            value should have, and the semantics of the encoded value. The
            return value will be of this type. If omitted, the encoded value
            will be decoded using the standard universal tag based on the
            encoded tag number.

        :param spec_params:
            A dict of params to pass to the spec object

        :return:
            An object of the type spec, or if not present, a child of Asn1Value
        """

        if self._parsed is None or self._parsed[1:3] != (spec, spec_params):
            parsed_value, _ = _parse_build(byte_cls(self), spec=spec, spec_params=spec_params)
            self._parsed = (parsed_value, spec, spec_params)
        return self._parsed[0]

    def __bytes__(self):
        """
        :return:
            A byte string
        """
        return self.contents

    @property
    def native(self):
        """
        The a native Python datatype representation of this value

        :return:
            A byte string or None
        """

        if self.contents is None:
            return None

        if self._native is None:
            if self._parsed is not None:
                self._native = self._parsed[0].native
            else:
                self._native = self.__bytes__()
        return self._native

    @property
    def parsed(self):
        """
        Returns the parsed object from .parse()

        :return:
            The object returned by .parse()
        """

        if self._parsed is None:
            self.parse()

        return self._parsed[0]

    def dump(self, force=False, normal_tagging=False):
        """
        Encodes the value using DER

        :param force:
            If the encoded contents already exist, clear them and regenerate
            to ensure they are in DER format instead of BER format

        :param normal_tagging:
            Ignore implicit or explicit tagging when serializing

        :return:
            A byte string of the DER-encoded value
        """

        if force:
            if self._parsed is not None:
                native = self.parsed.dump(force=force)
            else:
                native = self.native
            self.contents = None
            self.set(native)

        return Asn1Value.dump(self, normal_tagging=normal_tagging)


class IntegerOctetString(OctetString):
    """
    Represents a byte string in ASN.1 as a Python integer
    """

    def set(self, value):
        """
        Sets the value of the object

        :param value:
            An integer

        :raises:
            ValueError - when an invalid value is passed
        """

        if not isinstance(value, int):
            raise ValueError('%s value must be an integer, not %s' % (self.__class__.__name__, value.__class__.__name__))

        self._native = value
        # Set the unused bits to 0
        self.contents = int_to_bytes(value)
        self.header = None
        if self.trailer != b'':
            self.trailer = b''

    @property
    def native(self):
        """
        The a native Python datatype representation of this value

        :return:
            An integer or None
        """

        if self.contents is None:
            return None

        if self._native is None:
            self._native = int_from_bytes(self.contents)
        return self._native


class Null(Primitive):
    """
    Represents a null value in ASN.1 as None in Python
    """

    tag = 5

    contents = b''

    def set(self, value):
        """
        Sets the value of the object

        :param value:
            None
        """

        self.contents = b''

    @property
    def native(self):
        """
        The a native Python datatype representation of this value

        :return:
            None
        """

        return None


class ObjectIdentifier(Primitive, ValueMap):
    """
    Represents an object identifier in ASN.1 as a Python unicode dotted
    integer string
    """

    tag = 6

    def set(self, value):
        """
        Sets the value of the object

        :param value:
            A unicode string. May be a dotted integer string, or if _map is
            provided, one of the mapped values.

        :raises:
            ValueError - when an invalid value is passed
        """

        if not isinstance(value, str_cls):
            raise ValueError('%s value must be a unicode string, not %s' % (self.__class__.__name__, value.__class__.__name__))

        self._native = value

        if self._map is not None:
            if value in self._reverse_map:
                value = self._reverse_map[value]

        self.contents = b''
        first = None
        for index, part in enumerate(value.split('.')):
            part = int(part)

            # The first two parts are merged into a single byte
            if index == 0:
                first = part
                continue
            elif index == 1:
                part = (first * 40) + part

            encoded_part = chr_cls(0x7F & part)
            part = part >> 7
            while part > 0:
                encoded_part = chr_cls(0x80 | (0x7F & part)) + encoded_part
                part = part >> 7
            self.contents += encoded_part

        self.header = None
        if self.trailer != b'':
            self.trailer = b''

    def __unicode__(self):
        """
        :return:
            A unicode string
        """
        output = []

        part = 0
        for byte in self.contents:
            if py2:
                byte = ord(byte)
            part = part * 128
            part += byte & 127
            # Last byte in subidentifier has the eighth bit set to 0
            if byte & 0x80 == 0:
                if len(output) == 0:
                    output.append(str_cls(part // 40))
                    output.append(str_cls(part % 40))
                else:
                    output.append(str_cls(part))
                part = 0

        return '.'.join(output)

    @property
    def native(self):
        """
        The a native Python datatype representation of this value

        :return:
            A unicode string or None. If _map is not defined, the unicode string
            is a string of dotted integers. If _map is defined and the dotted
            string is present in the _map, the mapped value is returned.
        """

        if self.contents is None:
            return None

        if self._native is None:
            self._native = self.__unicode__()
            if self._map is not None and self._native in self._map:
                self._native = self._map[self._native]
        return self._native


class ObjectDescriptor(Primitive):
    """
    Represents an object descriptor from ASN.1 - no Python implementation
    """

    tag = 7


class InstanceOf(Primitive):
    """
    Represents an instance from ASN.1 - no Python implementation
    """

    tag = 8


class Real(Primitive):
    """
    Represents a real number from ASN.1 - no Python implementation
    """

    tag = 9


class Enumerated(Integer):
    """
    Represents a enumerated list of integers from ASN.1 as a Python
    unicode string
    """

    tag = 10

    def set(self, value):
        """
        Sets the value of the object

        :param value:
            An integer or a unicode string from _map

        :raises:
            ValueError - when an invalid value is passed
        """

        if not isinstance(value, int) and not isinstance(value, str_cls):
            raise ValueError('%s value must be an integer or a unicode string, not %s' % (self.__class__.__name__, value.__class__.__name__))

        if isinstance(value, str_cls):
            if value not in self._reverse_map:
                raise ValueError('%s value "%s" is not a valid value' % (self.__class__.__name__, value))

            value = self._reverse_map[value]

        elif value not in self._map:
            raise ValueError('%s value %s is not a valid value' % (self.__class__.__name__, value))

        Integer.set(self, value)

    @property
    def native(self):
        """
        The a native Python datatype representation of this value

        :return:
            A unicode string or None
        """

        if self.contents is None:
            return None

        if self._native is None:
            self._native = self._map[self.__int__()]
        return self._native


class UTF8String(AbstractString):
    """
    Represents a UTF-8 string from ASN.1 as a Python unicode string
    """

    tag = 12
    _encoding = 'utf-8'


class RelativeOid(ObjectIdentifier):
    """
    Represents an object identifier in ASN.1 as a Python unicode dotted
    integer string
    """

    tag = 13


class Sequence(Asn1Value):
    """
    Represents a sequence of fields from ASN.1 as a Python object with a
    dict-like interface
    """

    tag = 16

    class_ = 0
    method = 1

    # A list of child objects, in order of _fields
    children = None

    # A list of tuples in one of the following forms.
    #
    # Option 1, a unicode string field name and a value class
    #
    # ("name", Asn1ValueClass)
    #
    # Option 2, same as Option 1, but with a dict of class params
    #
    # ("name", Asn1ValueClass, {'tag_type': 'explicit', 'tag': 5})
    _fields = []

    # A dict with keys being the name of a field and the value being a unicode
    # string of the method name on self to call to get the spec for that field
    _spec_callbacks = None

    # A dict that maps unicode string field names to an index in _fields
    _field_map = None

    # A list in the same order as _fields that has tuples in the form (class_, tag)
    _field_ids = None

    # An optional 2-element tuple that defines the field names of an OID field
    # and the field that the OID should be used to help decode. Works with the
    # _oid_specs attribute.
    _oid_pair = None

    # A dict with keys that are unicode string OID values and values that are
    # Asn1Value classes to use for decoding a variable-type field.
    _oid_specs = None

    # A 2-element tuple of the indexes in _fields of the OID and value fields
    _oid_nums = None

    def __init__(self, value=None, default=None, **kwargs):
        """
        Allows setting field values before passing everything else along to
        Asn1Value.__init__()

        :param value:
            A native Python datatype to initialize the object value with

        :param default:
            The default value if no value is specified
        """

        Asn1Value.__init__(self, **kwargs)

        if value is None and default is not None:
            value = default

        if value is not None:
            for key, child in value.items():
                self.__setitem__(key, child)

    def _lazy_child(self, index):
        """
        Builds a child object if the child has only been parsed into a tuple so far
        """

        child = self.children[index]
        if isinstance(child, tuple):
            child = _build(*child)
            self.children[index] = child
        return child

    def __len__(self):
        """
        :return:
            Integer
        """
        # We inline this check to prevent method invocation each time
        if self.children is None:
            self._parse_children()

        return len(self.children)

    def __getitem__(self, key):
        """
        Allows accessing fields by name or index

        :param key:
            A unicode string of the field name, or an integer of the field index

        :raises:
            ValueError - when a field name or index is invalid

        :return:
            The Asn1Value object of the field specified
        """

        # We inline this check to prevent method invocation each time
        if self.children is None:
            self._parse_children()

        if not isinstance(key, int):
            if key not in self._field_map:
                raise KeyError('No field named "%s" defined for %s' % (key, self.__class__.__name__))
            key = self._field_map[key]

        if key >= len(self.children):
            raise KeyError('No field numbered %s is present in this %s' % (key, self.__class__.__name__))

        return self._lazy_child(key)

    def __setitem__(self, key, value):
        """
        Allows settings fields by name or index

        :param key:
            A unicode string of the field name, or an integer of the field index

        :param value:
            A native Python datatype to set the field value to. This method will
            construct the appropriate Asn1Value object from _fields.

        :raises:
            ValueError - when a field name or index is invalid
        """

        # We inline this check to prevent method invocation each time
        if self.children is None:
            self._parse_children()

        if not isinstance(key, int):
            if key not in self._field_map:
                raise KeyError('No field named "%s" defined for %s' % (key, self.__class__.__name__))
            key = self._field_map[key]

        field_info = self._fields[key]
        field_spec = field_info[1]
        value_spec = field_spec

        if self._spec_callbacks is not None and field_info[0] in self._spec_callbacks:
            callback = self._spec_callbacks[field_info[0]]
            spec_override = callback(self)
            # Allow a spec callback to specify both the base spec and
            # the override, for situations such as OctetString and parse_as
            if isinstance(spec_override, tuple) and len(spec_override) == 2:
                field_spec, value_spec = spec_override
            else:
                value_spec = spec_override

        elif self._oid_nums is not None and key == self._oid_nums[1]:
            oid = self._lazy_child(self._oid_nums[0]).native
            if oid in self._oid_specs:
                value_spec = self._oid_specs[oid]

        if issubclass(value_spec, Choice):
            if not isinstance(value, Asn1Value):
                raise ValueError('Can not set a native python value to %s, which has the choice type of %s – value must be an instance of Asn1Value' % (field_info[0], value_spec.__name__))
            if not isinstance(value, value_spec):
                wrapper = value_spec()
                wrapper.validate(value.class_, value.tag)
                wrapper._parsed = value  #pylint: disable=W0212
                new_value = wrapper
            else:
                new_value = value

        elif isinstance(value, field_spec):
            new_value = value

        else:
            if isinstance(value, value_spec):
                new_value = value
            else:
                new_value = value_spec(value, **(field_info[2] if len(field_info) > 2 else {}))

            # For when the field is OctetString or OctetBitString with embedded
            # values we need to wrap the value in the field spec to get the
            # appropriate encoded value.
            if field_spec != value_spec and not issubclass(field_spec, Any):
                wrapper = field_spec(value=new_value.dump())
                wrapper._parsed = new_value  #pylint: disable=W0212
                new_value = wrapper

        if new_value.contents is None:
            raise ValueError('Value for field "%s" of %s is not set' % (field_info[0], self.__class__.__name__))

        self.children[key] = new_value

        if self._native is not None:
            self._native[self._fields[key][0]] = self.children[key].native
        self._set_contents()

    def __delitem__(self, key):
        """
        Allows deleting optional or default fields by name or index

        :param key:
            A unicode string of the field name, or an integer of the field index

        :raises:
            ValueError - when a field name or index is invalid, or the field is not optional or defaulted
        """

        # We inline this check to prevent method invocation each time
        if self.children is None:
            self._parse_children()

        if not isinstance(key, int):
            if key not in self._field_map:
                raise KeyError('No field named "%s" defined for %s' % (key, self.__class__.__name__))
            key = self._field_map[key]

        info = self._fields[key]
        if len(info) < 3 or ('default' not in info[2] and 'optional' not in info[2]):
            raise ValueError('Can not delete the value for the field "%s" of %s since it is not optional or defaulted' % (info[0], self.__class__.__name__))

        if 'optional' in info[2]:
            self.children[key] = NoValue()
            if self._native is not None:
                self._native[info[0]] = None
        else:
            self.__setitem__(key, None)
        self._set_contents()

    def __iter__(self):  #pylint: disable=W0234
        """
        :return:
            An iterator of field key names
        """

        for info in self._fields:
            yield info[0]

    def _set_contents(self, force=False):
        """
        Updates the .contents attribute of the value with the encoded value of
        all of the child objects

        :param force:
            Ensure all contents are in DER format instead of possibly using
            cached BER-encoded data
        """

        if self.children is None:
            self._parse_children()

        self.contents = b''
        for index, info in enumerate(self._fields):
            child = self.children[index]
            if child is None:
                child_dump = b''
            elif isinstance(child, tuple):
                if force:
                    child_dump = self._lazy_child(index).dump(force=force)
                else:
                    child_dump = child[3] + child[4] + child[5]
            else:
                child_dump = child.dump(force=force)
            # Skip values that are the same as the default
            if len(info) > 2 and 'default' in info[2]:
                default_value = info[1](**info[2])
                if default_value.dump() == child_dump:
                    continue
            self.contents += child_dump
        self.header = None
        if self.trailer != b'':
            self.trailer = b''

    #pylint: disable=W0212
    def _setup(self):
        """
        Generates _field_map, _field_ids and _oid_nums for use in parsing
        """

        cls = self.__class__
        cls._field_map = {}
        cls._field_ids = []
        for index, field in enumerate(cls._fields):
            cls._field_map[field[0]] = index
            params = field[2] if len(field) > 2 else {}
            cls._field_ids.append(_build_id_tuple(params, field[1]))

        if cls._oid_pair is not None:
            cls._oid_nums = (cls._field_map[cls._oid_pair[0]], cls._field_map[cls._oid_pair[1]])

    def _parse_children(self, recurse=False):
        """
        Parses the contents and generates Asn1Value objects based on the
        definitions from _fields.

        :param recurse:
            If child objects that are Sequence or SequenceOf objects should
            be recursively parsed

        :raises:
            ValueError - when an error occurs parsing child objects
        """

        if self.contents is None:
            self.children = [None] * len(self._fields)
            return

        try:
            self.children = []
            contents_length = len(self.contents)
            child_pointer = 0
            field = 0
            while child_pointer < contents_length:
                parts, num_bytes = _parse(self.contents, pointer=child_pointer)

                if field < len(self._fields):
                    field_info = self._fields[field]
                    field_params = field_info[2] if len(field_info) > 2 else {}

                    field_spec = field_info[1]
                    value_spec = field_spec
                    spec_override = None

                    if self._spec_callbacks is not None and field_info[0] in self._spec_callbacks:
                        callback = self._spec_callbacks[field_info[0]]
                        spec_override = callback(self)
                        if spec_override:
                            # Allow a spec callback to specify both the base spec and
                            # the override, for situations such as OctetString and parse_as
                            if isinstance(spec_override, tuple) and len(spec_override) == 2:
                                field_spec, value_spec = spec_override  #pylint: disable=W0633
                            else:
                                value_spec = spec_override

                    elif self._oid_nums is not None and self._oid_nums[1] == field:
                        oid = self._lazy_child(self._oid_nums[0]).native
                        if oid in self._oid_specs:
                            spec_override = self._oid_specs[oid]
                            value_spec = spec_override

                    # If the next value is optional or default, allow it to not be present
                    if 'optional' in field_params or 'default' in field_params:
                        id_ = (parts[0], parts[2])

                        if self._field_ids[field] != id_ and field_spec != Any:
                            if 'optional' in field_params:
                                self.children.append(NoValue())
                            else:
                                self.children.append(field_spec(**field_params))
                            field += 1
                            continue

                    if field_spec is None or (issubclass(field_spec, Any) and spec_override):
                        field_spec = value_spec
                        spec_override = None

                    if spec_override:
                        child = parts + (field_spec, field_params, value_spec)
                    else:
                        child = parts + (field_spec, field_params)

                else:
                    child = parts

                if recurse:
                    child = _build(*child)
                    if isinstance(child, (Sequence, SequenceOf)):
                        child._parse_children(recurse=True)  #pylint: disable=W0212

                self.children.append(child)
                child_pointer += num_bytes
                field += 1

            total_fields = len(self._fields)
            index = len(self.children)
            while index < total_fields:
                field_info = self._fields[index]
                field_spec = field_info[1]
                field_params = field_info[2] if len(field_info) > 2 else {}
                if 'default' in field_params:
                    self.children.append(field_spec(**field_params))
                else:
                    self.children.append(NoValue())
                index += 1

        except (ValueError) as e:
            args = e.args[1:]
            e.args = (e.args[0] + '\n    while parsing %s' % self.__class__.__name__,) + args
            raise e

    @property
    def native(self):
        """
        The a native Python datatype representation of this value

        :return:
            An OrderedDict or None. If an OrderedDict, all child values are
            recursively converted to native representation also.
        """

        if self.contents is None:
            return None

        if self._native is None:
            if self.children is None:
                self._parse_children(recurse=True)
            self._native = OrderedDict()
            for index, child in enumerate(self.children):
                if isinstance(child, tuple):
                    child = _build(*child)
                    self.children[index] = child
                self._native[self._fields[index][0]] = child.native
        return self._native

    def dump(self, force=False, normal_tagging=False):
        """
        Encodes the value using DER

        :param force:
            If the encoded contents already exist, clear them and regenerate
            to ensure they are in DER format instead of BER format

        :param normal_tagging:
            Ignore implicit or explicit tagging when serializing

        :return:
            A byte string of the DER-encoded value
        """

        if force:
            self._set_contents(force=force)

        return Asn1Value.dump(self, normal_tagging=normal_tagging)


class SequenceOf(Asn1Value):
    """
    Represents a sequence (ordered) of a single type of values from ASN.1 as a
    Python object with a list-like interface
    """

    tag = 16

    class_ = 0
    method = 1

    # A list of child objects
    children = None

    # An Asn1Value class to use when parsing children
    _child_spec = None

    def __init__(self, value=None, default=None, spec=None, **kwargs):
        """
        Allows setting child objects and the _child_spec via the spec parameter
        before passing everything else along to Asn1Value.__init__()

        :param value:
            A native Python datatype to initialize the object value with

        :param default:
            The default value if no value is specified

        :param spec:
            A class derived from Asn1Value to use to parse children
        """

        if spec:
            self._child_spec = spec

        Asn1Value.__init__(self, **kwargs)

        if value is None and default is not None:
            value = default

        if value is not None:
            for index, child in enumerate(value):
                self.__setitem__(index, child)

    def _lazy_child(self, index):
        """
        Builds a child object if the child has only been parsed into a tuple so far
        """

        child = self.children[index]
        if isinstance(child, tuple):
            child = _build(*child)
            self.children[index] = child
        return child

    def __len__(self):
        """
        :return:
            An integer
        """
        # We inline this checks to prevent method invocation each time
        if self.children is None:
            self._parse_children()

        return len(self.children)

    def __getitem__(self, key):
        """
        Allows accessing children via index

        :param key:
            Integer index of child
        """

        # We inline this checks to prevent method invocation each time
        if self.children is None:
            self._parse_children()

        return self._lazy_child(key)

    def __setitem__(self, key, value):
        """
        Allows overriding a child via index

        :param key:
            Integer index of child

        :param value:
            Native python datatype that will be passed to _child_spec to create
            new child object
        """

        # We inline this checks to prevent method invocation each time
        if self.children is None:
            self._parse_children()

        # If adding at the end, create a space for the new value
        if key == len(self.children):
            self.children.append(None)

        if issubclass(self._child_spec, Any):
            if isinstance(value, Asn1Value):
                self.chilren[key] = value
            else:
                raise ValueError('Can not set a native python value to %s where the _child_spec is Any – value must be an instance of Asn1Value' % self.__class__.__name__)

        elif issubclass(self._child_spec, Choice):
            if not isinstance(value, Asn1Value):
                raise ValueError('Can not set a native python value to %s where the _child_spec is the choice type %s – value must be an instance of Asn1Value' % (self.__class__.__name__, self._child_spec.__name__))
            if not isinstance(value, self._child_spec):
                wrapper = self._child_spec()
                wrapper.validate(value.class_, value.tag)
                wrapper._parsed = value  #pylint: disable=W0212
                value = wrapper
            self.children[key] = value

        elif isinstance(value, self._child_spec):
            self.children[key] = value

        else:
            self.children[key] = self._child_spec(value=value)

        if self._native is not None:
            self._native[key] = self.children[key].native
        self._set_contents()

    def __delitem__(self, key):
        """
        Allows removing a child via index

        :param key:
            Integer index of child
        """

        # We inline this checks to prevent method invocation each time
        if self.children is None:
            self._parse_children()

        self.children.remove(key)
        if self._native is not None:
            self._native.remove(key)
        self._set_contents()

    def __iter__(self):  #pylint: disable=W0234
        """
        :return:
            An iter() of child objects
        """

        # We inline this checks to prevent method invocation each time
        if self.children is None:
            self._parse_children()

        for index in range(0, len(self.children)):
            yield self._lazy_child(index)

    def _set_contents(self, force=False):
        """
        Encodes all child objects into the contents for this object

        :param force:
            Ensure all contents are in DER format instead of possibly using
            cached BER-encoded data
        """

        if self.children is None:
            self._parse_children()

        self.contents = b''
        for index, info in enumerate(self._fields):
            child = self.children[index]
            if child is None:
                child_dump = b''
            elif isinstance(child, tuple):
                if force:
                    child_dump = self._lazy_child(index).dump(force=force)
                else:
                    child_dump = child[3] + child[4] + child[5]
            else:
                child_dump = child.dump(force=force)
            # Skip values that are the same as the default
            if len(info) > 2 and 'default' in info[2]:
                default_value = info[1](**info[2])
                if default_value.dump() == child_dump:
                    continue
            self.contents += child_dump
        self.header = None
        if self.trailer != b'':
            self.trailer = b''

    def _parse_children(self, recurse=False):
        """
        Parses the contents and generates Asn1Value objects based on the
        definitions from _child_spec.

        :param recurse:
            If child objects that are Sequence or SequenceOf objects should
            be recursively parsed

        :raises:
            ValueError - when an error occurs parsing child objects
        """

        try:
            self.children = []
            contents_length = len(self.contents)
            child_pointer = 0
            while child_pointer < contents_length:
                parts, num_bytes = _parse(self.contents, pointer=child_pointer)
                if self._child_spec:
                    child = parts + (self._child_spec,)
                else:
                    child = parts
                if recurse:
                    child = _build(*child)
                    if isinstance(child, (Sequence, SequenceOf)):
                        child._parse_children(recurse=True)  #pylint: disable=W0212
                self.children.append(child)
                child_pointer += num_bytes
        except (ValueError) as e:
            args = e.args[1:]
            e.args = (e.args[0] + '\n    while parsing %s' % self.__class__.__name__,) + args
            raise e

    @property
    def native(self):
        """
        The a native Python datatype representation of this value

        :return:
            A list or None. If a list, all child values are recursively
            converted to native representation also.
        """

        if self.contents is None:
            return None

        if self._native is None:
            if self.children is None:
                self._parse_children(recurse=True)
            self._native = [child.native for child in self]
        return self._native

    def dump(self, force=False, normal_tagging=False):
        """
        Encodes the value using DER

        :param force:
            If the encoded contents already exist, clear them and regenerate
            to ensure they are in DER format instead of BER format

        :param normal_tagging:
            Ignore implicit or explicit tagging when serializing

        :return:
            A byte string of the DER-encoded value
        """

        if force:
            self._set_contents(force=force)

        return Asn1Value.dump(self, normal_tagging=normal_tagging)


class Set(Sequence):
    """
    Represents a set of fields (unordered) from ASN.1 as a Python object with a
    dict-like interface
    """

    method = 1
    class_ = 0
    tag = 17

    # A dict of 2-element tuples in the form (class_, tag) as keys and integers
    # as values that are the index of the field in _fields
    _field_ids = None

    #pylint: disable=W0212
    def _setup(self):
        """
        Generates _field_map, _field_ids and _oid_nums for use in parsing
        """

        cls = self.__class__
        cls._field_map = {}
        cls._field_ids = {}
        for index, field in enumerate(cls._fields):
            cls._field_map[field[0]] = index
            params = field[2] if len(field) > 2 else {}
            cls._field_ids[_build_id_tuple(params, field[1])] = index

        if cls._oid_pair is not None:
            cls._oid_nums = (cls._field_map[cls._oid_pair[0]], cls._field_map[cls._oid_pair[1]])

    def _parse_children(self, recurse=False):
        """
        Parses the contents and generates Asn1Value objects based on the
        definitions from _fields.

        :param recurse:
            If child objects that are Sequence or SequenceOf objects should
            be recursively parsed

        :raises:
            ValueError - when an error occurs parsing child objects
        """

        try:
            child_map = {}
            contents_length = len(self.contents)
            child_pointer = 0
            while child_pointer < contents_length:
                parts, num_bytes = _parse(self.contents, pointer=child_pointer)

                id_ = (parts[0], parts[2])

                field = self._field_ids[id_]
                field_info = self._fields[field]
                field_params = field_info[2] if len(field_info) > 2 else {}

                spec = field_info[1]
                parse_as = None

                if self._oid_nums is not None and self._oid_nums[1] == field:
                    oid = self.children[self._oid_nums[0]].native
                    if isinstance(spec, Any):
                        spec = self._oid_specs[oid]
                    else:
                        parse_as = self._oid_specs[oid]

                if parse_as:
                    child = parts + (spec, field_params, parse_as)
                else:
                    child = parts + (spec, field_params)

                if recurse:
                    child = _build(*child)
                    if isinstance(child, (Sequence, SequenceOf)):
                        child._parse_children(recurse=True)  #pylint: disable=W0212

                child_map[field] = child
                child_pointer += num_bytes

            total_fields = len(self._fields)

            for index in range(0, total_fields):
                if index in child_map:
                    continue
                field_info = self._fields[index]

                missing = False

                if len(field_info) < 3:
                    missing = True
                elif 'optional' not in field_info[2] and 'default' not in field_info[2]:
                    missing = True
                elif 'optional' in field_info[2]:
                    child_map[index] = NoValue()
                elif 'default' in field_info[2]:
                    child_map[index] = field_info[1](**field_info[2])

                if missing:
                    raise ValueError('Missing required field "%s" from %s' % (field_info[0], self.__class__.__name__))

            self.children = []
            for index in range(0, total_fields):
                self.children.append(child_map[index])

        except (ValueError) as e:
            args = e.args[1:]
            e.args = (e.args[0] + '\n    while parsing %s' % self.__class__.__name__,) + args
            raise e


class SetOf(SequenceOf):
    """
    Represents a set (unordered) of a single type of values from ASN.1 as a
    Python object with a list-like interface
    """

    tag = 17


class EmbeddedPdv(Sequence):
    """
    A sequence structure
    """

    tag = 11


class NumericString(AbstractString):
    """
    Represents a numeric string from ASN.1 as a Python unicode string
    """

    tag = 18
    _encoding = 'latin1'


class PrintableString(AbstractString):
    """
    Represents a printable string from ASN.1 as a Python unicode string
    """

    tag = 19
    _encoding = 'latin1'


class TeletexString(AbstractString):
    """
    Represents a teletex string from ASN.1 as a Python unicode string
    """

    tag = 20
    _encoding = 'teletex'


class VideotexString(OctetString):
    """
    Represents a videotex string from ASN.1 as a Python byte string
    """

    tag = 21


class IA5String(AbstractString):
    """
    Represents an IA5 string from ASN.1 as a Python unicode string
    """

    tag = 22
    _encoding = 'latin1'


class AbstractTime(AbstractString):
    """
    Represents a time from ASN.1 as a Python datetime.datetime object
    """

    @property
    def native(self):
        """
        The a native Python datatype representation of this value

        :return:
            A datetime.datetime object in the UTC timezone or None
        """

        if self.contents is None:
            return None

        if self._native is None:
            string = str_cls(self)
            has_timezone = re.search('[-\\+]', string)

            # We don't know what timezone it is in, or it is UTC because of a Z
            # suffix, so we just assume UTC
            if not has_timezone:
                string = string.rstrip('Z')
                date = self._date_by_len(string)
                self._native = date.replace(tzinfo=timezone.utc)

            else:
                # Python 2 doesn't support the %z format code, so we have to manually
                # process the timezone offset.
                date = self._date_by_len(string[0:-5])

                hours = int(string[-4:-2])
                minutes = int(string[-2:])
                delta = timedelta(hours=abs(hours), minutes=minutes)
                if hours < 0:
                    date -= delta
                else:
                    date += delta

                self._native = date.replace(tzinfo=timezone.utc)

        return self._native


class UTCTime(AbstractTime):
    """
    Represents a UTC time from ASN.1 as a Python datetime.datetime object in UTC
    """

    tag = 23

    def set(self, value):
        """
        Sets the value of the object

        :param value:
            A unicode string or a datetime.datetime object

        :raises:
            ValueError - when an invalid value is passed
        """

        if isinstance(value, datetime):
            value = value.strftime('%y%m%d%H%M%SZ')

        AbstractString.set(self, value)
        # Set it to None and let the class take care of converting the next
        # time that .native is called
        self._native = None

    def _date_by_len(self, string):
        """
        Parses a date from a string based on its length

        :param string:
            A unicode string to parse

        :return:
            A datetime.datetime object or a unicode string
        """

        strlen = len(string)

        if strlen == 10:
            return datetime.strptime(string, '%y%m%d%H%M')

        if strlen == 12:
            return datetime.strptime(string, '%y%m%d%H%M%S')

        return string

class GeneralizedTime(AbstractTime):
    """
    Represents a generalized time from ASN.1 as a Python datetime.datetime
    object in UTC
    """

    tag = 24

    def set(self, value):
        """
        Sets the value of the object

        :param value:
            A unicode string or a datetime.datetime object

        :raises:
            ValueError - when an invalid value is passed
        """

        if isinstance(value, datetime):
            value = value.strftime('%Y%m%d%H%M%SZ')

        AbstractString.set(self, value)
        # Set it to None and let the class take care of converting the next
        # time that .native is called
        self._native = None

    def _date_by_len(self, string):
        """
        Parses a date from a string based on its length

        :param string:
            A unicode string to parse

        :return:
            A datetime.datetime object or a unicode string
        """

        strlen = len(string)

        if strlen == 10:
            return datetime.strptime(string, '%Y%m%d%H')

        if strlen == 12:
            return datetime.strptime(string, '%Y%m%d%H%M')

        if strlen == 14:
            return datetime.strptime(string, '%Y%m%d%H%M%S')

        if strlen == 18:
            return datetime.strptime(string, '%Y%m%d%H%M%S.%f')

        return string


class GraphicString(AbstractString):
    """
    Represents a graphic string from ASN.1 as a Python unicode string
    """

    tag = 25
    # This is technically not correct since this type can contain any charset
    _encoding = 'latin1'


class VisibleString(AbstractString):
    """
    Represents a visible string from ASN.1 as a Python unicode string
    """

    tag = 26
    _encoding = 'latin1'


class GeneralString(AbstractString):
    """
    Represents a general string from ASN.1 as a Python unicode string
    """

    tag = 27
    # This is technically not correct since this type can contain any charset
    _encoding = 'latin1'


class UniversalString(AbstractString):
    """
    Represents a universal string from ASN.1 as a Python unicode string
    """

    tag = 28
    _encoding = 'utf-32-be'


class CharacterString(AbstractString):
    """
    Represents a character string from ASN.1 as a Python unicode string
    """

    tag = 29
    # This is technically not correct since this type can contain any charset
    _encoding = 'latin1'


class BMPString(AbstractString):
    """
    Represents a BMP string from ASN.1 as a Python unicode string
    """

    tag = 30
    _encoding = 'utf-16-be'


def _build_id_tuple(params, spec):
    """
    Builds a 2-element tuple used to identify fields by grabbing the class_
    and tag from an Asn1Value class and the params dict being passed to it

    :param params:
        A dict of params to pass to spec

    :param spec:
        An Asn1Value class

    :return:
        A 2-element integer tuple in the form (class_, tag)
    """

    # Handle situations where the the spec is not known at setup time
    if spec is None:
        return (None, None)

    required_class = spec.class_
    required_tag = spec.tag

    tag_type = params.get('tag_type', spec.tag_type)
    if tag_type is not None:
        required_class = 2

    required_class = params.get('class_', required_class)
    required_tag = params.get('tag', required_tag)

    return (required_class, required_tag)


def _parse_id(encoded_data, pointer):
    """
    Peeks ahead into a byte string and parses the ASN.1 header

    :param encoded_data:
        A byte string

    :param pointer:
        The index in the byte string to parse the header from

    :return:
        A 4-element tuple of (class_, method, tag, number_of_bytes_consumed)
    """

    original_pointer = pointer

    first_octet = ord(encoded_data[pointer:pointer+1])
    pointer += 1

    class_ = first_octet >> 6
    method = (first_octet >> 5) & 1

    tag = first_octet & 31
    # Base 128 length using 8th bit as continuation indicator
    if tag == 31:
        tag = 0
        while True:
            num = ord(encoded_data[pointer:pointer+1])
            pointer += 1
            tag *= 128
            tag += num & 127
            if num >> 7 == 0:
                break

    num_bytes = pointer - original_pointer

    return (class_, method, tag, num_bytes)


def _build(class_, method, tag, header, contents, trailer, spec=None, spec_params=None, nested_spec=None):
    """
    Builds an Asn1Value object generically, or using a spec with optional params

    :param class_:
        An integer representing the ASN1 class

    :param method:
        An integer representing the ASN1 method

    :param tag:
        An integer representing the ASN1 tag

    :param header:
        A byte string of the ASN1 header (class, method, tag, length)

    :param contents:
        A byte string of the ASN1 value

    :param trailer:
        A byte string of any ASN1 trailer (only used by indefinite length encodings)

    :param spec:
        A class derived from Asn1Value that defines what class_ and tag the
        value should have, and the semantics of the encoded value. The
        return value will be of this type. If omitted, the encoded value
        will be decoded using the standard universal tag based on the
        encoded tag number.

    :param spec_params:
        A dict of params to pass to the spec object

    :param nested_spec:
        For certain Asn1Value classes (such as OctetString and BitString), the
        contents can be further parsed and interpreted as another Asn1Value.
        This parameter controls the spec for that sub-parsing.

    :return:
        An object of the type spec, or if not specified, a child of Asn1Value
    """

    if header is None:
        return NoValue()

    # If an explicit specification was passed in, make sure it matches
    if spec is not None:
        if spec_params:
            value = spec(**spec_params)
        else:
            value = spec()

        if isinstance(value, Any):
            pass

        elif value.tag_type == 'explicit':
            if class_ != value.explicit_class:
                raise ValueError(
                    'Error parsing %s - explicitly-tagged class should have been %s, but %s was found' %
                    (
                        value.__class__.__name__,
                        CLASS_NUM_TO_NAME_MAP.get(value.explicit_class),
                        CLASS_NUM_TO_NAME_MAP.get(class_, class_)
                    )
                )
            if method != 1:
                raise ValueError(
                    'Error parsing %s - explicitly-tagged method should have been %s, but %s was found' %
                    (
                        value.__class__.__name__,
                        METHOD_NUM_TO_NAME_MAP.get(1),
                        METHOD_NUM_TO_NAME_MAP.get(method, method)
                    )
                )
            if tag != value.explicit_tag:
                raise ValueError(
                    'Error parsing %s - explicitly-tagged tag should have been %s, but %s was found' %
                    (
                        value.__class__.__name__,
                        value.explicit_tag,
                        tag
                    )
                )

        elif isinstance(value, Choice):
            value.validate(class_, tag)

        else:
            if class_ != value.class_:
                raise ValueError(
                    'Error parsing %s - class should have been %s, but %s was found' %
                    (
                        value.__class__.__name__,
                        CLASS_NUM_TO_NAME_MAP.get(value.class_),
                        CLASS_NUM_TO_NAME_MAP.get(class_, class_)
                    )
                )
            if method != value.method:
                raise ValueError(
                    'Error parsing %s - method should have been %s, but %s was found' %
                    (
                        value.__class__.__name__,
                        METHOD_NUM_TO_NAME_MAP.get(value.method),
                        METHOD_NUM_TO_NAME_MAP.get(method, method)
                    )
                )
            if tag != value.tag:
                raise ValueError(
                    'Error parsing %s - tag should have been %s, but %s was found' %
                    (
                        value.__class__.__name__,
                        value.tag,
                        tag
                    )
                )

    # If no spec was specified, allow anything and just process what
    # is in the input data
    else:
        spec = {
            1: Boolean,
            2: Integer,
            3: BitString,
            4: OctetString,
            5: Null,
            6: ObjectIdentifier,
            7: ObjectDescriptor,
            8: InstanceOf,
            9: Real,
            10: Enumerated,
            11: EmbeddedPdv,
            12: UTF8String,
            13: RelativeOid,
            16: Sequence,
            17: Set,
            18: NumericString,
            19: PrintableString,
            20: TeletexString,
            21: VideotexString,
            22: IA5String,
            23: UTCTime,
            24: GeneralizedTime,
            25: GraphicString,
            26: VisibleString,
            27: GeneralString,
            28: UniversalString,
            29: CharacterString,
            30: BMPString
        }[tag]

        value = spec(class_=class_)

    value.header = header
    value.contents = contents
    if trailer is not None and trailer != b'':
        value.trailer = trailer

    # Destroy any default value that our contents have overwritten
    value._native = None  #pylint: disable=W0212

    # For explicitly tagged values, parse the inner value and pull it out
    if value.tag_type == 'explicit':
        original_value = value
        (class_, method, tag, header, contents, trailer), _ = _parse(value.contents)
        value = _build(class_, method, tag, header, contents, trailer, spec=spec)
        value.header = original_value.header + header
        value.trailer += original_value.trailer
        value.tag_type = 'explicit'
        value.explicit_class = original_value.explicit_class
        value.explicit_tag = original_value.explicit_tag

    # Force parsing the Choice now
    if isinstance(value, Choice):
        value.parse()

    if nested_spec:
        value.parse(nested_spec)

    return value


def _parse(encoded_data, pointer=0):
    """
    Parses a byte string into component parts

    :param encoded_data:
        A byte string that contains BER-encoded data

    :param pointer:
        The index in the byte string to parse from

    :return:
        A 2-element tuple:
         - 0: A tuple of (class_, method, tag, header, content, trailer)
         - 1: An integer indicating how many bytes were consumed
    """

    if len(encoded_data) == 0:
        return ((None, None, None, None, None, None), 0)

    start = pointer

    class_, method, tag, num_bytes = _parse_id(encoded_data, pointer)
    pointer += num_bytes

    length_octet = ord(encoded_data[pointer:pointer+1])
    pointer += 1
    length_type = length_octet >> 7
    if length_type == 1:
        length = 0
        remaining_length_octets = length_octet & 127
        while remaining_length_octets > 0:
            length *= 256
            length += ord(encoded_data[pointer:pointer+1])
            pointer += 1
            remaining_length_octets -= 1
    else:
        length = length_octet & 127

    header = encoded_data[start:pointer]

    # Indefinite length
    if length_type == 1 and length == 0:
        end_token = encoded_data.find(b'\x00\x00', pointer)
        contents = encoded_data[pointer:end_token]
        pointer = end_token + 2
        trailer = b'\x00\x00'
    else:
        contents = encoded_data[pointer:pointer+length]
        pointer += length
        trailer = b''

    num_bytes = pointer - start

    return ((class_, method, tag, header, contents, trailer), num_bytes)


def _parse_build(encoded_data, pointer=0, spec=None, spec_params=None):
    """
    Parses a byte string generically, or using a spec with optional params

    :param encoded_data:
        A byte string that contains BER-encoded data

    :param pointer:
        The index in the byte string to parse from

    :param spec:
        A class derived from Asn1Value that defines what class_ and tag the
        value should have, and the semantics of the encoded value. The
        return value will be of this type. If omitted, the encoded value
        will be decoded using the standard universal tag based on the
        encoded tag number.

    :param spec_params:
        A dict of params to pass to the spec object

    :return:
        A 2-element tuple:
         - 0: An object of the type spec, or if not specified, a child of Asn1Value
         - 1: An integer indicating how many bytes were consumed
    """

    (class_, method, tag, header, contents, trailer), num_bytes = _parse(encoded_data, pointer)
    value = _build(class_, method, tag, header, contents, trailer, spec=spec, spec_params=spec_params)
    return (value, num_bytes)
