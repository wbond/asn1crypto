# Universal Types with BER/DER Decoder and DER Encoder

The *asn1crypto* library is a combination of universal type classes that
implement BER/DER decoding and DER encoding, a PEM encoder and decoder, and a
number of pre-built cryptographic type classes. This document covers the
universal type classes.

For a general overview of ASN.1 as used in cryptography, please see
[A Layman's Guide to a Subset of ASN.1, BER, and DER](http://luca.ntop.org/Teaching/Appunti/asn1.html).

## Universal Types

For general purpose ASN.1 parsing, the `asn1crypto.core` module is used. It
contains the following classes, that parse, represent and serialize all of the
ASN.1 universal types:

| Class              | Native Type                            | Implementation Notes                 |
| ------------------ | -------------------------------------- | ------------------------------------ |
| `Boolean`          | `bool`                                 |                                      |
| `Integer`          | `int`                                  | may be `long` on Python 2            |
| `BitString`        | `tuple` of `int` or `set` of `unicode` | `set` used if `_map` present         |
| `OctetString`      | `bytes` (`str`)                        |                                      |
| `Null`             | `None`                                 |                                      |
| `ObjectIdentifier` | `str` (`unicode`)                      | string is dotted integer format      |
| `ObjectDescriptor` |                                        | no native conversion                 |
| `InstanceOf`       |                                        | no native conversion                 |
| `Real`             |                                        | no native conversion                 |
| `Enumerated`       | `str` (`unicode`)                      | `_map` must be set                   |
| `UTF8String`       | `str` (`unicode`)                      |                                      |
| `RelativeOid`      | `str` (`unicode`)                      | string is dotted integer format      |
| `Sequence`         | `OrderedDict`                          |                                      |
| `SequenceOf`       | `list`                                 |                                      |
| `Set`              | `OrderedDict`                          |                                      |
| `SetOf`            | `list`                                 |                                      |
| `EmbeddedPdv`      | `OrderedDict`                          | no named field parsing               |
| `NumericString`    | `str` (`unicode`)                      | no charset limitations               |
| `PrintableString`  | `str` (`unicode`)                      | no charset limitations               |
| `TeletexString`    | `str` (`unicode`)                      |                                      |
| `VideotexString`   | `bytes` (`str`)                        | no unicode conversion                |
| `IA5String`        | `str` (`unicode`)                      |                                      |
| `UTCTime`          | `datetime.datetime`                    |                                      |
| `GeneralizedTime`  | `datetime.datetime`                    | treated as UTC when no timezone      |
| `GraphicString`    | `str` (`unicode`)                      | unicode conversion as latin1         |
| `VisibleString`    | `str` (`unicode`)                      | no charset limitations               |
| `GeneralString`    | `str` (`unicode`)                      | unicode conversion as latin1         |
| `UniversalString`  | `str` (`unicode`)                      |                                      |
| `CharacterString`  | `str` (`unicode`)                      | unicode conversion as latin1         |
| `BMPString`        | `str` (`unicode`)                      |                                      |

For *Native Type*, the Python 3 type is listed first, with the Python 2 type
in parentheses.

As mentioned next to some of the types, value parsing may not be implemented
for types not currently used in cryptography (such as `ObjectDescriptor`,
`InstanceOf` and `Real`). Additionally some of the string classes don't
enforce character set limitations, and for some string types that accept all
different encodings, the default encoding is set to latin1.

In addition, there are a few overridden types where various specifications use
a `BitString` or `OctetString` type to represent a different type. These
include:

| Class                | Native Type         | Implementation Notes            |
| -------------------- | ------------------- | ------------------------------- |
| `OctetBitString`     | `bytes` (`str`)     |                                 |
| `IntegerBitString`   | `int`               | may be `long` on Python 2       |
| `IntegerOctetString` | `int`               | may be `long` on Python 2       |

## Basic Usage

All of the universal types implement two methods, the class method `.load()` for
parsing and the instance method `.dump()` for serialization.

```python
from asn1crypto.core import Sequence

parsed = Sequence.load(der_byte_string)
serialized = parsed.dump()
```

In addition to the two primary methods, every instance has a `.native` property
that converts the data into a native Python data type.

```python
import pprint
from asn1crypto.core import Sequence

parsed = Sequence.load(der_byte_string)
pprint(parsed.native)
```

## Sequence

One of the core structures when dealing with ASN.1 is the Sequence type. The
`Sequence` class can handle field with universal data types, however in most
situations the `_fields` property will need to be set with the expected
definition of each field in the Sequence.

### Configuration

The `_fields` property must be set to a `list` of 2-3 element `tuple`s. The
first element in the tuple must be a unicode string of the field name. The
second must be a type class - either a universal type, or a custom type. The
third, and optional, element is a `dict` with parameters to pass to the type
class for things like default values, marking the field as optional, or
implicit/explicit tagging.

```python
from asn1crypto.core import Sequence, Integer, OctetString, IA5String

class MySequence(Sequence):
    _fields = [
        ('field_one', Integer),
        ('field_two', OctetString),
        ('field_three', IA5String, {'optional': True}),
    ]
```

Implicit and explicit tagging will be covered in more detail later, however
the following are options that can be set for each field type class:

 - `{'default: 1}` sets the field's default value to `1`, allowing it to be
   omitted from the serialized form
 - `{'optional': True}` set the field to be optional, allowing it to be
   omitted

### Usage

To access values of the sequence, use dict-like access via `[]` and use the
name of the field:

```python
seq = MySequence.load(der_byte_string)
print(seq['field_two'].native)
```

The values of fields can be set by assigning via `[]`. If the value assigned is
of the correct type class, it will be used as-is. If the value is not of the
correct type class, a new instance of that type class will be created and the
value will be passed to the constructor.

```python
seq = MySequence.load(der_byte_string)
# These statements will result in the same state
seq['field_one'] = Integer(5)
seq['field_one'] = 5
```

When fields are complex types such as `Sequence` or `SequenceOf`, there is no
way to construct the value out of a native Python data type.

### Optional Fields

When a field is configured via the `optional` parameter, not present in the
`Sequence`, but accessed, an instance of the `NoValue` class will be returned.
This class is serialized to an empty byte string and returns `None` when
`.native` is accessed.

## Set

The `Set` class is configured in the same was as `Sequence`, however it allows
serialized fields to be in any order, per the ASN.1 standard.

```python
from asn1crypto.core import Set, Integer, OctetString, IA5String

class MySet(Set):
    _fields = [
        ('field_one', Integer),
        ('field_two', OctetString),
        ('field_three', IA5String, {'optional': True}),
    ]
```

## SequenceOf

The `SequenceOf` class is used to allow for zero or more instances of a type.
The class uses the `_child_spec` property to define the instance class type.

```python
from asn1crypto.core import SequenceOf, Integer

class Integers(SequenceOf):
    _child_spec = Integer
```

Values in the `SequenceOf` can be accessed via `[]` with an integer key. The
length of the `SequenceOf` is determined via `len()`.

```python
values = Integers.load(der_byte_string)
for i in range(0, len(values)):
    print(values[i].native)
```

## SetOf

The `SetOf` class is an exact duplicate of `SequenceOf`. According to the ASN.1
standard, the difference is that a `SequenceOf` is explicitly ordered, however
`SetOf` may be in any order. This is an equivalent comparison of a Python `list`
and `set`.

```python
from asn1crypto.core import SetOf, Integer

class Integers(SetOf):
    _child_spec = Integer
```

## Integer

The `Integer` class allows values to be *named*. An `Integer` with named values
may contain any integer, however special values with named will be represented
as those names when `.native` is called.

Named values are configured via the `_map` property, which must be a `dict`
with the keys being integers and the values being unicode strings.

```python
from asn1crypto.core import Integer

class Version(Integer):
    _map = {
        1: 'v1',
        2: 'v2',
    }

# Will print: "v1"
print(Version(1).native)

# Will print: 4
print(Version(4).native)
```

## Enumerated

The `Enumerated` class is almost identical to `Integer`, however only values in
the `_map` property are valid.

```python
from asn1crypto.core import Enumerated

class Version(Enumerated):
    _map = {
        1: 'v1',
        2: 'v2',
    }

# Will print: "v1"
print(Version(1).native)

# Will raise a ValueError exception
print(Version(4).native)
```

## ObjectIdentifier

The `ObjectIdentifier` class represents values of the ASN.1 type of the same
name. `ObjectIdentifier` instances are converted to a unicode string in a
dotted-integer format when `.native` is accessed.

While this standard conversion is a reasonable baseline, in most situations
it will be more maintainable to map the OID strings to a unicode string
containing a description of what the OID repesents.

The mapping of OID strings to name strings is configured via the `_map`
property, which is a `dict` object with keys being unicode OID string and the
values being a unicode string.

```python
from asn1crypto.core import ObjectIdentifier

class MyType(ObjectIdentifier):
    _map = {
        '1.8.2.1.23': 'value_name',
        '1.8.2.1.24': 'other_value',
    }

# Will print: "value_name"
print(MyType('1.8.2.1.23').native)

# Will print: "1.8.2.1.25"
print(MyType('1.8.2.1.25').native)
```

## BitString

When no `_map` is set for a `BitString` class, the native representation is a
`tuple` of `int`s (being either `1` or `0`).

```python
from asn1crypto.core import BitString

b1 = BitString((1, 0, 1))
```

Additionally, it is possible to set the `_map` property to a dict where the
keys are bit indexes and the values are unicode string names. This allows
checking the value of a given bit by item access, and the native representation
becomes a `set` of unicode strings.

```python
from asn1crypto.core import BitString

class MyFlags(BitString):
    _map = {
        0: 'edit',
        1: 'delete',
        2: 'manage_users',
    }

permissions = MyFlags({'edit', 'delete'})

# This will be printed
if permissions['edit'] and permissions['delete']:
    print('Can edit and delete')

# This will not
if 'manage_users' in permissions.native:
    print('Is admin')
```

## Strings

ASN.1 contains quite a number of string types:

| Type              | Standard Encoding                 | Implementation Encoding | Notes                                                                     |
| ----------------- | --------------------------------- | ----------------------- | ------------------------------------------------------------------------- |
| `UTF8String`      | UTF-8                             | UTF-8                   |                                                                           |
| `NumericString`   | ASCII `[0-9 ]`                    | ISO 8859-1              | The implementation is a superset of supported characters                  |
| `PrintableString` | ASCII `[a-zA-Z0-9 '()+,\\-./:=?]` | ISO 8859-1              | The implementation is a superset of supported characters                  |
| `TeletexString`   | ITU T.61                          | Custom                  | The implementation is based off of https://en.wikipedia.org/wiki/ITU_T.61 |
| `VideotexString`  | *?*                               | *None*                  | This has no set encoding, and it not used in cryptography                 |
| `IA5String`       | ITU T.50 (very similar to ASCII)  | ISO 8859-1              | The implementation is a superset of supported characters                  |
| `GraphicString`   | *                                 | ISO 8859-1              | This has not set encoding, but seems to often contain ISO 8859-1          |
| `VisibleString`   | ASCII (printable)                 | ISO 8859-1              | The implementation is a superset of supported characters                  |
| `GeneralString`   | *                                 | ISO 8859-1              | This has not set encoding, but seems to often contain ISO 8859-1          |
| `UniversalString` | UTF-32                            | UTF-32                  |                                                                           |
| `CharacterString` | *                                 | ISO 8859-1              | This has not set encoding, but seems to often contain ISO 8859-1          |
| `BMPString`       | UTF-16                            | UTF-16                  |                                                                           |

As noted in the table above, many of the implementations are supersets of the
supported characters. This simplifies parsing, but puts the onus of using valid
characters on the developer. However, in general `UTF8String`, `BMPString` or
`UniversalString` should be preferred when a choice is given.

All string types other than `VideotexString` are created from unicode strings.

```python
from asn1crypto.core import IA5String

print(IA5String('Testing!').native)
```

## UTCTime

The class `UTCTime` accepts a unicode string in one of the formats:

 - `%y%m%d%H%MZ`
 - `%y%m%d%H%M%SZ`
 - `%y%m%d%H%M%z`
 - `%y%m%d%H%M%S%z`

or a `datetime.datetime` instance. See the
[Python datetime strptime() reference](https://docs.python.org/3/library/datetime.html#strftime-and-strptime-behavior)
for details of the formats.

When `.native` is accessed, it returns a `datetime.datetime` object with a
`tzinfo` of `asn1crypto.util.timezone.utc`.

## GeneralizedTime

The class `GeneralizedTime` accepts a unicode string in one of the formats:

 - `%Y%m%d%H`
 - `%Y%m%d%H%M`
 - `%Y%m%d%H%M%S`
 - `%Y%m%d%H%M%S.%f`
 - `%Y%m%d%HZ`
 - `%Y%m%d%H%MZ`
 - `%Y%m%d%H%M%SZ`
 - `%Y%m%d%H%M%S.%fZ`
 - `%Y%m%d%H%z`
 - `%Y%m%d%H%M%z`
 - `%Y%m%d%H%M%S%z`
 - `%Y%m%d%H%M%S.%f%z`

or a `datetime.datetime` instance. See the
[Python datetime strptime() reference](https://docs.python.org/3/library/datetime.html#strftime-and-strptime-behavior)
for details of the formats.

When `.native` is accessed, it returns a `datetime.datetime` object with a
`tzinfo` of `asn1crypto.util.timezone.utc`. For formats where the time has a
timezone offset is specified (`[+-]\d{4}`), the time is converted to UTC. For
times without a timezone, the time is assumed to be in UTC.

## Choice

The `Choice` class allows handling ASN.1 Choice structures. The `_alternatives`
property must be set to a `list` containing 2-3 element `tuple`s. The first
element in the tuple is the alternative name. The second element is the type
class for the alternative. The, optional, third element is a `dict` of
parameters to pass to the type class constructor. This is used primarily for
implicit and explicit tagging.

```python
from asn1crypto.core import Choice, Integer, OctetString, IA5String

class MyChoice(Choice):
    _alternatives = [
        ('option_one', Integer),
        ('option_two', OctetString),
        ('option_three', IA5String),
    ]
```

`Choice` objects has two extra properties, `.name` and `.chosen`. The `.name`
property contains the name of the chosen alternative. The `.chosen` property
contains the instance of the chosen type class.

```python
parsed = MyChoice.load(der_bytes)
print(parsed.name)
print(type(parsed.chosen))
```

The `.native` property and `.dump()` method work as with the universal type
classes. Under the hood they just proxy the calls to the `.chosen` object.

## Any

The `Any` class implements the ASN.1 Any type, which allows any data type. By
default objects of this class do not perform any parsing. However, the
`.parse()` instance method allows parsing the contents of the `Any` object,
either into a universal type, or to a specification pass in via the `spec`
parameter.

This type is not used as a top-level structure, but instead allows `Sequence`
and `Set` objects to accept varying contents, usually based on some sort of
`ObjectIdentifier`.

```python
from asn1crypto.core import Sequence, ObjectIdentifier, Any, Integer, OctetString

class MySequence(Sequence):
    _fields = [
        ('type', ObjectIdentifier),
        ('value', Any),
    ]
```

## Specification via OID

Throughout the usage of ASN.1 in cryptography, a pattern is present where an
`ObjectIdenfitier` is used to determine what specification should be used to
interpret another field in a `Sequence`. Usually the other field is an instance
of `Any`, however ocassionally it is an `OctetString`.

*asn1crypto* provides the `_oid_pair` and `_oid_specs` properties of the
`Sequence` class to allow handling these situations.

The `_oid_pair` is a tuple with two unicode string elements. The first is the
name of the field that is an `ObjectIdentifier` and the second if the name of
the field that has a variable specification based on the first field.

The `_oid_specs` property is a `dict` object with `ObjectIdentifier` values as
the keys (either dotted or mapped notation) and a type class as the value. When
the first field in `_oid_pair` has a value equal to one of the keys in
`_oid_specs`, then the corresponding type class will be used as the
specification for the second field of `_oid_pair`.

```python
from asn1crypto.core import Sequence, ObjectIdentifier, Any, OctetString, Integer

class MyId(ObjectIdentifier):
    _map = {
        '1.2.3.4': 'initialization_vector',
        '1.2.3.5': 'iterations',
    }

class MySequence(Sequence):
    _fields = [
        ('type', MyId),
        ('value', Any),
    ]

    _oid_pair = ('type', 'value')
    _oid_specs = {
        'initialization_vector': OctetString,
        'iterations': Integer,
    }
```

In some situations, the second field in `_oid_pair` is not an instance of `Any`,
but instead is an instance of `OctetString`. This is dictated by the ASN.1
specification of the data structures being worked with.

## Explicit and Implicit Tagging

When working with `Sequence`, `Set` and `Choice` it is often necessary to
disambiguate between fields because of a number of factors:

 - In `Sequence` the presence of an optional field must be determined by tag number
 - In `Set`, each field must have a different tag number since they can be in any order
 - In `Choice`, each alternative must have a different tag number to determine which is present

The universal types all have unique tag numbers. However, if a `Sequence`, `Set`
or `Choice` has more than one field with the same universal type, tagging allows
a way to keep the semantics of the original type, but with a different tag
number.

Implicit tagging simply changes the tag number of a type to a different value.
However, Explicit tagging wraps the existing type in another tag with the
specified tag number.

In general, most situations allow for implicit tagging, with the notable
exception than a field that is a `Choice` type must always be explicitly tagged.
Otherwise, using implicit tagging would modify the tag of the chosen
alternative, breaking the mechanism by which `Choice` works.

Here is an example of implicit and explicit tagging where explicit tagging on
the `Sequence` allows a `Choice` type field to be optional, and where implicit
tagging in the `Choice` structure allows disambiguating between two string of
the same type.

```python
from asn1crypto.core import Sequence, Choice, IA5String, UTCTime, ObjectIdentifier

class Person(Choice):
    _alternatives = [
        ('name', IA5String),
        ('email', IA5String, {'tag_type': 'implicit', 'tag': 0}),
    ]

class Record(Sequence):
    _fields = [
        ('id', ObjectIdentifier),
        ('created', UTCTime),
        ('creator', Person, {'tag_type': 'explicit', 'tag': 0, 'optional': True}),
    ]
```

As is shown above, the keys `tag_type` and `tag` are used for tagging, and are
passed to a type class constructor via the optional third element of a field
or alternative tuple. The `tag_type` may be the unicode strings `'implicit'` or
`'explicit'` and the `tag` may be any integer.
