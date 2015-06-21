# coding: utf-8

"""
ASN.1 type classes for PDF signature structures. Adds extra oid mapping and
value parsing to asn1crypto.x509.Extension() and asn1crypto.xms.CMSAttribute().
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from .cms import CMSAttributeType, CMSAttribute
from .core import (
    Boolean,
    Integer,
    Null,
    ObjectIdentifier,
    OctetString,
    Sequence,
    SetOf,
)
from .crl import CertificateList
from .ocsp import OCSPResponse
from .x509 import ExtensionId, Extension, GeneralName, KeyPurposeId



class AdobeArchiveRevInfo(Sequence):
    _fields = [
        ('version', Integer)
    ]


class AdobeTimestamp(Sequence):
    _fields = [
        ('version', Integer),
        ('location', GeneralName),
        ('requires_auth', Boolean),
    ]


class OtherRevInfo(Sequence):
    _fields = [
        ('type', ObjectIdentifier),
        ('value', OctetString),
    ]


class RevocationInfoArchival(Sequence):
    _fields = [
        ('crl', CertificateList, {'tag_type': 'explicit', 'tag': 0, 'optional': True}),
        ('ocsp', OCSPResponse, {'tag_type': 'explicit', 'tag': 1, 'optional': True}),
        ('other_rev_info', OtherRevInfo, {'tag_type': 'explicit', 'tag': 2, 'optional': True}),
    ]


class SetOfRevocationInfoArchival(SetOf):
    _child_spec = RevocationInfoArchival


ExtensionId._map['1.2.840.113583.1.1.9.2'] = 'adobe_archive_rev_info'  #pylint: disable=W0212
ExtensionId._map['1.2.840.113583.1.1.9.1'] = 'adobe_timestamp'  #pylint: disable=W0212
ExtensionId._map['1.2.840.113583.1.1.10'] = 'adobe_ppklite_credential'  #pylint: disable=W0212
Extension._oid_specs['adobe_archive_rev_info'] = AdobeArchiveRevInfo  #pylint: disable=W0212
Extension._oid_specs['adobe_timestamp'] = AdobeTimestamp  #pylint: disable=W0212
Extension._oid_specs['adobe_ppklite_credential'] = Null  #pylint: disable=W0212
KeyPurposeId._map['1.2.840.113583.1.1.5'] = 'pdf_signing'  #pylint: disable=W0212
CMSAttributeType._map['1.2.840.113583.1.1.8'] = 'adobe_revocation_info_archival'  #pylint: disable=W0212
CMSAttribute._oid_specs['adobe_revocation_info_archival'] = SetOfRevocationInfoArchival  #pylint: disable=W0212
