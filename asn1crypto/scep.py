# coding: utf-8

"""
ASN.1 type classes for SCEP requests and responses. Adds extra oid mapping and
value parsing to asn1crypto.cms.CMSAttribute().
"""

from __future__ import unicode_literals, division, absolute_import, print_function
from .cms import CMSAttributeType, CMSAttribute, SetOfOctetString
from .core import PrintableString, SetOf


class SetOfPrintableString(SetOf):
    _child_spec = PrintableString


# https://tools.ietf.org/html/draft-gutmann-scep-06#section-3.2.1
CMSAttributeType._map['2.16.840.1.113733.1.9.2'] = 'scep_message_type'
CMSAttributeType._map['2.16.840.1.113733.1.9.3'] = 'scep_pki_status'
CMSAttributeType._map['2.16.840.1.113733.1.9.4'] = 'scep_fail_info'
CMSAttributeType._map['2.16.840.1.113733.1.9.5'] = 'scep_sender_nonce'
CMSAttributeType._map['2.16.840.1.113733.1.9.6'] = 'scep_recipient_nonce'
CMSAttributeType._map['2.16.840.1.113733.1.9.7'] = 'scep_transaction_id'

CMSAttribute._oid_specs['scep_message_type'] = SetOfPrintableString
CMSAttribute._oid_specs['scep_pki_status'] = SetOfPrintableString
CMSAttribute._oid_specs['scep_fail_info'] = SetOfPrintableString
CMSAttribute._oid_specs['scep_sender_nonce'] = SetOfOctetString
CMSAttribute._oid_specs['scep_recipient_nonce'] = SetOfOctetString
CMSAttribute._oid_specs['scep_transaction_id'] = SetOfPrintableString
