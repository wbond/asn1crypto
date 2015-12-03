# coding: utf-8

"""
ASN.1 type classes for cryptographic message syntax (CMS). Structures are also
compatible with PKCS#7. Exports the following items:

 - AuthenticatedData()
 - AuthEnvelopedData()
 - CompressedData()
 - ContentInfo()
 - EncryptedData()
 - EnvelopedData()
 - EnvelopedData()
 - SignedAndEnvelopedData()
 - SignedData()

Other type classes are defined that help compose the types listed above.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

try:
    import zlib
except (ImportError):
    zlib = None

from .algos import (
    DigestAlgorithm,
    EncryptionAlgorithm,
    HmacAlgorithm,
    KdfAlgorithm,
    SignedDigestAlgorithm,
)
from .core import (
    Any,
    Choice,
    Enumerated,
    GeneralizedTime,
    Integer,
    ObjectIdentifier,
    OctetBitString,
    OctetString,
    ParsableOctetString,
    Sequence,
    SequenceOf,
    SetOf,
    UTCTime,
)
from .crl import CertificateList
from .keys import PublicKeyInfo
from .ocsp import OCSPResponse
from .x509 import Attributes, Certificate, Extensions, GeneralNames, Name


# These structures are taken from
# ftp://ftp.rsasecurity.com/pub/pkcs/ascii/pkcs-6.asc

class ExtendedCertificateInfo(Sequence):
    _fields = [
        ('version', Integer),
        ('certificate', Certificate),
        ('attributes', Attributes),
    ]


class ExtendedCertificate(Sequence):
    _fields = [
        ('extended_certificate_info', ExtendedCertificateInfo),
        ('signature_algorithm', SignedDigestAlgorithm),
        ('signature', OctetBitString),
    ]


# These structures are taken from https://tools.ietf.org/html/rfc5652,
# https://tools.ietf.org/html/rfc5083, http://tools.ietf.org/html/rfc2315,
# https://tools.ietf.org/html/rfc5940, https://tools.ietf.org/html/rfc3274,
# https://tools.ietf.org/html/rfc3281


class CMSVersion(Integer):
    _map = {
        0: 'v0',
        1: 'v1',
        2: 'v2',
        3: 'v3',
        4: 'v4',
        5: 'v5',
    }


class CMSAttributeType(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.9.3': 'content_type',
        '1.2.840.113549.1.9.4': 'message_digest',
        '1.2.840.113549.1.9.5': 'signing_time',
        '1.2.840.113549.1.9.6': 'counter_signature',
    }


class Time(Choice):
    _alternatives = [
        ('utc_time', UTCTime),
        ('generalized_time', GeneralizedTime),
    ]


class ContentType(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.7.1': 'data',
        '1.2.840.113549.1.7.2': 'signed_data',
        '1.2.840.113549.1.7.3': 'enveloped_data',
        '1.2.840.113549.1.7.4': 'signed_and_enveloped_data',
        '1.2.840.113549.1.7.5': 'digested_data',
        '1.2.840.113549.1.7.6': 'encrypted_data',
        '1.2.840.113549.1.9.16.1.2': 'authenticated_data',
        '1.2.840.113549.1.9.16.1.9': 'compressed_data',
        '1.2.840.113549.1.9.16.1.23': 'authenticated_enveloped_data',
    }


class SetOfContentType(SetOf):
    _child_spec = ContentType


class SetOfOctetString(SetOf):
    _child_spec = OctetString


class SetOfTime(SetOf):
    _child_spec = Time


class SetOfAny(SetOf):
    _child_spec = Any


class CMSAttribute(Sequence):
    _fields = [
        ('type', CMSAttributeType),
        ('values', None),
    ]

    _oid_specs = {}

    def _values_spec(self):
        return self._oid_specs.get(self['type'].native, SetOfAny)

    _spec_callbacks = {
        'values': _values_spec
    }


class CMSAttributes(SetOf):
    _child_spec = CMSAttribute


class IssuerSerial(Sequence):
    _fields = [
        ('issuer', GeneralNames),
        ('serial', Integer),
        ('issuer_uid', OctetBitString, {'optional': True}),
    ]


class AttCertVersion(Integer):
    _map = {
        0: 'v1',
        1: 'v2',
    }


class AttCertSubject(Choice):
    _alternatives = [
        ('base_certificate_id', IssuerSerial, {'tag_type': 'explicit', 'tag': 0}),
        ('subject_name', GeneralNames, {'tag_type': 'explicit', 'tag': 1}),
    ]


class AttCertValidityPeriod(Sequence):
    _fields = [
        ('not_before_time', GeneralizedTime),
        ('not_after_time', GeneralizedTime),
    ]


class AttributeCertificateInfoV1(Sequence):
    _fields = [
        ('version', AttCertVersion, {'default': 'v1'}),
        ('subject', AttCertSubject),
        ('issuer', GeneralNames),
        ('signature', SignedDigestAlgorithm),
        ('serial_number', Integer),
        ('att_cert_validity_period', AttCertValidityPeriod),
        ('attributes', Attributes),
        ('issuer_unique_id', OctetBitString, {'optional': True}),
        ('extensions', Extensions, {'optional': True}),
    ]


class AttributeCertificateV1(Sequence):
    _fields = [
        ('ac_info', AttributeCertificateInfoV1),
        ('signature_algorithm', SignedDigestAlgorithm),
        ('signature', OctetBitString),
    ]


class DigestedObjectType(Enumerated):
    _map = {
        0: 'public_key',
        1: 'public_key_cert',
        2: 'other_objy_types',
    }


class ObjectDigestInfo(Sequence):
    _fields = [
        ('digested_object_type', DigestedObjectType),
        ('other_object_type_id', ObjectIdentifier, {'optional': True}),
        ('digest_algorithm', DigestAlgorithm),
        ('object_digest', OctetBitString),
    ]


class Holder(Sequence):
    _fields = [
        ('base_certificate_id', IssuerSerial, {'tag_type': 'implicit', 'tag': 0, 'optional': True}),
        ('entity_name', GeneralNames, {'tag_type': 'implicit', 'tag': 1, 'optional': True}),
        ('object_digest_info', ObjectDigestInfo, {'tag_type': 'implicit', 'tag': 2, 'optional': True}),
    ]


class V2Form(Sequence):
    _fields = [
        ('issuer_name', GeneralNames, {'optional': True}),
        ('base_certificate_id', IssuerSerial, {'tag_type': 'explicit', 'tag': 0, 'optional': True}),
        ('object_digest_info', ObjectDigestInfo, {'tag_type': 'explicit', 'tag': 1, 'optional': True}),
    ]


class AttCertIssuer(Choice):
    _alternatives = [
        ('v1_form', GeneralNames),
        ('v2_form', V2Form, {'tag_type': 'explicit', 'tag': 0}),
    ]


class AttributeCertificateInfoV2(Sequence):
    _fields = [
        ('version', AttCertVersion),
        ('holder', Holder),
        ('issuer', AttCertIssuer),
        ('signature', SignedDigestAlgorithm),
        ('serial_number', Integer),
        ('att_cert_validity_period', AttCertValidityPeriod),
        ('attributes', Attributes),
        ('issuer_unique_id', OctetBitString, {'optional': True}),
        ('extensions', Extensions, {'optional': True}),
    ]


class AttributeCertificateV2(Sequence):
    _fields = [
        ('ac_info', AttributeCertificateInfoV2),
        ('signature_algorithm', SignedDigestAlgorithm),
        ('signature', OctetBitString),
    ]


class OtherCertificateFormat(Sequence):
    _fields = [
        ('other_cert_format', ObjectIdentifier),
        ('other_cert', Any),
    ]


class CertificateChoices(Choice):
    _alternatives = [
        ('certificate', Certificate),
        ('extended_certificate', ExtendedCertificate, {'tag_type': 'implicit', 'tag': 0}),
        ('v1_attr_cert', AttributeCertificateV1, {'tag_type': 'implicit', 'tag': 1}),
        ('v2_attr_cert', AttributeCertificateV2, {'tag_type': 'implicit', 'tag': 2}),
        ('other', OtherCertificateFormat, {'tag_type': 'implicit', 'tag': 3}),
    ]


class CertificateSet(SetOf):
    _child_spec = CertificateChoices


class ContentInfo(Sequence):
    _fields = [
        ('content_type', ContentType),
        ('content', Any, {'tag_type': 'explicit', 'tag': 0, 'optional': True}),
    ]

    _oid_pair = ('content_type', 'content')
    _oid_specs = {}


class EncapsulatedContentInfo(Sequence):
    _fields = [
        ('content_type', ContentType),
        ('content', ParsableOctetString, {'tag_type': 'explicit', 'tag': 0, 'optional': True}),
    ]

    _oid_pair = ('content_type', 'content')
    _oid_specs = {}


class IssuerAndSerialNumber(Sequence):
    _fields = [
        ('issuer', Name),
        ('serial_number', Integer),
    ]


class SignerIdentifier(Choice):
    _alternatives = [
        ('issuer_and_serial_number', IssuerAndSerialNumber),
        ('subject_key_identifier', OctetString, {'tag_type': 'implicit', 'tag': 0}),
    ]


class DigestAlgorithms(SetOf):
    _child_spec = DigestAlgorithm


class CertificateRevocationLists(SetOf):
    _child_spec = CertificateList


class SCVPReqRes(Sequence):
    _fields = [
        ('request', ContentInfo, {'tag_type': 'explicit', 'tag': 0, 'optional': True}),
        ('response', ContentInfo),
    ]


class OtherRevInfoFormatId(ObjectIdentifier):
    _map = {
        '1.3.6.1.5.5.7.16.2': 'ocsp_response',
        '1.3.6.1.5.5.7.16.4': 'scvp',
    }


class OtherRevocationInfoFormat(Sequence):
    _fields = [
        ('other_rev_info_format', OtherRevInfoFormatId),
        ('other_rev_info', Any),
    ]

    _oid_pair = ('other_rev_info_format', 'other_rev_info')
    _oid_specs = {
        'ocsp_response': OCSPResponse,
        'scvp': SCVPReqRes,
    }


class RevocationInfoChoice(Choice):
    _alternatives = [
        ('crl', CertificateList),
        ('other', OtherRevocationInfoFormat, {'tag_type': 'implciit', 'tag': 1}),
    ]


class RevocationInfoChoices(SetOf):
    _child_spec = RevocationInfoChoice


class SignerInfo(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('sid', SignerIdentifier),
        ('digest_algorithm', DigestAlgorithm),
        ('signed_attrs', CMSAttributes, {'tag_type': 'implicit', 'tag': 0, 'optional': True}),
        ('signature_algorithm', SignedDigestAlgorithm),
        ('signature', OctetString),
        ('unsigned_attrs', CMSAttributes, {'tag_type': 'implicit', 'tag': 1, 'optional': True}),
    ]


class SignerInfos(SetOf):
    _child_spec = SignerInfo


class SignedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('digest_algorithms', DigestAlgorithms),
        ('encap_content_info', None),
        ('certificates', CertificateSet, {'tag_type': 'implicit', 'tag': 0, 'optional': True}),
        ('crls', RevocationInfoChoices, {'tag_type': 'implicit', 'tag': 1, 'optional': True}),
        ('signer_infos', SignerInfos),
    ]

    def _encap_content_info_spec(self):
        # If the encap_content_info is version v1, then this could be a PKCS#7
        # structure, or a CMS structure. CMS wraps the encoded value in an
        # Octet String tag.

        # If the version is greater than 1, it is definite CMS
        if self['version'].native != 'v1':
            return EncapsulatedContentInfo

        # Otherwise, the ContentInfo spec from PKCS#7 will be compatible with
        # CMS v1 (which only allows Data, an Octet String) and PKCS#7, which
        # allows Any
        return ContentInfo

    _spec_callbacks = {
        'encap_content_info': _encap_content_info_spec
    }


class OriginatorInfo(Sequence):
    _fields = [
        ('certs', CertificateSet, {'tag_type': 'implicit', 'tag': 0, 'optional': True}),
        ('crls', RevocationInfoChoices, {'tag_type': 'implicit', 'tag': 1, 'optional': True}),
    ]


class RecipientIdentifier(Choice):
    _alternatives = [
        ('issuer_and_serial_number', IssuerAndSerialNumber),
        ('subject_key_identifier', OctetString, {'tag_type': 'implicit', 'tag': 0}),
    ]


class KeyEncryptionAlgorithmId(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.1.1': 'rsa',
        '2.16.840.1.101.3.4.1.5': 'aes128_wrap',
        '2.16.840.1.101.3.4.1.8': 'aes128_wrap_pad',
        '2.16.840.1.101.3.4.1.25': 'aes192_wrap',
        '2.16.840.1.101.3.4.1.28': 'aes192_wrap_pad',
        '2.16.840.1.101.3.4.1.45': 'aes256_wrap',
        '2.16.840.1.101.3.4.1.48': 'aes256_wrap_pad',
    }


class KeyEncryptionAlgorithm(Sequence):
    _fields = [
        ('algorithm', KeyEncryptionAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]


class KeyTransRecipientInfo(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('rid', RecipientIdentifier),
        ('key_encryption_algorithm', KeyEncryptionAlgorithm),
        ('encrypted_key', OctetString),
    ]


class OriginatorIdentifierOrKey(Choice):
    _alternatives = [
        ('issuer_and_serial_number', IssuerAndSerialNumber),
        ('subject_key_identifier', OctetString, {'tag_type': 'implicit', 'tag': 0}),
        ('originator_key', PublicKeyInfo, {'tag_type': 'implicit', 'tag': 1}),
    ]


class OtherKeyAttribute(Sequence):
    _fields = [
        ('key_attr_id', ObjectIdentifier),
        ('key_attr', Any),
    ]


class RecipientKeyIdentifier(Sequence):
    _fields = [
        ('subject_key_identifier', OctetString),
        ('date', GeneralizedTime, {'optional': True}),
        ('other', OtherKeyAttribute, {'optional': True}),
    ]


class KeyAgreementRecipientIdentifier(Choice):
    _alternatives = [
        ('issuer_and_serial_number', IssuerAndSerialNumber),
        ('r_key_id', RecipientKeyIdentifier, {'tag_type': 'implicit', 'tag': 0}),
    ]


class RecipientEncryptedKey(Sequence):
    _fields = [
        ('rid', KeyAgreementRecipientIdentifier),
        ('encrypted_key', OctetString),
    ]


class RecipientEncryptedKeys(SequenceOf):
    _child_spec = RecipientEncryptedKey


class KeyAgreeRecipientInfo(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('originator', OriginatorIdentifierOrKey, {'tag_type': 'explicit', 'tag': 0}),
        ('ukm', OctetString, {'tag_type': 'explicit', 'tag': 1, 'optional': True}),
        ('key_encryption_algorithm', KeyEncryptionAlgorithm),
        ('recipient_encrypted_keys', RecipientEncryptedKeys),
    ]


class KEKIdentifier(Sequence):
    _fields = [
        ('key_identifier', OctetString),
        ('date', GeneralizedTime, {'optional': True}),
        ('other', OtherKeyAttribute, {'optional': True}),
    ]


class KEKRecipientInfo(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('kekid', KEKIdentifier),
        ('key_encryption_algorithm', KeyEncryptionAlgorithm),
        ('encrypted_key', OctetString),
    ]


class PasswordRecipientInfo(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('key_derivation_algorithm', KdfAlgorithm, {'tag_type': 'implicit', 'tag': 0, 'optional': True}),
        ('key_encryption_algorithm', KeyEncryptionAlgorithm),
        ('encrypted_key', OctetString),
    ]


class OtherRecipientInfo(Sequence):
    _fields = [
        ('ori_type', ObjectIdentifier),
        ('ori_value', Any),
    ]


class RecipientInfo(Choice):
    _alternatives = [
        ('ktri', KeyTransRecipientInfo),
        ('kari', KeyAgreeRecipientInfo, {'tag_type': 'implicit', 'tag': 1}),
        ('kekri', KEKRecipientInfo, {'tag_type': 'implicit', 'tag': 2}),
        ('pwri', PasswordRecipientInfo, {'tag_type': 'implicit', 'tag': 3}),
        ('ori', OtherRecipientInfo, {'tag_type': 'implicit', 'tag': 4}),
    ]


class RecipientInfos(SetOf):
    _child_spec = RecipientInfo


class EncryptedContentInfo(Sequence):
    _fields = [
        ('content_type', ContentType),
        ('content_encryption_algorithm', EncryptionAlgorithm),
        ('encrypted_content', OctetString, {'tag_type': 'implicit', 'tag': 0, 'optional': True}),
    ]


class EnvelopedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('originator_info', OriginatorInfo, {'tag_type': 'implicit', 'tag': 0, 'optional': True}),
        ('recipient_infos', RecipientInfos),
        ('encrypted_content_info', EncryptedContentInfo),
        ('unprotected_attrs', CMSAttributes, {'tag_type': 'implicit', 'tag': 1, 'optional': True}),
    ]


class SignedAndEnvelopedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('recipient_infos', RecipientInfos),
        ('digest_algorithms', DigestAlgorithms),
        ('encrypted_content_info', EncryptedContentInfo),
        ('certificates', CertificateSet, {'tag_type': 'implicit', 'tag': 0, 'optional': True}),
        ('crls', CertificateRevocationLists, {'tag_type': 'implicit', 'tag': 1, 'optional': True}),
        ('signer_infos', SignerInfos),
    ]


class DigestedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('digest_algorithm', DigestAlgorithm),
        ('encap_content_info', None),
        ('digest', OctetString),
    ]

    def _encap_content_info_spec(self):
        # If the encap_content_info is version v1, then this could be a PKCS#7
        # structure, or a CMS structure. CMS wraps the encoded value in an
        # Octet String tag.

        # If the version is greater than 1, it is definite CMS
        if self['version'].native != 'v1':
            return EncapsulatedContentInfo

        # Otherwise, the ContentInfo spec from PKCS#7 will be compatible with
        # CMS v1 (which only allows Data, an Octet String) and PKCS#7, which
        # allows Any
        return ContentInfo

    _spec_callbacks = {
        'encap_content_info': _encap_content_info_spec
    }


class EncryptedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('encrypted_content_info', EncryptedContentInfo),
        ('unprotected_attrs', CMSAttributes, {'tag_type': 'implicit', 'tag': 1, 'optional': True}),
    ]


class AuthenticatedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('originator_info', OriginatorInfo, {'tag_type': 'implicit', 'tag': 0, 'optional': True}),
        ('recipient_infos', RecipientInfos),
        ('mac_algorithm', HmacAlgorithm),
        ('digest_algorithm', DigestAlgorithm, {'tag_type': 'implicit', 'tag': 1, 'optional': True}),
        # This does not require the _spec_callbacks approach of SignedData and
        # DigestedData since AuthenticatedData was not part of PKCS#7
        ('encap_content_info', EncapsulatedContentInfo),
        ('auth_attrs', CMSAttributes, {'tag_type': 'implicit', 'tag': 2, 'optional': True}),
        ('mac', OctetString),
        ('unauth_attrs', CMSAttributes, {'tag_type': 'implicit', 'tag': 3, 'optional': True}),
    ]


class AuthEnvelopedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('originator_info', OriginatorInfo, {'tag_type': 'implicit', 'tag': 0, 'optional': True}),
        ('recipient_infos', RecipientInfos),
        ('auth_encrypted_content_info', EncryptedContentInfo),
        ('auth_attrs', CMSAttributes, {'tag_type': 'implicit', 'tag': 1, 'optional': True}),
        ('mac', OctetString),
        ('unauth_attrs', CMSAttributes, {'tag_type': 'implicit', 'tag': 2, 'optional': True}),
    ]


class CompressionAlgorithmId(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.9.16.3.8': 'zlib',
    }


class CompressionAlgorithm(Sequence):
    _fields = [
        ('algorithm', CompressionAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]


class CompressedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('compression_algorithm', CompressionAlgorithm),
        ('encap_content_info', EncapsulatedContentInfo),
    ]

    _decompressed = None

    @property
    def decompressed(self):
        if self._decompressed is None:
            if zlib is None:
                raise SystemError('The zlib module is not available')
            self._decompressed = zlib.decompress(self['encap_content_info']['content'].native)
        return self._decompressed


ContentInfo._oid_specs = {
    'data': OctetString,
    'signed_data': SignedData,
    'enveloped_data': EnvelopedData,
    'signed_and_enveloped_data': SignedAndEnvelopedData,
    'digested_data': DigestedData,
    'encrypted_data': EncryptedData,
    'authenticated_data': AuthenticatedData,
    'compressed_data': CompressedData,
    'authenticated_enveloped_data': AuthEnvelopedData,
}


EncapsulatedContentInfo._oid_specs = {
    'signed_data': SignedData,
    'enveloped_data': EnvelopedData,
    'signed_and_enveloped_data': SignedAndEnvelopedData,
    'digested_data': DigestedData,
    'encrypted_data': EncryptedData,
    'authenticated_data': AuthenticatedData,
    'compressed_data': CompressedData,
    'authenticated_enveloped_data': AuthEnvelopedData,
}


CMSAttribute._oid_specs = {
    'content_type': SetOfContentType,
    'message_digest': SetOfOctetString,
    'signing_time': SetOfTime,
    'counter_signature': SignerInfos,
}
