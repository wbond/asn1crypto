# coding: utf-8

"""
ASN.1 type classes for the online certificate status protocol (OCSP). Exports
the following items:

 - OCSPRequest()
 - OCSPResponse()

Other type classes are defined that help compose the types listed above.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from .algos import DigestAlgorithm, SignedDigestAlgorithm
from .core import (
    Boolean,
    Choice,
    Enumerated,
    GeneralizedTime,
    IA5String,
    Integer,
    Null,
    ObjectIdentifier,
    OctetBitString,
    OctetString,
    Sequence,
    SequenceOf,
)
from .crl import AuthorityInfoAccessSyntax, CRLReason
from .keys import PublicKeyAlgorithm
from .x509 import Certificate, GeneralName, GeneralNames, Name



# The structures in this file are taken from https://tools.ietf.org/html/rfc6960


class Version(Integer):
    _map = {
        0: 'v1'
    }


class CertId(Sequence):
    _fields = [
        ('hash_algorithm', DigestAlgorithm),
        ('issuer_name_hash', OctetString),
        ('issuer_key_hash', OctetString),
        ('serial_number', Integer),
    ]


class ServiceLocator(Sequence):
    _fields = [
        ('issuer', Name),
        ('locator', AuthorityInfoAccessSyntax),
    ]


class RequestExtensionId(ObjectIdentifier):
    _map = {
        '1.3.6.1.5.5.7.48.1.7': 'service_locator',
    }


class RequestExtension(Sequence):
    _fields = [
        ('extn_id', RequestExtensionId),
        ('critical', Boolean, {'default': False}),
        ('extn_value', OctetString),
    ]

    _oid_pair = ('extn_id', 'extn_value')
    _oid_specs = {
        'service_locator': ServiceLocator,
    }


class RequestExtensions(SequenceOf):
    _child_spec = RequestExtension


class Request(Sequence):
    _fields = [
        ('req_cert', CertId),
        ('single_request_extensions', RequestExtensions, {'tag_type': 'explicit', 'tag': 0, 'optional': True}),
    ]


class Requests(SequenceOf):
    _child_spec = Request


class ResponseType(ObjectIdentifier):
    _map = {
        '1.3.6.1.5.5.7.48.1.1': 'basic_ocsp_response',
    }


class AcceptableResponses(SequenceOf):
    _child_spec = ResponseType


class PreferredSignatureAlgorithm(Sequence):
    _fields = [
        ('sig_identifier', SignedDigestAlgorithm),
        ('cert_identifier', PublicKeyAlgorithm, {'optional': True}),
    ]


class PreferredSignatureAlgorithms(SequenceOf):
    _child_spec = PreferredSignatureAlgorithm


class TBSRequestExtensionId(ObjectIdentifier):
    _map = {
        '1.3.6.1.5.5.7.48.1.2': 'nonce',
        '1.3.6.1.5.5.7.48.1.4': 'acceptable_responses',
        '1.3.6.1.5.5.7.48.1.8': 'preferred_signature_algorithms',
    }


class TBSRequestExtension(Sequence):
    _fields = [
        ('extn_id', TBSRequestExtensionId),
        ('critical', Boolean, {'default': False}),
        ('extn_value', OctetString),
    ]

    _oid_pair = ('extn_id', 'extn_value')
    _oid_specs = {
        'nonce': OctetString,
        'acceptable_responses': AcceptableResponses,
        'preferred_signature_algorithms': PreferredSignatureAlgorithms,
    }


class TBSRequestExtensions(SequenceOf):
    _child_spec = TBSRequestExtension


class TBSRequest(Sequence):
    _fields = [
        ('version', Version, {'tag_type': 'explicit', 'tag': 0, 'default': 'v1'}),
        ('requestor_name', GeneralName, {'tag_type': 'explicit', 'tag': 1, 'optional': True}),
        ('request_list', Requests),
        ('request_extensions', TBSRequestExtensions, {'tag_type': 'explicit', 'tag': 2, 'optional': True}),
    ]


class Certificates(SequenceOf):
    _child_spec = Certificate


class Signature(Sequence):
    _fields = [
        ('signature_algorithm', SignedDigestAlgorithm),
        ('signature', OctetBitString),
        ('certs', Certificates, {'tag_type': 'explicit', 'tag': 0, 'optional': True}),
    ]


class OCSPRequest(Sequence):
    _fields = [
        ('tbs_request', TBSRequest),
        ('optional_signature', Signature, {'tag_type': 'explicit', 'tag': 0, 'optional': True}),
    ]


class OCSPResponseStatus(Enumerated):
    _map = {
        0: 'successful',
        1: 'malformed_request',
        2: 'internal_error',
        3: 'try_later',
        5: 'sign_required',
        6: 'unauthorized',
    }


class ResponderId(Choice):
    _alternatives = [
        ('by_name', Name, {'tag_type': 'explicit', 'tag': 1}),
        ('by_key', OctetString, {'tag_type': 'explicit', 'tag': 2}),
    ]


class RevokedInfo(Sequence):
    _fields = [
        ('revocation_time', GeneralizedTime),
        ('revocation_reason', CRLReason, {'tag_type': 'explicit', 'tag': 0, 'optional': True}),
    ]


class CertStatus(Choice):
    _alternatives = [
        ('good', Null, {'tag_type': 'implicit', 'tag': 0}),
        ('revoked', RevokedInfo, {'tag_type': 'implicit', 'tag': 1}),
        ('unknown', Null, {'tag_type': 'implicit', 'tag': 2}),
    ]


class CrlId(Sequence):
    _fields = [
        ('crl_url', IA5String, {'tag_type': 'explicit', 'tag': 0, 'optional': True}),
        ('crl_num', Integer, {'tag_type': 'explicit', 'tag': 1, 'optional': True}),
        ('crl_time', GeneralizedTime, {'tag_type': 'explicit', 'tag': 2, 'optional': True}),
    ]


class SingleResponseExtensionId(ObjectIdentifier):
    _map = {
        '1.3.6.1.5.5.7.48.1.3': 'crl',
        '1.3.6.1.5.5.7.48.1.6': 'archive_cutoff',
        # These are CRLEntryExtension values from
        # https://tools.ietf.org/html/rfc5280
        '2.5.29.21': 'crl_reason',
        '2.5.29.24': 'invalidity_date',
        '2.5.29.29': 'certificate_issuer',
    }


class SingleResponseExtension(Sequence):
    _fields = [
        ('extn_id', SingleResponseExtensionId),
        ('critical', Boolean, {'default': False}),
        ('extn_value', OctetString),
    ]

    _oid_pair = ('extn_id', 'extn_value')
    _oid_specs = {
        'crl': CrlId,
        'archive_cutoff': GeneralizedTime,
        'crl_reason': CRLReason,
        'invalidity_date': GeneralizedTime,
        'certificate_issuer': GeneralNames,
    }


class SingleResponseExtensions(SequenceOf):
    _child_spec = SingleResponseExtension


class SingleResponse(Sequence):
    _fields = [
        ('cert_id', CertId),
        ('cert_status', CertStatus),
        ('this_update', GeneralizedTime),
        ('next_update', GeneralizedTime, {'tag_type': 'explicit', 'tag': 0, 'optional': True}),
        ('single_extensions', SingleResponseExtensions, {'tag_type': 'explicit', 'tag': 1, 'optional': True}),
    ]


class Responses(SequenceOf):
    _child_spec = SingleResponse


class ResponseDataExtensionId(ObjectIdentifier):
    _map = {
        '1.3.6.1.5.5.7.48.1.2': 'nonce',
        '1.3.6.1.5.5.7.48.1.9': 'extended_revoke',
    }


class ResponseDataExtension(Sequence):
    _fields = [
        ('extn_id', ResponseDataExtensionId),
        ('critical', Boolean, {'default': False}),
        ('extn_value', OctetString),
    ]

    _oid_pair = ('extn_id', 'extn_value')
    _oid_specs = {
        'nonce': OctetString,
        'extended_revoke': Null,
    }


class ResponseDataExtensions(SequenceOf):
    _child_spec = ResponseDataExtension


class ResponseData(Sequence):
    _fields = [
        ('version', Version, {'tag_type': 'explicit', 'tag': 0, 'default': 'v1'}),
        ('responder_id', ResponderId),
        ('produced_at', GeneralizedTime),
        ('responses', Responses),
        ('response_extensions', ResponseDataExtensions, {'tag_type': 'explicit', 'tag': 1, 'optional': True}),
    ]


class BasicOCSPResponse(Sequence):
    _fields = [
        ('tbs_response_data', ResponseData),
        ('signature_algorithm', SignedDigestAlgorithm),
        ('signature', OctetBitString),
        ('certs', Certificates, {'tag_type': 'explicit', 'tag': 0, 'optional': True}),
    ]


class ResponseBytes(Sequence):
    _fields = [
        ('response_type', ResponseType),
        ('response', OctetString),
    ]

    _oid_pair = ('response_type', 'response')
    _oid_specs = {
        'basic_ocsp_response': BasicOCSPResponse,
    }


class OCSPResponse(Sequence):
    _fields = [
        ('response_status', OCSPResponseStatus),
        ('response_bytes', ResponseBytes, {'tag_type': 'explicit', 'tag': 0, 'optional': True}),
    ]
