# coding: utf-8
from __future__ import unicode_literals

from .algos import SignedDigestAlgorithm
from .core import (
    Boolean,
    Enumerated,
    GeneralizedTime,
    Integer,
    ObjectIdentifier,
    OctetBitString,
    OctetString,
    Sequence,
    SequenceOf,
)
from .x509 import (
    AuthorityKeyIdentifier,
    CRLDistributionPoints,
    DistributionPointName,
    GeneralName,
    GeneralNames,
    Name,
    ReasonFlags,
    Time,
)



# The structures in this file are taken from https://tools.ietf.org/html/rfc5280


class Version(Integer):
    _map = {
        0: 'v1',
        1: 'v2',
        2: 'v3',
    }


class IssuingDistributionPoint(Sequence):
    _fields = [
        ('distribution_point', DistributionPointName, {'tag_type': 'explicit', 'tag': 0, 'optional': True}),
        ('only_contains_user_certs', Boolean, {'tag_type': 'implicit', 'tag': 1, 'default': False}),
        ('only_contains_ca_certs', Boolean, {'tag_type': 'implicit', 'tag': 2, 'default': False}),
        ('only_some_reasons', ReasonFlags, {'tag_type': 'implicit', 'tag': 3, 'optional': True}),
        ('indirect_crl', Boolean, {'tag_type': 'implicit', 'tag': 4, 'default': False}),
        ('only_contains_attribute_certs', Boolean, {'tag_type': 'implicit', 'tag': 5, 'default': False}),
    ]


class AccessMethod(ObjectIdentifier):
    _map = {
        '1.3.6.1.5.5.7.48.1': 'ocsp',
        '1.3.6.1.5.5.7.48.2': 'ca_issuers',
    }


class AccessDescription(Sequence):
    _fields = [
        ('access_method', AccessMethod),
        ('access_location', GeneralName),
    ]


class AuthorityInfoAccessSyntax(SequenceOf):
    _child_spec = AccessDescription


class TBSCertListExtensionId(ObjectIdentifier):
    _map = {
        '2.5.29.18': 'issuer_alt_name',
        '2.5.29.20': 'crl_number',
        '2.5.29.27': 'delta_crl_indicator',
        '2.5.29.28': 'issuing_distribution_point',
        '2.5.29.35': 'authority_key_identifier',
        '2.5.29.46': 'freshest_crl',
        '1.3.6.1.5.5.7.1.1': 'authority_information_access',
    }


class TBSCertListExtension(Sequence):
    _fields = [
        ('extn_id', TBSCertListExtensionId),
        ('critical', Boolean, {'default': False}),
        ('extn_value', OctetString),
    ]

    _oid_pair = ('extn_id', 'extn_value')
    _oid_specs = {
        'issuer_alt_name': GeneralNames,
        'crl_number': Integer,
        'delta_crl_indicator': Integer,
        'issuing_distribution_point': IssuingDistributionPoint,
        'authority_key_identifier': AuthorityKeyIdentifier,
        'freshest_crl': CRLDistributionPoints,
        'authority_information_access': AuthorityInfoAccessSyntax,
    }


class TBSCertListExtensions(SequenceOf):
    _child_spec = TBSCertListExtension


class CRLReason(Enumerated):
    _map = {
        0: 'unspecified',
        1: 'key_compromise',
        2: 'ca_compromise',
        3: 'affiliation_changed',
        4: 'superseded',
        5: 'cessation_of_operation',
        6: 'certificate_hold',
        8: 'remove_from_crl',
        9: 'privilege_withdrawn',
        10: 'aa_compromise',
    }


class CRLEntryExtensionId(ObjectIdentifier):
    _map = {
        '2.5.29.21': 'crl_reason',
        '2.5.29.24': 'invalidity_date',
        '2.5.29.29': 'certificate_issuer',
    }


class CRLEntryExtension(Sequence):
    _fields = [
        ('extn_id', CRLEntryExtensionId),
        ('critical', Boolean, {'default': False}),
        ('extn_value', OctetString),
    ]

    _oid_pair = ('extn_id', 'extn_value')
    _oid_specs = {
        'crl_reason': CRLReason,
        'invalidity_date': GeneralizedTime,
        'certificate_issuer': GeneralNames,
    }


class CRLEntryExtensions(SequenceOf):
    _child_spec = CRLEntryExtension


class RevokedCertificate(Sequence):
    _fields = [
        ('user_certificate', Integer),
        ('revocation_date', Time),
        ('crl_entry_extensions', CRLEntryExtensions, {'optional': True}),
    ]


class RevokedCertificates(SequenceOf):
    _child_spec = RevokedCertificate


class TbsCertList(Sequence):
    _fields = [
        ('version', Version, {'optional': True}),
        ('signature', SignedDigestAlgorithm),
        ('issuer', Name),
        ('this_update', Time),
        ('next_update', Time),
        ('revoked_certificates', RevokedCertificates, {'optional': True}),
        ('crl_extensions', TBSCertListExtensions, {'tag_type': 'explicit', 'tag': 0, 'optional': True}),
    ]


class CertificateList(Sequence):
    _fields = [
        ('tbs_cert_list', TbsCertList),
        ('signature_algorith', SignedDigestAlgorithm),
        ('signature', OctetBitString),
    ]
