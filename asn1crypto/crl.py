# coding: utf-8

"""
ASN.1 type classes for certificate revocation lists (CRL). Exports the
following items:

 - CertificateList()

Other type classes are defined that help compose the types listed above.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

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
    AuthorityInfoAccessSyntax,
    AuthorityKeyIdentifier,
    CRLDistributionPoints,
    DistributionPointName,
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

    @property
    def human_friendly(self):
        """
        :return:
            A unicode string with revocation description that is suitable to
            show to end-users. Starts with a lower case letter and phrased in
            such a way that it makes sense after the phrase "because of" or
            "due to".
        """

        return {
            'unspecified': 'an unspecified reason',
            'key_compromise': 'a compromised key',
            'ca_compromise': 'the CA being compromised',
            'affiliation_changed': 'an affiliation change',
            'superseded': 'certificate supersession',
            'cessation_of_operation': 'a cessation of operation',
            'certificate_hold': 'a certificate hold',
            'remove_from_crl': 'removal from the CRL',
            'privilege_withdrawn': 'privilege withdrawl',
            'aa_compromise': 'the AA being compromised',
        }[self.native]


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

    _processed_extensions = False
    _critical_extensions = None
    _crl_reason_value = None
    _invalidity_date_value = None
    _certificate_issuer_value = None

    def _set_extensions(self):
        """
        Sets common named extensions to private attributes and creates a list
        of critical extensions
        """

        self._critical_extensions = []

        for extension in self['crl_entry_extensions']:
            name = extension['extn_id'].native
            attribute_name = '_%s_value' % name
            if hasattr(self, attribute_name):
                setattr(self, attribute_name, extension['extn_value'].parsed)
            if extension['critical'].native:
                self._critical_extensions.append(name)

        self._processed_extensions = True

    @property
    def critical_extensions(self):
        """
        Returns a list of the names (or OID if not a known extension) of the
        extensions marked as critical

        :return:
            A list of unicode strings
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._critical_extensions

    @property
    def crl_reason_value(self):
        """
        This extension indicates the reason that a certificate was revoked.

        :return:
            None or a CRLReason object
        """

        if self._processed_extensions is False:
            self._processed_extensions()
        return self._crl_reason_value

    @property
    def invalidity_date_value(self):
        """
        This extension indicates the suspected date/time the private key was
        compromised or the certificate became invalid. This would usually be
        before the revocation date, which is when the CA processed the
        revocation.

        :return:
            None or a GeneralizedTime object
        """

        if self._processed_extensions is False:
            self._processed_extensions()
        return self._invalidity_date_value

    @property
    def certificate_issuer_value(self):
        """
        This extension indicates the issuer of the certificate in question,
        and is used in indirect CRLs. CRL entries without this extension are
        for certificates issued from the last seen issuer.

        :return:
            None or an x509.GeneralNames object
        """

        if self._processed_extensions is False:
            self._processed_extensions()
        return self._certificate_issuer_value


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

    _processed_extensions = False
    _critical_extensions = None
    _issuer_alt_name = None
    _crl_number = None
    _delta_crl_indicator = None
    _issuing_distribution_point = None
    _authority_key_identifier = None
    _freshest_crl = None
    _authority_information_access = None

    def _set_extensions(self):
        """
        Sets common named extensions to private attributes and creates a list
        of critical extensions
        """

        self._critical_extensions = []

        for extension in self['tbs_cert_list']['crl_extensions']:
            name = extension['extn_id'].native
            attribute_name = '_%s_value' % name
            if hasattr(self, attribute_name):
                setattr(self, attribute_name, extension['extn_value'].parsed)
            if extension['critical'].native:
                self._critical_extensions.append(name)

        self._processed_extensions = True

    @property
    def critical_extensions(self):
        """
        Returns a list of the names (or OID if not a known extension) of the
        extensions marked as critical

        :return:
            A list of unicode strings
        """

        if not self._processed_extensions:
            self._set_extensions()
        return self._critical_extensions

    @property
    def issuer_alt_name_value(self):
        """
        This extension allows associating one or more alternative names with
        the issuer of the CRL.

        :return:
            None or an x509.GeneralNames object
        """

        if self._processed_extensions is False:
            self._processed_extensions()
        return self._issuer_alt_name_value

    @property
    def crl_number_value(self):
        """
        This extension adds a monotonically increasing number to the CRL and is
        used to distinguish different versions of the CRL.

        :return:
            None or an Integer object
        """

        if self._processed_extensions is False:
            self._processed_extensions()
        return self._crl_number_value

    @property
    def delta_crl_indicator_value(self):
        """
        This extension indicates a CRL is a delta CRL, and contains the CRL
        number of the base CRL that it is a delta from.

        :return:
            None or an Integer object
        """

        if self._processed_extensions is False:
            self._processed_extensions()
        return self._delta_crl_indicator_value

    @property
    def issuing_distribution_point_value(self):
        """
        This extension includes information about what types of revocations
        and certificates are part of the CRL.

        :return:
            None or an IssuingDistributionPoint object
        """

        if self._processed_extensions is False:
            self._processed_extensions()
        return self._issuing_distribution_point_value

    @property
    def authority_key_identifier_value(self):
        """
        This extension helps in identifying the public key with which to
        validate the authenticity of the CRL.

        :return:
            None or an AuthorityKeyIdentifier object
        """

        if self._processed_extensions is False:
            self._processed_extensions()
        return self._authority_key_identifier_value

    @property
    def freshest_crl_value(self):
        """
        This extension is used in complete CRLs to indicate where a delta CRL
        may be located.

        :return:
            None or a CRLDistributionPoints object
        """

        if self._processed_extensions is False:
            self._processed_extensions()
        return self._freshest_crl_value

    @property
    def authority_information_access_value(self):
        """
        This extension is used to provide a URL with which to download the
        certificate used to sign this CRL.

        :return:
            None or an AuthorityInfoAccessSyntax object
        """

        if self._processed_extensions is False:
            self._processed_extensions()
        return self._authority_information_access_value
