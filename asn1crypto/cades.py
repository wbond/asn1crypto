# coding: utf-8

"""
ASN.1 type classes for cryptographic message syntax (CADES, RFC 5126 and RFC 3126). Structures are also
compatible with PKCS#7. Exports the following items:

 - AuthenticatedData()
 - AuthEnvelopedData()
 - CompressedData()
 - ContentInfo()
 - DigestedData()
 - EncryptedData()
 - EnvelopedData()
 - SignedAndEnvelopedData()
 - SignedData()

Other type classes are defined that help compose the types listed above.

ContentInfo is the main structure

-----------------
ASN.1 Definitions
-----------------

ETS-ElectronicSignatureFormats-ExplicitSyntax88 { iso(1) member-body(2)
us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-mod(0)
eSignature-explicit88(28)}

DEFINITIONS EXPLICIT TAGS ::=

BEGIN

-- EXPORTS All

IMPORTS

-- Cryptographic Message Syntax (CMS): RFC 3852

   ContentInfo, ContentType, id-data, id-signedData, SignedData,
   EncapsulatedContentInfo, SignerInfo, id-contentType,
   id-messageDigest, MessageDigest, id-signingTime, SigningTime,
   id-countersignature, Countersignature
      FROM CryptographicMessageSyntax2004
      { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
      smime(16) modules(0) cms-2004(24) }

-- ESS Defined attributes: ESS Update
-- RFC 5035 (Adding CertID Algorithm Agility)

   id-aa-signingCertificate, SigningCertificate, IssuerSerial,
   id-aa-contentReference, ContentReference, id-aa-contentIdentifier,
   ContentIdentifier, id-aa-signingCertificateV2
      FROM ExtendedSecurityServices-2006
        { iso(1) member-body(2) us(840) rsadsi(113549)
          pkcs(1) pkcs-9(9) smime(16) modules(0) id-mod-ess-2006(30) }

-- Internet X.509 Public Key Infrastructure - Certificate and CRL
-- Profile: RFC 3280

   Certificate, AlgorithmIdentifier, CertificateList, Name,
   DirectoryString, Attribute, BMPString, UTF8String
      FROM PKIX1Explicit88
      {iso(1) identified-organization(3) dod(6) internet(1)
      security(5) mechanisms(5) pkix(7) id-mod(0) id-pkix1-explicit(18)}

   GeneralNames, GeneralName, PolicyInformation
      FROM PKIX1Implicit88
      {iso(1) identified-organization(3) dod(6) internet(1) security(5)
       mechanisms(5) pkix(7) id-mod(0) id-pkix1-implicit (19)}

-- Internet Attribute Certificate Profile for Authorization - RFC 3281

   AttributeCertificate
      FROM PKIXAttributeCertificate {iso(1) identified-organization(3)
                dod(6) internet(1) security(5) mechanisms(5) pkix(7)
                id-mod(0) id-mod-attribute-cert(12)}

-- OCSP - RFC 2560

   BasicOCSPResponse, ResponderID
      FROM OCSP {iso(1) identified-organization(3) dod(6) internet(1)
      security(5) mechanisms(5) pkix(7) id-mod(0) id-mod-ocsp(14)}

-- Time Stamp Protocol RFC 3161

   TimeStampToken
      FROM PKIXTSP
      {iso(1) identified-organization(3) dod(6) internet(1) security(5)
      mechanisms(5) pkix(7) id-mod(0) id-mod-tsp(13)}

;


-- Definitions of Object Identifier arcs used in the present document
-- ==================================================================

-- OID used referencing electronic signature mechanisms based on
-- the present document for use with the Independent Data Unit
-- Protection (IDUP) API (see Annex D)

   id-etsi-es-IDUP-Mechanism-v1 OBJECT IDENTIFIER ::=
   { itu-t(0) identified-organization(4) etsi(0)
     electronic-signature-standard (1733) part1 (1) idupMechanism (4)
     etsiESv1(1) }


-- Basic ES CMS Attributes Defined in the present document
-- =======================================================

-- OtherSigningCertificate - deprecated

    id-aa-ets-otherSigCert OBJECT IDENTIFIER ::=
    { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
    smime(16) id-aa(2) 19 }

   OtherSigningCertificate ::=  SEQUENCE {
      certs        SEQUENCE OF OtherCertID,
      policies     SEQUENCE OF PolicyInformation OPTIONAL
                   -- NOT USED IN THE PRESENT DOCUMENT
   }

   OtherCertID ::= SEQUENCE {
      otherCertHash            OtherHash,
      issuerSerial             IssuerSerial OPTIONAL
   }

   OtherHash ::= CHOICE {
       sha1Hash     OtherHashValue,
       -- This contains a SHA-1 hash
       otherHash    OtherHashAlgAndValue
   }

   OtherHashValue ::= OCTET STRING

   OtherHashAlgAndValue ::= SEQUENCE {
       hashAlgorithm     AlgorithmIdentifier,
       hashValue         OtherHashValue
   }

-- Policy ES Attributes Defined in the present document
-- ====================================================

-- Mandatory Basic Electronic Signature Attributes as above,
-- plus in addition.

-- Signature-policy-identifier attribute

   id-aa-ets-sigPolicyId OBJECT IDENTIFIER ::=
   { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
   smime(16) id-aa(2) 15 }

   SignaturePolicy ::= CHOICE {
      signaturePolicyId          SignaturePolicyId,
      signaturePolicyImplied     SignaturePolicyImplied
                                 --  not used in this version
   }

   SignaturePolicyId ::= SEQUENCE {
      sigPolicyId        SigPolicyId,
      sigPolicyHash      SigPolicyHash,
      sigPolicyQualifiers   SEQUENCE SIZE (1..MAX) OF
                                   SigPolicyQualifierInfo OPTIONAL
   }

   SignaturePolicyImplied ::= NULL

   SigPolicyId ::= OBJECT IDENTIFIER

   SigPolicyHash ::= OtherHashAlgAndValue

   OtherHashAlgAndValue ::= SEQUENCE {
      hashAlgorithm   AlgorithmIdentifier,
      hashValue       OtherHashValue }

   OtherHashValue ::= OCTET STRING

   SigPolicyQualifierInfo ::= SEQUENCE {
      sigPolicyQualifierId  SigPolicyQualifierId,
      sigQualifier          ANY DEFINED BY sigPolicyQualifierId }

   SigPolicyQualifierId ::=   OBJECT IDENTIFIER

   id-spq-ets-uri OBJECT IDENTIFIER ::=
   { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
   smime(16) id-spq(5) 1 }

   SPuri ::= IA5String

   id-spq-ets-unotice OBJECT IDENTIFIER ::=
   { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
   smime(16) id-spq(5) 2 }

   SPUserNotice ::= SEQUENCE {
       noticeRef        NoticeReference OPTIONAL,
       explicitText     DisplayText OPTIONAL}

   NoticeReference ::= SEQUENCE {
      organization     DisplayText,
      noticeNumbers    SEQUENCE OF INTEGER }

   DisplayText ::= CHOICE {
      visibleString    VisibleString  (SIZE (1..200)),
      bmpString        BMPString      (SIZE (1..200)),

      utf8String       UTF8String     (SIZE (1..200)) }

-- Optional Electronic Signature Attributes

-- Commitment-type attribute

id-aa-ets-commitmentType OBJECT IDENTIFIER ::= { iso(1) member-body(2)
us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 16}

   CommitmentTypeIndication ::= SEQUENCE {
     commitmentTypeId CommitmentTypeIdentifier,
     commitmentTypeQualifier SEQUENCE SIZE (1..MAX) OF
            CommitmentTypeQualifier OPTIONAL}

   CommitmentTypeIdentifier ::= OBJECT IDENTIFIER

   CommitmentTypeQualifier ::= SEQUENCE {
      commitmentTypeIdentifier CommitmentTypeIdentifier,
      qualifier   ANY DEFINED BY commitmentTypeIdentifier }

id-cti-ets-proofOfOrigin OBJECT IDENTIFIER ::= { iso(1) member-body(2)
us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) cti(6) 1}

id-cti-ets-proofOfReceipt OBJECT IDENTIFIER ::= { iso(1) member-body(2)
us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) cti(6) 2}

id-cti-ets-proofOfDelivery OBJECT IDENTIFIER ::=
{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
smime(16) cti(6) 3}

id-cti-ets-proofOfSender OBJECT IDENTIFIER ::= { iso(1) member-body(2)
us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) cti(6) 4}

id-cti-ets-proofOfApproval OBJECT IDENTIFIER ::=
{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
smime(16) cti(6) 5}

id-cti-ets-proofOfCreation OBJECT IDENTIFIER ::=
{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
smime(16) cti(6) 6}

-- Signer-location attribute

id-aa-ets-signerLocation OBJECT IDENTIFIER ::= { iso(1) member-body(2)
us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 17}

   SignerLocation ::= SEQUENCE {
       -- at least one of the following shall be present
       countryName    [0]   DirectoryString OPTIONAL,
          -- As used to name a Country in X.500
       localityName   [1]   DirectoryString OPTIONAL,
           -- As used to name a locality in X.500
       postalAdddress [2]   PostalAddress OPTIONAL }

   PostalAddress ::= SEQUENCE SIZE(1..6) OF DirectoryString

-- Signer-attributes attribute

id-aa-ets-signerAttr OBJECT IDENTIFIER ::= { iso(1) member-body(2)
us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 18}

   SignerAttribute ::= SEQUENCE OF CHOICE {
      claimedAttributes   [0] ClaimedAttributes,
      certifiedAttributes [1] CertifiedAttributes }

   ClaimedAttributes ::= SEQUENCE OF Attribute

   CertifiedAttributes ::= AttributeCertificate
   -- as defined in RFC 3281: see Section 4.1

-- Content-time-stamp attribute

id-aa-ets-contentTimestamp OBJECT IDENTIFIER ::=
{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
smime(16) id-aa(2) 20}

   ContentTimestamp ::= TimeStampToken

-- Signature-time-stamp attribute

id-aa-signatureTimeStampToken OBJECT IDENTIFIER ::=
{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
smime(16) id-aa(2) 14}

SignatureTimeStampToken ::= TimeStampToken

-- Complete-certificate-references attribute

id-aa-ets-certificateRefs OBJECT IDENTIFIER ::= { iso(1) member-body(2)
us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 21}

CompleteCertificateRefs ::=  SEQUENCE OF OtherCertID

-- Complete-revocation-references attribute

id-aa-ets-revocationRefs OBJECT IDENTIFIER ::= { iso(1) member-body(2)
us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 22}

   CompleteRevocationRefs ::=  SEQUENCE OF CrlOcspRef

   CrlOcspRef ::= SEQUENCE {
      crlids          [0] CRLListID   OPTIONAL,
      ocspids         [1] OcspListID  OPTIONAL,
      otherRev        [2] OtherRevRefs OPTIONAL
   }

   CRLListID ::=  SEQUENCE {
      crls        SEQUENCE OF CrlValidatedID}

   CrlValidatedID ::=  SEQUENCE {
      crlHash                   OtherHash,
      crlIdentifier             CrlIdentifier OPTIONAL}

   CrlIdentifier ::= SEQUENCE {
      crlissuer                 Name,
      crlIssuedTime             UTCTime,
      crlNumber                 INTEGER OPTIONAL }

   OcspListID ::=  SEQUENCE {
       ocspResponses        SEQUENCE OF OcspResponsesID}

   OcspResponsesID ::=  SEQUENCE {
       ocspIdentifier              OcspIdentifier,
       ocspRepHash                 OtherHash    OPTIONAL
   }

   OcspIdentifier ::= SEQUENCE {
      ocspResponderID      ResponderID,
      -- As in OCSP response data
      producedAt           GeneralizedTime
      -- As in OCSP response data
   }

   OtherRevRefs ::= SEQUENCE {
       otherRevRefType   OtherRevRefType,
       otherRevRefs      ANY DEFINED BY otherRevRefType
    }

   OtherRevRefType ::= OBJECT IDENTIFIER

-- Certificate-values attribute

id-aa-ets-certValues OBJECT IDENTIFIER ::= { iso(1) member-body(2)
us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 23}

   CertificateValues ::=  SEQUENCE OF Certificate

-- Certificate-revocation-values attribute

id-aa-ets-revocationValues OBJECT IDENTIFIER ::= { iso(1)
member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
smime(16) id-aa(2) 24}

   RevocationValues ::=  SEQUENCE {
      crlVals           [0] SEQUENCE OF CertificateList OPTIONAL,
      ocspVals          [1] SEQUENCE OF BasicOCSPResponse OPTIONAL,
      otherRevVals      [2] OtherRevVals OPTIONAL}

   OtherRevVals ::= SEQUENCE {
       otherRevValType   OtherRevValType,
       otherRevVals      ANY DEFINED BY otherRevValType
   }

   OtherRevValType ::= OBJECT IDENTIFIER

-- CAdES-C time-stamp attribute

id-aa-ets-escTimeStamp OBJECT IDENTIFIER ::= { iso(1) member-body(2)
us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 25}

ESCTimeStampToken ::= TimeStampToken

-- Time-Stamped Certificates and CRLs

id-aa-ets-certCRLTimestamp OBJECT IDENTIFIER ::= { iso(1)
member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
smime(16) id-aa(2) 26}

TimestampedCertsCRLs ::= TimeStampToken

-- Archive time-stamp attribute
id-aa-ets-archiveTimestampV2  OBJECT IDENTIFIER ::= { iso(1)
member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
smime(16) id-aa(2) 48}

ArchiveTimeStampToken ::= TimeStampToken

-- Attribute-certificate-references attribute

id-aa-ets-attrCertificateRefs OBJECT IDENTIFIER ::= { iso(1)
member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
smime(16) id-aa(2) 44}

AttributeCertificateRefs ::=  SEQUENCE OF OtherCertID

-- Attribute-revocation-references attribute

id-aa-ets-attrRevocationRefs OBJECT IDENTIFIER ::= { iso(1)
member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
smime(16) id-aa(2) 45}

AttributeRevocationRefs ::=  SEQUENCE OF CrlOcspRef

END

------------------------
End of ASN.1 Definitions
------------------------
"""
from __future__ import unicode_literals, division, absolute_import, print_function

from .core import (
    Any,
    BMPString,
    Choice,
    GeneralizedTime,
    IA5String,
    Integer,
    Null,
    ObjectIdentifier,
    OctetString,
    Sequence,
    SequenceOf,
    SetOf,
    UTCTime,
    UTF8String,
    VisibleString,
)

# All the commented imports are available
# from .cms import CMSAttribute, ContentInfo, SignedData, EncapsulatedContentInfo, SignerInfo, MessageDigest, SigningTime, Countersignature

# TODO: handle certificate encoding correctly
from .cms import AttributeCertificateV2, CMSAttribute, CMSAttributeType, SetOfContentInfo
from .crl import CertificateList
from .ocsp import BasicOCSPResponse, ResponderId
from .tsp import IssuerSerial
# from .tsp import SigningCertificate, SigningCertificateV2,  ContentReference, ContentIdentifier
# from .tsp import TimeStampToken
from .x509 import AlgorithmIdentifier, Attributes, Certificate, CertificatePolicies, DirectoryString, Name
# from .x509 import Certificate, AlgorithmIdentifier, CertificateList, Name, Attribute
# from .x509 import GeneralNames, GeneralName, PolicyInformation

# Definitions of Object Identifier arcs used in the present document
# ==================================================================
# Referencing OID: id-etsi-es-IDUP-Mechanism-v1 = '0.4.0.1733.1.4.1'
# TODO: define this

#
# Basic ES CMS Attributes
# =======================
# defined in RFC 5126 (page 35, section 5.7.3.3.) and RFC 3126 (page 24, section 3.8.2)


class OtherHashValue(OctetString):
    pass


class OtherHashAlgAndValue(Sequence):
    _fields = [
        ('hashAlgorithm', AlgorithmIdentifier),
        ('hashValue', OtherHashValue),
    ]


class OtherHash(Choice):
    _alternatives = [
        ('sha1Hash', OtherHashValue),
        ('otherHash', OtherHashAlgAndValue),
    ]


class OtherCertId(Sequence):
    _fields = [
        ('otherCertHash', OtherHash),
        ('issuerSerial', IssuerSerial, {'optional': True}),
    ]


class OtherCertIds(SequenceOf):
    _child_spec = OtherCertId


class OtherSigningCertificate(Sequence):
    _fields = [
        ('certs', OtherCertIds),
        ('policies', CertificatePolicies, {'optional': True}),
    ]


class SetOfOtherSigningCertificate(SetOf):
    _child_spec = OtherSigningCertificate


CMSAttributeType._map['1.2.840.113549.1.9.16.2.19'] = 'other_signing_certificate'
CMSAttribute._oid_specs['other_signing_certificate'] = SetOfOtherSigningCertificate


# Policy ES CMS Attributes
# ========================
# defined in RFC 5126 page 36 section 5.8.


class SigPolicyId(ObjectIdentifier):
    pass


class SigPolicyHash(OtherHashAlgAndValue):
    pass


class SigPolicyQualifierId(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.9.16.5.1': 'uri',
        '1.2.840.113549.1.9.16.5.2': 'unotice',
    }


class SPuri(IA5String):
    pass


class DisplayText(Choice):
    _alternatives = [
        ('visibleString', VisibleString),
        ('bmpString', BMPString),
        ('utf8String', UTF8String),
    ]


class NoticeNumbers(SequenceOf):
    _child_spec = Integer


class NoticeReference(Sequence):
    _fields = [
        ('organization', DisplayText),
        ('noticeNumbers', NoticeNumbers),
    ]


class SPUserNotice(Sequence):
    _fields = [
        ('noticeRef', NoticeReference, {'optional': True}),
        ('explicitText', DisplayText, {'optional': True}),
    ]


class SigPolicyQualifierInfo(Sequence):
    _fields = [
        ('sigPolicyQualifierId', SigPolicyQualifierId),
        ('sigQualifier', Any)     # TODO
    ]
    _oid_pair = ('sigPolicyQualifierId', 'sigQualifier')
    _oid_specs = {
        'uri': SPuri,
        'unotice': SPUserNotice,
    }


class SigPolicyQualifierInfos(SequenceOf):      # should be 1..MAX
    _child_spec = SigPolicyQualifierInfo


class SignaturePolicyId(Sequence):
    _fields = [
        ('sigPolicyId', SigPolicyId),
        ('sigPolicyHash', SigPolicyHash),
        ('sigPolicyQualifiers', SigPolicyQualifierInfos, {'optional': True}),
    ]


class SignaturePolicyImplied(Null):
    pass


class SignaturePolicy(Choice):
    _alternatives = [
        ('signaturePolicyId', SignaturePolicyId),
        ('signaturePolicyImplied', SignaturePolicyImplied),     # RFC 5126 states "not used in this version"
    ]


class SetOfSignaturePolicy(SetOf):
    _child_spec = SignaturePolicy


CMSAttributeType._map['1.2.840.113549.1.9.16.2.15'] = 'signature_policy'
CMSAttribute._oid_specs['signature_policy'] = SetOfSignaturePolicy


# Optional Electronic Signature Attributes
# ========================================
#
# commitment-type
# ---------------

class CommitmentTypeIdentifier(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.9.16.6.1': 'proofOfOrigin',
        '1.2.840.113549.1.9.16.6.2': 'proofOfReceipt',
        '1.2.840.113549.1.9.16.6.3': 'proofOfDelivery',
        '1.2.840.113549.1.9.16.6.4': 'proofOfSender',
        '1.2.840.113549.1.9.16.6.5': 'proofOfApproval',
        '1.2.840.113549.1.9.16.6.6': 'proofOfCreation',
    }


class CommitmentTypeQualifier(Sequence):
    _fields = [
        ('commitmentTypeIdentifier', CommitmentTypeIdentifier),
        ('qualifier', Any),
    ]


class CommitmentTypeQualifiers(SequenceOf):
    _child_spec = CommitmentTypeQualifier


class CommitmentTypeIndication(Sequence):
    _fields = [
        ('commitmentTypeId', CommitmentTypeIdentifier),
        ('commitmentTypeQualifier', CommitmentTypeQualifiers, {'optional': True}),
    ]


class SetOfCommitmentTypeIndication(SetOf):
    _child_spec = CommitmentTypeIndication


CMSAttributeType._map['1.2.840.113549.1.9.16.2.16'] = 'commitment_type'
CMSAttribute._oid_specs['signature_policy'] = SetOfCommitmentTypeIndication

# signer-location
# ---------------


class PostalAddress(SequenceOf):
    _child_spec = DirectoryString


class SignerLocation(Sequence):
    _fields = [
        ('countryName', DirectoryString, {'explicit': 0, 'optional': True}),
        ('localityName', DirectoryString, {'explicit': 1, 'optional': True}),
        ('postalAdddress', PostalAddress, {'explicit': 2, 'optional': True}),
    ]


class SetOfSignerLocation(SetOf):
    _child_spec = SignerLocation


CMSAttributeType._map['1.2.840.113549.1.9.16.2.17'] = 'signer_location'
CMSAttribute._oid_specs['signature_policy'] = SetOfSignerLocation


# signer-attributes
# -----------------

ClaimedAttributes = Attributes                  # Attributes from x509 (RFC 3280)
CertifiedAttributes = AttributeCertificateV2    # AttributeCertificate from RFC 3281


class SignerAttributeChoice(Choice):
    _alternatives = [
        ('claimedAttributes', ClaimedAttributes, {'explicit': 0}),
        ('certifiedAttributes', CertifiedAttributes, {'explicit': 1}),
    ]


class SignerAttributes(SequenceOf):
    _child_spec = SignerAttributeChoice


class SetOfSignerAttributes(SetOf):
    _child_spec = SignerAttributes


CMSAttributeType._map['1.2.840.113549.1.9.16.2.18'] = 'signer_attributes'
CMSAttribute._oid_specs['signer_attributes'] = SetOfSignerAttributes


# content-time-stamp
# ------------------

# TimeStampToken = ContentInfo

SetOfTimeStampToken = SetOfContentInfo

CMSAttributeType._map['1.2.840.113549.1.9.16.2.20'] = 'content_time_stamp_token'
CMSAttribute._oid_specs['content_time_stamp_token'] = SetOfTimeStampToken

# signature-time-stamp
# --------------------
# already included in CMS
# CMSAttributeType._map['1.2.840.113549.1.9.16.2.14'] = 'signature_time_stamp_token'


# complete-certificate-references
# -------------------------------

# CompleteCertificateRefs = OtherCertIds


class SetOfOtherCertIds(SetOf):
    _child_spec = OtherCertIds


# SetOfCompleteCertificateRefs = SetOfOtherCertIds


CMSAttributeType._map['1.2.840.113549.1.9.16.2.21'] = 'complete_certificate_references'
CMSAttribute._oid_specs['complete_certificate_references'] = SetOfOtherCertIds


# complete-revocation-references
# ------------------------------

class CrlIdentifier(Sequence):
    _fields = [
        ('crlissuer', Name),
        ('crlIssuedTime', UTCTime),
        ('crlNumber', Integer, {'optional': True}),
    ]


class CrlValidatedId(Sequence):
    _fields = [
        ('crlHash', OtherHash),
        ('crlIdentifier', CrlIdentifier, {'optional': True}),
    ]


class CrlValidatedIds(SequenceOf):
    _child_spec = CrlValidatedId


class CRLListId(Sequence):
    _fields = [
        ('crls', CrlValidatedIds),
    ]


class OcspIdentifier(Sequence):
    _fields = [
        ('ocspResponderID', ResponderId),   # -- As in OCSP response data
        ('producedAt', GeneralizedTime),    # -- As in OCSP response data
    ]


class OcspResponsesId(Sequence):
    _fields = [
        ('ocspIdentifier', OcspIdentifier),
        ('ocspRepHash', OtherHash, {'optional': True}),
    ]


class OcspResponsesIds(SequenceOf):
    _child_spec = OcspResponsesId


class OcspListId(Sequence):
    _fields = [
        ('ocspResponses', OcspResponsesIds),
    ]


OtherRevRefType = ObjectIdentifier


class OtherRevRefs(Sequence):
    _fields = [
        ('otherRevRefType', OtherRevRefType),
        ('otherRevRefs', Any),  # DEFINED BY otherRevRefType
    ]


class CrlOcspRef(Sequence):
    _fields = [
        ('crlids', CRLListId, {'explicit': 0, 'optional': True}),
        ('ocspids', OcspListId, {'explicit': 1, 'optional': True}),
        ('otherRev', OtherRevRefs, {'explicit': 2, 'optional': True}),
    ]


class CrlOcspRefs(SequenceOf):
    _child_spec = CrlOcspRef


class SetOfCrlOcspRefs(SetOf):
    _child_spec = CrlOcspRefs


# CompleteRevocationRefs = CrlOcspRefs
# SetOfCompleteRevocationRefs = SetOfCrlOcspRefs

CMSAttributeType._map['1.2.840.113549.1.9.16.2.22'] = 'complete_revocation_references'
CMSAttribute._oid_specs['complete_revocation_references'] = SetOfCrlOcspRefs


# certificate-values
# ------------------


class CertificateValues(SequenceOf):
    _child_spec = Certificate


class SetOfCertificateValues(SetOf):
    _child_spec = CertificateValues


CMSAttributeType._map['1.2.840.113549.1.9.16.2.23'] = 'certificate_values'
CMSAttribute._oid_specs['certificate_values'] = SetOfCertificateValues


# certificate-revocation-values
# -----------------------------

OtherRevValType = ObjectIdentifier


class OtherRevVals(Sequence):
    _fields = [
        ('otherRevValType', OtherRevValType),
        ('otherRevVals', Any),
    ]


class CertificateLists(SequenceOf):
    _child_spec = CertificateList


class BasicOCSPResponses(SequenceOf):
    _child_spec = BasicOCSPResponse


class RevocationValues(Sequence):
    _fields = [
        ('crlVals', CertificateLists, {'optional': True, 'explicit': 0}),
        ('ocspVals', BasicOCSPResponses, {'optional': True, 'explicit': 1}),
        ('otherRevVals', OtherRevVals, {'optional': True, 'explicit': 2}),
    ]


class SetOfRevocationValues(SetOf):
    _child_spec = RevocationValues


CMSAttributeType._map['1.2.840.113549.1.9.16.2.24'] = 'certificate_revocation_values'
CMSAttribute._oid_specs['certificate_revocation_values'] = SetOfRevocationValues

# CAdES-C-time-stamp
# ------------------

CMSAttributeType._map['1.2.840.113549.1.9.16.2.25'] = 'cades_c_time_stamp_token'
CMSAttribute._oid_specs['cades_c_time_stamp_token'] = SetOfTimeStampToken

# Time-Stamped Certificates and CRLs
# ----------------------------------

CMSAttributeType._map['1.2.840.113549.1.9.16.2.26'] = 'certs_crls_time_stamp_token'
CMSAttribute._oid_specs['certs_crls_time_stamp_token'] = SetOfTimeStampToken

# Archive time-stamp
# ------------------
CMSAttributeType._map['1.2.840.113549.1.9.16.2.48'] = 'archive_time_tamp_token'
CMSAttribute._oid_specs['archive_time_tamp_token'] = SetOfTimeStampToken

# Attribute-certificate-references
# --------------------------------

# AttributeCertificateRefs = OtherCertIds

CMSAttributeType._map['1.2.840.113549.1.9.16.2.44'] = 'attribute_certificate_references'
CMSAttribute._oid_specs['attribute_certificate_references'] = SetOfOtherCertIds

# Attribute-revocation-references
CMSAttributeType._map['1.2.840.113549.1.9.16.2.45'] = 'attribute_revocation_references'
CMSAttribute._oid_specs['attribute_revocation_references'] = SetOfCrlOcspRefs
