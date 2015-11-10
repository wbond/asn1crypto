# changelog

## 0.13.0

 - Backwards compatibility break: the native representation of some
   `algos.EncryptionAlgorithmId` values changed. `aes128` became `aes128_cbc`,
   `aes192` became `aes192_cbc` and `aes256` became `aes256_cbc`.
 - Added more OIDs to `algos.EncryptionAlgorithmId`
 - Added more OIDs to `cms.KeyEncryptionAlgorithmId`
 - `x509.Name.human_friendly` now properly supports multiple values per
   `x509.NameTypeAndValue` object
 - Added `ocsp.OCSPResponse.basic_ocsp_response` and
   `ocsp.OCSPResponse.response_data` properties
 - Added `algos.EncryptionAlgorithm.encryption_mode` property
 - Fixed a bug with parsing times containing timezone offsets in Python 3
 - The `attributes` field of `csr.CertificationRequestInfo` is now optional,
   for compatibility with other ASN.1 parsers

## 0.12.2

 - Correct `core.Sequence.__setitem__()` so set `core.VOID` to an optional
   field when `None` is set

## 0.12.1

 - Fixed a `unicode`/`bytes` bug with `x509.URI.dump()` on Python 2

## 0.12.0

 - Backwards Compatiblity Break: `core.NoValue` was renamed to `core.Void` and
   a singleton was added as `core.VOID`
 - 20-30% improvement in parsing performance
 - `core.Void` now implements `__nonzero__`
 - `core.Asn1Value.copy()` now performs a deep copy
 - All `core` value classes are now compatible with the `copy` module
 - `core.SequenceOf` and `core.SetOf` now implement `__contains__`
 - Added `x509.Name.__len__()`
 - Fixed a bug where `core.Choice.validate()` would not properly account for
   explicit tagging
 - `core.Choice.load()` now properly passes itself as the spec when parsing
 - `x509.Certificate.crl_distribution_points` no longer throws an exception if
   the `DistributionPoint` does not have a value for the `distribution_point`
   field

## 0.11.1

 - Corrected `core.UTCTime` to interpret year <= 49 as 20xx and >= 50 as 19xx
 - `keys.PublicKeyInfo.hash_algo` can now handle DSA keys without parameters
 - Added `crl.CertificateList.sha256` and `crl.CertificateList.sha1`
 - Fixed `x509.Name.build()` to properly encode `country_name`, `serial_number`
   and `dn_qualifier` as `core.PrintableString` as specified in RFC 5280,
   instead of `core.UTF8String`

## 0.11.0

 - Added Python 2.6 support
 - Added ability to compare primitive type objects
 - Implemented proper support for internationalized domains, URLs and email
   addresses in `x509.Certificate`
 - Comparing `x509.Name` and `x509.GeneralName` objects adheres to RFC 5280
 - `x509.Certificate.self_signed` and `x509.Certificate.self_issued` no longer
   require that certificate is for a CA
 - Fixed `x509.Certificate.valid_domains` to adhere to RFC 6125
 - Added `x509.Certificate.is_valid_domain_ip()`
 - Added `x509.Certificate.sha1` and `x509.Certificate.sha256`
 - Exposed `util.inet_ntop()` and `util.inet_pton()` for IP address encoding
 - Improved exception messages for improper types to include type's module name

## 0.10.1

 - Fixed bug in `core.Sequence` affecting Python 2.7 and pypy

## 0.10.0

 - Added PEM encoding/decoding functionality
 - `core.BitString` now uses item access instead of attributes for named bit
   access
 - `core.BitString.native` now uses a `set` of unicode strings when `_map` is
   present
 - Removed `core.Asn1Value.pprint()` method
 - Added `core.ParsableOctetString` class
 - Added `core.ParsableOctetBitString` class
 - Added `core.Asn1Value.copy()` method
 - Added `core.Asn1Value.debug()` method
 - Added `core.SequenceOf.append()` method
 - Added `core.Sequence.spec()` and `core.SequenceOf.spec()` methods
 - Added correct IP address parsing to `x509.GeneralName`
 - `x509.Name` and `x509.GeneralName` are now compared according to rules in
   RFC 5280
 - Added convenience attributes to:
   - `algos.SignedDigestAlgorithm`
   - `crl.CertificateList`
   - `crl.RevokedCertificate`
   - `keys.PublicKeyInfo`
   - `ocsp.OCSPRequest`
   - `ocsp.Request`
   - `ocsp.OCSPResponse`
   - `ocsp.SingleResponse`
   - `x509.Certificate`
   - `x509.Name`
 - Added `asn1crypto.util` module with the following items:
   - `int_to_bytes()`
   - `int_from_bytes()`
   - `timezone.utc`
 - Added `setup.py clean` command

## 0.9.0

 - Initial release
