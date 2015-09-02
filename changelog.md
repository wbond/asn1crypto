# changelog

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
