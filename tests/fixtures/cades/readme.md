# CAdES test signatures

## About

This directory includes real-world signatures, i.e. the signatures:

* Have been created using a valid trans-european qualified certificate, valid at the time of writing
* Have been created using then open source AutoFirma 1.5/1.6 signature client (cliente @firma project) supported by the spanish government
* The A / XL formats have been created by a official Trust Service Provide (TSP) (Ministry for Public Administrations)

## CAdES Intro

CMS Advanced Electronic Signatures (CAdES) is a signature format (as efined by European Telecommunications Standards Institute, ETSI TS 101 733 and RFC 5126) which is basically aimed at long term signature validations, i.e. it should be possible to validate signatures long time after the signing certificate has expired. Whenever signature / digest algorithms get weak, signatures can be sealed again using more modern ones.

For this purpose, full timestamped verification data (OCSP responses/CRL data) with complete certificates are added to data structure and sealed by an external trusted service.

## Policies

A *Signature Policy* makes explicit under what conditions signatures are accomplished and how they should be verified.

CAdES signatures may have or not explicit signature policy:

* BES: Basic Enhanced Signature: No policy info
* EPES: Excplict Policy Enhanced Signature: An explicit policy is given through a URI, normally a URL which points to a human readable document, and a registered Object Identifier.

## Implicit / Explicit

CAdES, like XADES, can have the full original document encapsulated or just a hash of it:

* Implicit: The original document is encapsulated
* Explicit: The original document is not included, just a hash

## Extended info: T, C, X, XL, A

Extended info can be added to enable long term verification:

* T (timestamp): Third-party (TSP) timestamp info is added to the signature
* C (complete): Complete validation references are enabled to allow for off-line validations
* X (extended): Additional date/time info is included expressing when the  validation info was added
* XL (extended long-term): Complete certificates are included, i.e., the complete certificate hierarchy of both, signer and revocation verifier. *Long-Term-Verification enabled*.
* A (archive): Additional info is added about the resealing policy. *Long-Term-Verification enabled*

The test data file names have been structured like this:
<pre>
    cades-(bes|epes)[-(T|C|X|XL|A)]-(explicit|implicit).der
</pre>

## Other additional attributes

Beside this, some additional attributes are added to basic signature data, e.g.:

* CommitmentType: make explicit what the signer wants to express with his signature RFC 5126 except:
  * Proof of origin indicates that the signer recognizes to have created, approved, and sent the message.
  * Proof of receipt indicates that signer recognizes to have received the content of the message.
  * Proof of delivery indicates that the TSP providing that indication has delivered a message in a local store accessible to the recipient of the message.
  * Proof of sender indicates that the entity providing that indication has sent the message (but not necessarily created it).
  * Proof of approval indicates that the signer has approved the content of the message.
* Signer Location: Signer address / city where the document has been signed. 

