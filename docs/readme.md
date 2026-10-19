# asn1crypto Documentation

The documentation for *asn1crypto* is composed of tutorials on basic usage and
links to the source for the various pre-defined type classes.

## Tutorials

 - [Universal Types with BER/DER Decoder and DER Encoder](universal_types.md)
 - [PEM Decoder and Encoder](pem.md)

## Reference

 - [Universal types](../asn1crypto/core.py), `asn1crypto.core`
 - [Digest, MAC, signed digest and encryption algorithms](../asn1crypto/algos.py), `asn1crypto.algos`
 - [Private and public keys](../asn1crypto/keys.py), `asn1crypto.keys`
 - [X.509 certificates](../asn1crypto/x509.py), `asn1crypto.x509`
 - [Certificate revocation lists (CRLs)](../asn1crypto/crl.py), `asn1crypto.crl`
 - [Online certificate status protocol (OCSP)](../asn1crypto/ocsp.py), `asn1crypto.ocsp`
 - [Certificate signing requests (CSRs)](../asn1crypto/csr.py), `asn1crypto.csr`
 - [Private key/certificate containers (PKCS#12)](../asn1crypto/pkcs12.py), `asn1crypto.pkcs12`
 - [Cryptographic message syntax (CMS, PKCS#7)](../asn1crypto/cms.py), `asn1crypto.cms`
 - [Time stamp protocol (TSP)](../asn1crypto/tsp.py), `asn1crypto.tsp`
 - [PDF signatures](../asn1crypto/pdf.py), `asn1crypto.pdf`

## CMS AES-GMAC parameters

The historically named `algos.HmacAlgorithm` also represents other MAC
algorithms used by CMS, including `des_mac` and `aes128_gmac`, `aes192_gmac`,
and `aes256_gmac`. The AES-GMAC algorithms use `algos.GmacParams`:

```python
mac_algorithm = algos.HmacAlgorithm({
    'algorithm': 'aes128_gmac',
    'parameters': {'nonce': nonce, 'length': 16},
})
```

Supply this as `cms.AuthenticatedData`'s `mac_algorithm`. The parameters must
be present; `length` defaults to 12 and may be 12 through 16 bytes. It must
match the message's MAC length. See [RFC 9044](https://www.rfc-editor.org/rfc/rfc9044.html).

These classes encode and decode ASN.1 structures; they do not compute or
verify MACs, enforce nonce uniqueness, or validate cryptographic algorithm
usage. AES-GMAC must not be used as a PBKDF2 pseudorandom function, despite
PBKDF2 sharing the `HmacAlgorithm` representation.
