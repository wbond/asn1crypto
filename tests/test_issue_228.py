"""
Reproduce the issue: "ValueError when x500UniqueIdentifier is of type UTF8String"
- https://github.com/wbond/asn1crypto/issues/228
"""

import unittest

from asn1crypto import x509, pem

try:
    import certvalidator
except ImportError:
    certvalidator = None

# A self-signed certificate without a unique identifier. Generated with:
#   openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.pem -sha256 -days 365 \
#     -subj '/CN=test_ca' -nodes -addext 'keyUsage = digitalSignature'
SELF_SIGNED_CERTIFICATE_WITHOUT_UNIQUE_IDENTIFIER = """\
-----BEGIN CERTIFICATE-----
MIIFEjCCAvqgAwIBAgIUMeSviFzM1Y4sC5J1LESGqBpSXJ4wDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHdGVzdF9jYTAeFw0yMjEwMTgxNTQxNDFaFw0yMzEwMTgx
NTQxNDFaMBIxEDAOBgNVBAMMB3Rlc3RfY2EwggIiMA0GCSqGSIb3DQEBAQUAA4IC
DwAwggIKAoICAQDLgJB5X86SkyGiEHwRytCAU57IpDiC2y9luRJ720ApnFIB/DBm
lrgpAJOQFumCbrJyFAJVOhRnPyN0uEU2sxUxAxBCDx4Y2NwkDuKcBJst3WhSQct/
0H16EVnfY8mZLmfPY12dwc/hmnuDvTYRZCTfirxsLD2yLrijVPjuQTVFlUrQtLPR
YuOJiiJHXSrNtH3x7F2Nz3gjVDNAcE2lZmWXGnf++dSrF3wXADu/no3ZbXUOqmUj
hxtJLkM1FvCJ10Ar8PQa6lGdRjfvaMLierqdHq2qOalC42s/g+6Rc89VpCZHbUSu
KsN1ummgv6F/7aOXaaPYgGuRP219N5gtAuJzkOZ7yN5u5sYly8Tq5HhVaE71yCTY
szdA6zyFGNC/D5vzD4JbgxnYwLJluMUVBFjA7uB4FAWvQVGXIKYUCWDwesb5osND
SaN3LYPD/pKhRRwNNKTw3+4pwYXo0KBUYK/egVYUaoKARrgvOvVQSHqJl3rdl/uQ
tHCgsJlWiNzhHrMP46NU26AuZmZ+fabhtvZitC4sXzvPBQtCA6fL1wXo5X/UdXVb
d6FlFUJnVkvHTKuZEjCqKhxfd37eoqLbZ6QxuTEHMmZGZHJsC0IuB1ePFKRwYQ81
w3CEBdM1M1jAoUE/FPmydh+X9B/34BTObkhKsg72nDh/DyXSS+sp1sIkNwIDAQAB
o2AwXjAdBgNVHQ4EFgQU0e06i2g2nucUHh7/kOvOVfTvDTcwHwYDVR0jBBgwFoAU
0e06i2g2nucUHh7/kOvOVfTvDTcwDwYDVR0TAQH/BAUwAwEB/zALBgNVHQ8EBAMC
B4AwDQYJKoZIhvcNAQELBQADggIBAMKVm5dNtgUPHVGb2L/EpN005dCC/u5oAQck
aNGNcAMxJRk2vel5xc9U2VUACUOUwwDyySqGItNufPGqXT5cFjgPqnpSFmVbr7yb
nYPZu7vGfaoncLo+0XiVpDGYS4RpAz8YwVcOKTIMR8/ppD/GO63Zv66AjQoLWOJ/
R93IJz0G/hLGseGKxjBRU75ghgs77RMoO60W47Vm0AFGZl/PWWOGRGG2au27+p/l
J0QEAfhXtOqsvyHa+JTIhefq81C9qgMxgUlA9tXQO9EwMl/fsPnDlp0c9yfL7eEZ
5U9JpPIX/mrFUrL8CO0sgI//miPimV9dxGP3Qy26CRM5+yGHXuHYdBbiwT2rNXnu
bww6mHVoHKN8W9xNYeLyIedCJewKvn/INvA+zEy2xnn8hXV6Gq5fbbmCC2XxgzDk
OjqetmEqcEe+yIQrisLq7rZE/FiQYfWzEpxB8wX7H3YYVUQ8ZAWbKsdtHkGrih1H
KytztKVKrsHd4DpDVy/IFWSsLuK+1jzOIE7dAkVw3822YdGJTdZxjPkWPuA7N1nZ
/MH3Rd4RlggfCwOLMq8chXlbgsysbwd1djzfMpCngIBV8w3TnG7XK29AjaTR91ot
WzeiP1hP7KYBHkEa/ovqFAc1mbfYt/NIDTpzlw+uamRzjQ2WymkNBGPQgr6LguZQ
D3XaChqg
-----END CERTIFICATE-----
""".encode()

# A self-signed certificate with a unique identifier. Generated with:
#   openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.pem -sha256 -days 365  \
#     -subj '/CN=test_ca/x500UniqueIdentifier=test_ca'  -nodes -addext 'keyUsage = digitalSignature'
SELF_SIGNED_CERTIFICATE_WITH_UNIQUE_IDENTIFIER = """\
-----BEGIN CERTIFICATE-----
MIIFNjCCAx6gAwIBAgIUCPrnutEh5MXwjmq7fnt+HfguyRcwDQYJKoZIhvcNAQEL
BQAwJDEQMA4GA1UEAwwHdGVzdF9jYTEQMA4GA1UELQwHdGVzdF9jYTAeFw0yMjEw
MTgxNTQzMTBaFw0yMzEwMTgxNTQzMTBaMCQxEDAOBgNVBAMMB3Rlc3RfY2ExEDAO
BgNVBC0MB3Rlc3RfY2EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC6
6EfjFe7gUOKxs82ZaKBJmnKmGoiinsuBpV6NPMymL3YaAWE4Q11laa0fVJsGOWvi
WqM4sF4IZd0+5KaktXNms6U0MR6JI1LleA2iuCxi8FL6DCCFHAuVrHys76xwc+79
fkugu5OThlr98iiEURvIhGat9c3mhWksfSXIb3qTocI4+oglAZBWE7lINIAS2RR7
z+KuNNhsAExnnnGVKHRx1uVZzDezQgcMKZUQzr1xjkCim5bw0njbEjopDcT8rOsU
XahMu7J69XDRNh8O0Qao0kn7Gc9agV/PDZo3fq13ajUT3Z1pTbmp9OgdVBXH0lWn
dzfwD0+SCsrkJnvWPYxVPzsPkVG9rs9kazglicleO8fFz1RKEeX8bKh7yPEjKI07
EucyAuxfL2UXm/kQE/U40CL19ASve0bGoYWBR9La0huxpDom6UBKb/7BND7Ps9ef
eZGUkOl2JxW9epjas5Zia2VEFnXDTI26Z5Dcsb02DLurvLmyd69gOtpTEwd0iMpN
KwXEMksbgT2e3FfcO2j9Ew5g7QSMArHDvlsrM/+jCi9Hzh5PhZxgcRQ9aKW6EUdY
uY8ZKV20SSEYxVB14GhSdmWRyzMFIFCS2Bj9t7DkKor5tjkI/rzNk2de33BryR/0
vMAwvY+KL0vQs6mowhANbsOKUMJEEzfpHW2JWB4i5QIDAQABo2AwXjAdBgNVHQ4E
FgQUuGDEUb1ZfcLcmEhK5qVOSuKJ/cMwHwYDVR0jBBgwFoAUuGDEUb1ZfcLcmEhK
5qVOSuKJ/cMwDwYDVR0TAQH/BAUwAwEB/zALBgNVHQ8EBAMCB4AwDQYJKoZIhvcN
AQELBQADggIBAHgi/iGEdhH9/ao9Ql6PofQqA9OL7MnjEocoEqhOQx1jNtGRxgzJ
US+G05NXTm2Ll5TPjj6Zg8Mo35WN+94/oOGGAfeS2aKONqrJ6LEnTM+gaN05Fih8
h+tDjlz94WFvgGG3Qf0TMoMfSauDTB4Vn1aYbnaG5FfVHdWms6UBb7LS4srIZzL7
lhJRUJV0bRQAHNV4pgarOIslzJiYYdhIAEigf3Zj/MOGNQy+uWXdBieavEXACV2r
mGaqTluzh7WrF+TgWXSVLDQW/jYGYIh1h+7MbDeadfzOTWk4gQJU4RRm96YFivfc
dmJmrQMYXpbDDQuPqEMzq7lWW4rZho1wbpXFakU1ZMRjpHaLJAp4+8WIHUImuDPY
RA8SYfeMTY4HvO0j1DTDrN+Nzc612xrOvrx6EFAwydDk5/upPAJND2/HCm2QjuAm
xCHECYf7/7OM5vl6ktEMJT3Dt/dtSKpw6+HnT/vFr+mIMJYYBAyTpN6UsGPsVsS6
XEmKKB82EdaT3/8tie6AAfFDvswKI5PzHSyiProsNUcCGbv+bp87uwTcql5ayTei
uqJ1t3t574/X4xYVD3v96fJ/VMsFmR3x59nL08mqYusA86rs2Ey93Y31jmk48wSr
u7T1GLOivJ4Dbk7yzitkpjbDAWnkouHSMDbqrdxwzFG2xaIanJMFxVtO
-----END CERTIFICATE-----
""".encode()


class Issue228Tests(unittest.TestCase):
    RAW_CERTIFICATE = NotImplemented

    def setUp(self):
        _, _, der_bytes = pem.unarmor(self.RAW_CERTIFICATE)
        self.self_signed_certificate = x509.Certificate.load(der_bytes)

    def test_subject_common_name(self):
        self.assertEqual(self.self_signed_certificate.subject.native["common_name"], "test_ca")

    @unittest.skipUnless(certvalidator, "requires certvalidator")
    def test_validate_certificate_with_trust_root(self):
        validation_context = certvalidator.ValidationContext(extra_trust_roots=[self.self_signed_certificate])
        validator = certvalidator.CertificateValidator(
            self.self_signed_certificate, validation_context=validation_context
        )
        validator.validate_usage({"digital_signature"})

    @unittest.skipUnless(certvalidator, "requires certvalidator")
    def test_validate_certificate_without_trust_root(self):
        validator = certvalidator.CertificateValidator(self.self_signed_certificate)
        self.assertRaises(
            certvalidator.errors.InvalidCertificateError, lambda: validator.validate_usage({"digital_signature"})
        )


class Issue228WithoutUniqueIdentifierTests(Issue228Tests):
    RAW_CERTIFICATE = SELF_SIGNED_CERTIFICATE_WITHOUT_UNIQUE_IDENTIFIER


class Issue228WithUniqueIdentifierTests(Issue228Tests):
    RAW_CERTIFICATE = SELF_SIGNED_CERTIFICATE_WITH_UNIQUE_IDENTIFIER
