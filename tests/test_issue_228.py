"""
Reproduce the issue: "ValueError when x500UniqueIdentifier is of type UTF8String"
- https://github.com/wbond/asn1crypto/issues/228
"""

import pytest

from asn1crypto import x509, pem

# A self-signed certificate without a unique identifier. Generated with:
#   openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.pem -sha256 -days 365 -subj '/CN=test_ca' -nodes -addext 'keyUsage = digitalSignature'
SELF_SIGNED_CERTIFICATE_WITHOUT_UNIQUE_IDENTIFIER = b"-----BEGIN CERTIFICATE-----\nMIIFEjCCAvqgAwIBAgIUMeSviFzM1Y4sC5J1LESGqBpSXJ4wDQYJKoZIhvcNAQEL\nBQAwEjEQMA4GA1UEAwwHdGVzdF9jYTAeFw0yMjEwMTgxNTQxNDFaFw0yMzEwMTgx\nNTQxNDFaMBIxEDAOBgNVBAMMB3Rlc3RfY2EwggIiMA0GCSqGSIb3DQEBAQUAA4IC\nDwAwggIKAoICAQDLgJB5X86SkyGiEHwRytCAU57IpDiC2y9luRJ720ApnFIB/DBm\nlrgpAJOQFumCbrJyFAJVOhRnPyN0uEU2sxUxAxBCDx4Y2NwkDuKcBJst3WhSQct/\n0H16EVnfY8mZLmfPY12dwc/hmnuDvTYRZCTfirxsLD2yLrijVPjuQTVFlUrQtLPR\nYuOJiiJHXSrNtH3x7F2Nz3gjVDNAcE2lZmWXGnf++dSrF3wXADu/no3ZbXUOqmUj\nhxtJLkM1FvCJ10Ar8PQa6lGdRjfvaMLierqdHq2qOalC42s/g+6Rc89VpCZHbUSu\nKsN1ummgv6F/7aOXaaPYgGuRP219N5gtAuJzkOZ7yN5u5sYly8Tq5HhVaE71yCTY\nszdA6zyFGNC/D5vzD4JbgxnYwLJluMUVBFjA7uB4FAWvQVGXIKYUCWDwesb5osND\nSaN3LYPD/pKhRRwNNKTw3+4pwYXo0KBUYK/egVYUaoKARrgvOvVQSHqJl3rdl/uQ\ntHCgsJlWiNzhHrMP46NU26AuZmZ+fabhtvZitC4sXzvPBQtCA6fL1wXo5X/UdXVb\nd6FlFUJnVkvHTKuZEjCqKhxfd37eoqLbZ6QxuTEHMmZGZHJsC0IuB1ePFKRwYQ81\nw3CEBdM1M1jAoUE/FPmydh+X9B/34BTObkhKsg72nDh/DyXSS+sp1sIkNwIDAQAB\no2AwXjAdBgNVHQ4EFgQU0e06i2g2nucUHh7/kOvOVfTvDTcwHwYDVR0jBBgwFoAU\n0e06i2g2nucUHh7/kOvOVfTvDTcwDwYDVR0TAQH/BAUwAwEB/zALBgNVHQ8EBAMC\nB4AwDQYJKoZIhvcNAQELBQADggIBAMKVm5dNtgUPHVGb2L/EpN005dCC/u5oAQck\naNGNcAMxJRk2vel5xc9U2VUACUOUwwDyySqGItNufPGqXT5cFjgPqnpSFmVbr7yb\nnYPZu7vGfaoncLo+0XiVpDGYS4RpAz8YwVcOKTIMR8/ppD/GO63Zv66AjQoLWOJ/\nR93IJz0G/hLGseGKxjBRU75ghgs77RMoO60W47Vm0AFGZl/PWWOGRGG2au27+p/l\nJ0QEAfhXtOqsvyHa+JTIhefq81C9qgMxgUlA9tXQO9EwMl/fsPnDlp0c9yfL7eEZ\n5U9JpPIX/mrFUrL8CO0sgI//miPimV9dxGP3Qy26CRM5+yGHXuHYdBbiwT2rNXnu\nbww6mHVoHKN8W9xNYeLyIedCJewKvn/INvA+zEy2xnn8hXV6Gq5fbbmCC2XxgzDk\nOjqetmEqcEe+yIQrisLq7rZE/FiQYfWzEpxB8wX7H3YYVUQ8ZAWbKsdtHkGrih1H\nKytztKVKrsHd4DpDVy/IFWSsLuK+1jzOIE7dAkVw3822YdGJTdZxjPkWPuA7N1nZ\n/MH3Rd4RlggfCwOLMq8chXlbgsysbwd1djzfMpCngIBV8w3TnG7XK29AjaTR91ot\nWzeiP1hP7KYBHkEa/ovqFAc1mbfYt/NIDTpzlw+uamRzjQ2WymkNBGPQgr6LguZQ\nD3XaChqg\n-----END CERTIFICATE-----\n"

# A self-signed certificate with a unique identifier. Generated with:
#   openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.pem -sha256 -days 365 -subj '/CN=test_ca/x500UniqueIdentifier=test_ca'  -nodes -addext 'keyUsage = digitalSignature'
SELF_SIGNED_CERTIFICATE_WITH_UNIQUE_IDENTIFIER = b"-----BEGIN CERTIFICATE-----\nMIIFNjCCAx6gAwIBAgIUCPrnutEh5MXwjmq7fnt+HfguyRcwDQYJKoZIhvcNAQEL\nBQAwJDEQMA4GA1UEAwwHdGVzdF9jYTEQMA4GA1UELQwHdGVzdF9jYTAeFw0yMjEw\nMTgxNTQzMTBaFw0yMzEwMTgxNTQzMTBaMCQxEDAOBgNVBAMMB3Rlc3RfY2ExEDAO\nBgNVBC0MB3Rlc3RfY2EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC6\n6EfjFe7gUOKxs82ZaKBJmnKmGoiinsuBpV6NPMymL3YaAWE4Q11laa0fVJsGOWvi\nWqM4sF4IZd0+5KaktXNms6U0MR6JI1LleA2iuCxi8FL6DCCFHAuVrHys76xwc+79\nfkugu5OThlr98iiEURvIhGat9c3mhWksfSXIb3qTocI4+oglAZBWE7lINIAS2RR7\nz+KuNNhsAExnnnGVKHRx1uVZzDezQgcMKZUQzr1xjkCim5bw0njbEjopDcT8rOsU\nXahMu7J69XDRNh8O0Qao0kn7Gc9agV/PDZo3fq13ajUT3Z1pTbmp9OgdVBXH0lWn\ndzfwD0+SCsrkJnvWPYxVPzsPkVG9rs9kazglicleO8fFz1RKEeX8bKh7yPEjKI07\nEucyAuxfL2UXm/kQE/U40CL19ASve0bGoYWBR9La0huxpDom6UBKb/7BND7Ps9ef\neZGUkOl2JxW9epjas5Zia2VEFnXDTI26Z5Dcsb02DLurvLmyd69gOtpTEwd0iMpN\nKwXEMksbgT2e3FfcO2j9Ew5g7QSMArHDvlsrM/+jCi9Hzh5PhZxgcRQ9aKW6EUdY\nuY8ZKV20SSEYxVB14GhSdmWRyzMFIFCS2Bj9t7DkKor5tjkI/rzNk2de33BryR/0\nvMAwvY+KL0vQs6mowhANbsOKUMJEEzfpHW2JWB4i5QIDAQABo2AwXjAdBgNVHQ4E\nFgQUuGDEUb1ZfcLcmEhK5qVOSuKJ/cMwHwYDVR0jBBgwFoAUuGDEUb1ZfcLcmEhK\n5qVOSuKJ/cMwDwYDVR0TAQH/BAUwAwEB/zALBgNVHQ8EBAMCB4AwDQYJKoZIhvcN\nAQELBQADggIBAHgi/iGEdhH9/ao9Ql6PofQqA9OL7MnjEocoEqhOQx1jNtGRxgzJ\nUS+G05NXTm2Ll5TPjj6Zg8Mo35WN+94/oOGGAfeS2aKONqrJ6LEnTM+gaN05Fih8\nh+tDjlz94WFvgGG3Qf0TMoMfSauDTB4Vn1aYbnaG5FfVHdWms6UBb7LS4srIZzL7\nlhJRUJV0bRQAHNV4pgarOIslzJiYYdhIAEigf3Zj/MOGNQy+uWXdBieavEXACV2r\nmGaqTluzh7WrF+TgWXSVLDQW/jYGYIh1h+7MbDeadfzOTWk4gQJU4RRm96YFivfc\ndmJmrQMYXpbDDQuPqEMzq7lWW4rZho1wbpXFakU1ZMRjpHaLJAp4+8WIHUImuDPY\nRA8SYfeMTY4HvO0j1DTDrN+Nzc612xrOvrx6EFAwydDk5/upPAJND2/HCm2QjuAm\nxCHECYf7/7OM5vl6ktEMJT3Dt/dtSKpw6+HnT/vFr+mIMJYYBAyTpN6UsGPsVsS6\nXEmKKB82EdaT3/8tie6AAfFDvswKI5PzHSyiProsNUcCGbv+bp87uwTcql5ayTei\nuqJ1t3t574/X4xYVD3v96fJ/VMsFmR3x59nL08mqYusA86rs2Ey93Y31jmk48wSr\nu7T1GLOivJ4Dbk7yzitkpjbDAWnkouHSMDbqrdxwzFG2xaIanJMFxVtO\n-----END CERTIFICATE-----\n"


@pytest.fixture(
    params=[
        SELF_SIGNED_CERTIFICATE_WITHOUT_UNIQUE_IDENTIFIER,
        SELF_SIGNED_CERTIFICATE_WITH_UNIQUE_IDENTIFIER,
    ],
    ids=["without_unique_identifier", "with_unique_identifier"],
)
def self_signed_certificate(request):
    type_name, headers, der_bytes = pem.unarmor(request.param)
    return x509.Certificate.load(der_bytes)


def test_subject_common_name(self_signed_certificate):
    assert self_signed_certificate.subject.native["common_name"] == "test_ca"


def test_validate_certificate_with_trust_root(self_signed_certificate):
    try:
        from certvalidator import CertificateValidator, ValidationContext
    except ImportError:
        pytest.skip("certvalidator not installed")
    validation_context = ValidationContext(extra_trust_roots=[self_signed_certificate])
    validator = CertificateValidator(
        self_signed_certificate, validation_context=validation_context
    )
    validator.validate_usage({"digital_signature"})


def test_validate_certificate_without_trust_root(self_signed_certificate):
    try:
        from certvalidator import CertificateValidator, errors
    except ImportError:
        pytest.skip("certvalidator not installed")
    validator = CertificateValidator(self_signed_certificate)
    with pytest.raises(errors.InvalidCertificateError):
        validator.validate_usage({"digital_signature"})
