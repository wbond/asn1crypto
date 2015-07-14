# coding: utf-8
from __future__ import unicode_literals

import unittest
import sys
import os
from collections import OrderedDict
from datetime import datetime

from asn1crypto import x509, core

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')



class X509Tests(unittest.TestCase):

    def test_extensions(self):
        with open(os.path.join(fixtures_dir, 'keys/test-der.crt'), 'rb') as f:
            cert = x509.Certificate.load(f.read())

        self.assertEqual([], cert.critical_extensions)
        self.assertEqual(b'\xbeB\x85=\xcc\xff\xe3\xf9(\x02\x8f~XV\xb4\xfd\x03\\\xeaK', cert.key_identifier_value.native)
        self.assertEqual(None, cert.key_usage_value)
        self.assertEqual(None, cert.subject_alt_name_value)
        self.assertEqual(True, cert.basic_constraints_value['ca'].native)
        self.assertEqual(None, cert.basic_constraints_value['path_len_constraint'].native)
        self.assertEqual(None, cert.name_constraints_value)
        self.assertEqual(None, cert.crl_distribution_points_value)
        self.assertEqual(None, cert.certificate_policies_value)
        self.assertEqual(None, cert.policy_mappings_value)
        self.assertEqual(b'\xbeB\x85=\xcc\xff\xe3\xf9(\x02\x8f~XV\xb4\xfd\x03\\\xeaK', cert.authority_key_identifier_value['key_identifier'].native)
        self.assertEqual(None, cert.policy_constraints_value)
        self.assertEqual(None, cert.extended_key_usage_value)
        self.assertEqual(None, cert.authority_information_access_value)
        self.assertEqual(None, cert.ocsp_no_check_value)

    def test_extensions2(self):
        with open(os.path.join(fixtures_dir, 'keys/test-inter-der.crt'), 'rb') as f:
            cert = x509.Certificate.load(f.read())

        self.assertEqual([], cert.critical_extensions)
        self.assertEqual(b'\xd2\n\xfd.%\xd1\xb7!\xd7P~\xbb\xa4}\xbf4\xefR^\x02', cert.key_identifier_value.native)
        self.assertEqual(None, cert.key_usage_value)
        self.assertEqual(None, cert.subject_alt_name_value)
        self.assertEqual(True, cert.basic_constraints_value['ca'].native)
        self.assertEqual(None, cert.basic_constraints_value['path_len_constraint'].native)
        self.assertEqual(None, cert.name_constraints_value)
        self.assertEqual(None, cert.crl_distribution_points_value)
        self.assertEqual(None, cert.certificate_policies_value)
        self.assertEqual(None, cert.policy_mappings_value)
        self.assertEqual(b'\xbeB\x85=\xcc\xff\xe3\xf9(\x02\x8f~XV\xb4\xfd\x03\\\xeaK', cert.authority_key_identifier_value['key_identifier'].native)
        self.assertEqual(None, cert.policy_constraints_value)
        self.assertEqual(None, cert.extended_key_usage_value)
        self.assertEqual(None, cert.authority_information_access_value)
        self.assertEqual(None, cert.ocsp_no_check_value)

    def test_extensions3(self):
        with open(os.path.join(fixtures_dir, 'keys/test-third-der.crt'), 'rb') as f:
            cert = x509.Certificate.load(f.read())

        self.assertEqual([], cert.critical_extensions)
        self.assertEqual(b'D8\xe0\xe0&\x85\xbf\x98\x86\xdc\x1b\xe1\x1d\xf520\xbe\xab\xac\r', cert.key_identifier_value.native)
        self.assertEqual(None, cert.key_usage_value)
        self.assertEqual(None, cert.subject_alt_name_value)
        self.assertEqual(None, cert.basic_constraints_value)
        self.assertEqual(None, cert.name_constraints_value)
        self.assertEqual(None, cert.crl_distribution_points_value)
        self.assertEqual(None, cert.certificate_policies_value)
        self.assertEqual(None, cert.policy_mappings_value)
        self.assertEqual(b'\xd2\n\xfd.%\xd1\xb7!\xd7P~\xbb\xa4}\xbf4\xefR^\x02', cert.authority_key_identifier_value['key_identifier'].native)
        self.assertEqual(None, cert.policy_constraints_value)
        self.assertEqual(None, cert.extended_key_usage_value)
        self.assertEqual(None, cert.authority_information_access_value)
        self.assertEqual(None, cert.ocsp_no_check_value)

    def test_extensions4(self):
        with open(os.path.join(fixtures_dir, 'geotrust_certs/GeoTrust_Universal_CA.crt'), 'rb') as f:
            cert = x509.Certificate.load(f.read())

        self.assertEqual(['basic_constraints', 'key_usage'], cert.critical_extensions)
        self.assertEqual(b'\xda\xbb.\xaa\xb0\x0c\xb8\x88&Qt\\m\x03\xd3\xc0\xd8\x8fz\xd6', cert.key_identifier_value.native)
        self.assertEqual(
            OrderedDict([
                ('digital_signature', True),
                ('non_repudiation', False),
                ('key_encipherment', False),
                ('data_encipherment', False),
                ('key_agreement', False),
                ('key_cert_sign', True),
                ('crl_sign', True),
                ('encipher_only', False),
                ('decipher_only', False),
            ]),
            cert.key_usage_value.native
        )
        self.assertEqual(None, cert.subject_alt_name_value)
        self.assertEqual(
            OrderedDict([
                ('ca', True),
                ('path_len_constraint', None),
            ]),
            cert.basic_constraints_value.native
        )
        self.assertEqual(None, cert.name_constraints_value)
        self.assertEqual(None, cert.crl_distribution_points_value)
        self.assertEqual(None, cert.certificate_policies_value)
        self.assertEqual(None, cert.policy_mappings_value)
        self.assertEqual(b'\xda\xbb.\xaa\xb0\x0c\xb8\x88&Qt\\m\x03\xd3\xc0\xd8\x8fz\xd6', cert.authority_key_identifier_value['key_identifier'].native)
        self.assertEqual(None, cert.policy_constraints_value)
        self.assertEqual(None, cert.extended_key_usage_value)
        self.assertEqual(None, cert.authority_information_access_value)
        self.assertEqual(None, cert.ocsp_no_check_value)

    def test_extensions5(self):
        with open(os.path.join(fixtures_dir, 'geotrust_certs/GeoTrust_Primary_CA.crt'), 'rb') as f:
            cert = x509.Certificate.load(f.read())

        self.assertEqual(['basic_constraints', 'key_usage'], cert.critical_extensions)
        self.assertEqual(b',\xd5PA\x97\x15\x8b\xf0\x8f6a[J\xfbk\xd9\x99\xc93\x92', cert.key_identifier_value.native)
        self.assertEqual(
            OrderedDict([
                ('digital_signature', True),
                ('non_repudiation', True),
                ('key_encipherment', False),
                ('data_encipherment', False),
                ('key_agreement', False),
                ('key_cert_sign', False),
                ('crl_sign', False),
                ('encipher_only', False),
                ('decipher_only', False),
            ]),
            cert.key_usage_value.native
        )
        self.assertEqual(None, cert.subject_alt_name_value)
        self.assertEqual(True, cert.basic_constraints_value['ca'].native)
        self.assertEqual(None, cert.basic_constraints_value['path_len_constraint'].native)
        self.assertEqual(None, cert.name_constraints_value)
        self.assertEqual(None, cert.crl_distribution_points_value)
        self.assertEqual(None, cert.certificate_policies_value)
        self.assertEqual(None, cert.policy_mappings_value)
        self.assertEqual(None, cert.authority_key_identifier_value)
        self.assertEqual(None, cert.policy_constraints_value)
        self.assertEqual(None, cert.extended_key_usage_value)
        self.assertEqual(None, cert.authority_information_access_value)
        self.assertEqual(None, cert.ocsp_no_check_value)

    def test_extensions6(self):
        with open(os.path.join(fixtures_dir, 'geotrust_certs/GeoTrust_EV_SSL_CA_-_G4.crt'), 'rb') as f:
            cert = x509.Certificate.load(f.read())

        self.assertEqual(['basic_constraints', 'key_usage'], cert.critical_extensions)
        self.assertEqual(b'\xde\xcf\\P\xb7\xae\x02\x1f\x15\x17\xaa\x16\xe8\r\xb5(\x9djZ\xf3', cert.key_identifier_value.native)
        self.assertEqual(
            OrderedDict([
                ('digital_signature', True),
                ('non_repudiation', True),
                ('key_encipherment', False),
                ('data_encipherment', False),
                ('key_agreement', False),
                ('key_cert_sign', False),
                ('crl_sign', False),
                ('encipher_only', False),
                ('decipher_only', False),
            ]),
            cert.key_usage_value.native
        )
        self.assertEqual(
            [
                OrderedDict([
                    ('common_name', 'SymantecPKI-1-538')
                ])
            ],
            cert.subject_alt_name_value.native
        )
        self.assertEqual(True, cert.basic_constraints_value['ca'].native)
        self.assertEqual(0, cert.basic_constraints_value['path_len_constraint'].native)
        self.assertEqual(None, cert.name_constraints_value)
        self.assertEqual(
            [
                OrderedDict([
                    ('distribution_point', ['http://g1.symcb.com/GeoTrustPCA.crl']),
                    ('reasons', None),
                    ('crl_issuer', None)
                ])
            ],
            cert.crl_distribution_points_value.native
        )
        self.assertEqual(
            [
                OrderedDict([
                    ('policy_identifier', 'any_policy'),
                    (
                        'policy_qualifiers',
                        [
                            OrderedDict([
                                ('policy_qualifier_id', 'certification_practice_statement'),
                                ('qualifier', 'https://www.geotrust.com/resources/cps')
                            ])
                        ]
                    )
                ])
            ],
            cert.certificate_policies_value.native
        )
        self.assertEqual(None, cert.policy_mappings_value)
        self.assertEqual(b',\xd5PA\x97\x15\x8b\xf0\x8f6a[J\xfbk\xd9\x99\xc93\x92', cert.authority_key_identifier_value['key_identifier'].native)
        self.assertEqual(None, cert.policy_constraints_value)
        self.assertEqual(None, cert.extended_key_usage_value)
        self.assertEqual(
            [
                OrderedDict([
                    ('access_method', 'ocsp'),
                    ('access_location', 'http://g2.symcb.com')
                ])
            ],
            cert.authority_information_access_value.native
        )
        self.assertEqual(None, cert.ocsp_no_check_value)

    def test_parse_certificate(self):
        with open(os.path.join(fixtures_dir, 'keys/test-der.crt'), 'rb') as f:
            cert = x509.Certificate.load(f.read())

        tbs_certificate = cert['tbs_certificate']
        signature = tbs_certificate['signature']
        issuer = tbs_certificate['issuer']
        validity = tbs_certificate['validity']
        subject = tbs_certificate['subject']
        subject_public_key_info = tbs_certificate['subject_public_key_info']
        subject_public_key_algorithm = subject_public_key_info['algorithm']
        subject_public_key = subject_public_key_info['public_key'].parsed
        extensions = tbs_certificate['extensions']

        self.assertEqual(
            'v3',
            tbs_certificate['version'].native
        )
        self.assertEqual(
            13683582341504654466,
            tbs_certificate['serial_number'].native
        )
        self.assertEqual(
            'sha256_rsa',
            signature['algorithm'].native
        )
        self.assertEqual(
            None,
            signature['parameters'].native
        )
        self.assertEqual(
            OrderedDict([
                ('country_name', 'US'),
                ('state_or_province_name', 'Massachusetts'),
                ('locality_name', 'Newbury'),
                ('organization_name', 'Codex Non Sufficit LC'),
                ('organizational_unit_name', 'Testing'),
                ('common_name', 'Will Bond'),
                ('email_address', 'will@codexns.io'),
            ]),
            issuer.native
        )
        self.assertEqual(
            datetime(2015, 5, 6, 14, 37, 16, tzinfo=core.timezone.utc),
            validity['not_before'].native
        )
        self.assertEqual(
            datetime(2025, 5, 3, 14, 37, 16, tzinfo=core.timezone.utc),
            validity['not_after'].native
        )
        self.assertEqual(
            OrderedDict([
                ('country_name', 'US'),
                ('state_or_province_name', 'Massachusetts'),
                ('locality_name', 'Newbury'),
                ('organization_name', 'Codex Non Sufficit LC'),
                ('organizational_unit_name', 'Testing'),
                ('common_name', 'Will Bond'),
                ('email_address', 'will@codexns.io'),
            ]),
            subject.native
        )
        self.assertEqual(
            'rsa',
            subject_public_key_algorithm['algorithm'].native
        )
        self.assertEqual(
            None,
            subject_public_key_algorithm['parameters'].native
        )
        self.assertEqual(
            23903990516906431865559598284199534387004799030432486061102966678620221767754702651554142956492614440585611990224871381291841413369032752409360196079700921141819811294444393525264295297988924243231844876926173670633422654261873814968313363171188082579071492839040415373948505938897419917635370450127498164824808630475648771544810334682447182123219422360569466851807131368135806769502898151721274383486320505905826683946456552230958810028663378886363555981449715929872558073101554364803925363048965464124465016494920967179276744892632783712377912841537032383450409486298694116013299423220523450956288827030007092359007,
            subject_public_key['modulus'].native
        )
        self.assertEqual(
            65537,
            subject_public_key['public_exponent'].native
        )
        self.assertEqual(
            None,
            tbs_certificate['issuer_unique_id'].native
        )
        self.assertIsInstance(
            tbs_certificate['issuer_unique_id'],
            core.NoValue
        )
        self.assertEqual(
            None,
            tbs_certificate['subject_unique_id'].native
        )
        self.assertIsInstance(
            tbs_certificate['subject_unique_id'],
            core.NoValue
        )

        self.maxDiff = None
        for extension in extensions:
            self.assertIsInstance(
                extension,
                x509.Extension
            )
        self.assertEqual(
            [
                OrderedDict([
                    ('extn_id', 'key_identifier'),
                    ('critical', False),
                    ('extn_value', b'\xBE\x42\x85\x3D\xCC\xFF\xE3\xF9\x28\x02\x8F\x7E\x58\x56\xB4\xFD\x03\x5C\xEA\x4B'),
                ]),
                OrderedDict([
                    ('extn_id', 'authority_key_identifier'),
                    ('critical', False),
                    (
                        'extn_value',
                        OrderedDict([
                            ('key_identifier', b'\xBE\x42\x85\x3D\xCC\xFF\xE3\xF9\x28\x02\x8F\x7E\x58\x56\xB4\xFD\x03\x5C\xEA\x4B'),
                            (
                                'authority_cert_issuer',
                                [
                                    OrderedDict([
                                        ('country_name', 'US'),
                                        ('state_or_province_name', 'Massachusetts'),
                                        ('locality_name', 'Newbury'),
                                        ('organization_name', 'Codex Non Sufficit LC'),
                                        ('organizational_unit_name', 'Testing'),
                                        ('common_name', 'Will Bond'),
                                        ('email_address', 'will@codexns.io'),
                                    ])
                                ]
                            ),
                            ('authority_cert_serial_number', 13683582341504654466),
                        ])
                    ),
                ]),
                OrderedDict([
                    ('extn_id', 'basic_constraints'),
                    ('critical', False),
                    (
                        'extn_value',
                        OrderedDict([
                            ('ca', True),
                            ('path_len_constraint', None)
                        ])
                    ),
                ]),
            ],
            extensions.native
        )

    def test_parse_dsa_certificate(self):
        with open(os.path.join(fixtures_dir, 'keys/test-dsa-der.crt'), 'rb') as f:
            cert = x509.Certificate.load(f.read())

        tbs_certificate = cert['tbs_certificate']
        signature = tbs_certificate['signature']
        issuer = tbs_certificate['issuer']
        validity = tbs_certificate['validity']
        subject = tbs_certificate['subject']
        subject_public_key_info = tbs_certificate['subject_public_key_info']
        subject_public_key_algorithm = subject_public_key_info['algorithm']
        subject_public_key = subject_public_key_info['public_key'].parsed
        extensions = tbs_certificate['extensions']

        self.assertEqual(
            'v3',
            tbs_certificate['version'].native
        )
        self.assertEqual(
            14308214745771946523,
            tbs_certificate['serial_number'].native
        )
        self.assertEqual(
            'sha256_dsa',
            signature['algorithm'].native
        )
        self.assertEqual(
            None,
            signature['parameters'].native
        )
        self.assertEqual(
            OrderedDict([
                ('country_name', 'US'),
                ('state_or_province_name', 'Massachusetts'),
                ('locality_name', 'Newbury'),
                ('organization_name', 'Codex Non Sufficit LC'),
                ('organizational_unit_name', 'Testing'),
                ('common_name', 'Will Bond'),
                ('email_address', 'will@codexns.io'),
            ]),
            issuer.native
        )
        self.assertEqual(
            datetime(2015, 5, 20, 13, 9, 2, tzinfo=core.timezone.utc),
            validity['not_before'].native
        )
        self.assertEqual(
            datetime(2025, 5, 17, 13, 9, 2, tzinfo=core.timezone.utc),
            validity['not_after'].native
        )
        self.assertEqual(
            OrderedDict([
                ('country_name', 'US'),
                ('state_or_province_name', 'Massachusetts'),
                ('locality_name', 'Newbury'),
                ('organization_name', 'Codex Non Sufficit LC'),
                ('organizational_unit_name', 'Testing'),
                ('common_name', 'Will Bond'),
                ('email_address', 'will@codexns.io'),
            ]),
            subject.native
        )
        self.assertEqual(
            'dsa',
            subject_public_key_algorithm['algorithm'].native
        )
        self.assertEqual(
            OrderedDict([
                ('p', 4511743893397705393934377497936985478231822206263141826261443300639402520800626925517264115785551703273809312112372693877437137848393530691841757974971843334497076835630893064661599193178307024379015589119302113551197423138934242435710226975119594589912289060014025377813473273600967729027125618396732574594753039493158066887433778053086408525146692226448554390096911703556213619406958876388642882534250747780313634767409586007581976273681005928967585750017105562145167146445061803488570714706090280814293902464230717946651489964409785146803791743658888866280873858000476717727810363942159874283767926511678640730707887895260274767195555813448140889391762755466967436731106514029224490921857229134393798015954890071206959203407845438863870686180087606429828973298318856683615900474921310376145478859687052812749087809700610549251964102790514588562086548577933609968589710807989944739877028770343142449461177732058649962678857),
                ('q', 71587850165936478337655415373676526523562874562337607790945426056266440596923),
                ('g', 761437146067908309288345767887973163494473925243194806582679580640442238588269326525839153095505341738937595419375068472941615006110237832663093084973431440436421580371384720052414080562019831325744042316268714195397974084616335082272743706567701546951285088540646372701485690904535540223121118329044403681933304838754517522024738251994717369464179515923093116622352823578284891812676662979104509631349201801577889230316128523885862472086364717411346341249139971907827526291913249445756671582283459372536334490171231311487207683108274785825764378203622999309355578169139646003751751448501475767709869676880946562283552431757983801739671783678927397420797147373441051876558068212062253171347849380506793433921881336652424898488378657239798694995315456959568806256079056461448199493507273882763491729787817044805150879660784158902456811649964987582162907020243296662602990514615480712948126671999033658064244112238138589732202),
            ]),
            subject_public_key_algorithm['parameters'].native
        )
        self.assertEqual(
            934231235067929794039535952071098031636053793876274937162425423023735221571983693370780054696865229184537343792766496068557051933738826401423094028670222490622041397241325320965905259541032379046252395145258594355589801644789631904099105867133976990593761395721476198083091062806327384261369876465927159169400428623265291958463077792777155465482611741502621885386691681062128487785344975981628995609792181581218570320181053055516069553767918513262908069925035292416868414952256645902605335068760774106734518308281769128146479819566784704033671969858507248124850451414380441279385481154336362988505436125981975735568289420374790767927084033441728922597082155884801013899630856890463962357814273014111039522903328923758417820349377075487103441305806369234738881875734407495707878637895190993370257589211331043479113328811265005530361001980539377903738453549980082795009589559114091215518866106998956304437954236070776810740036,
            subject_public_key.native
        )
        self.assertEqual(
            None,
            tbs_certificate['issuer_unique_id'].native
        )
        self.assertIsInstance(
            tbs_certificate['issuer_unique_id'],
            core.NoValue
        )
        self.assertEqual(
            None,
            tbs_certificate['subject_unique_id'].native
        )
        self.assertIsInstance(
            tbs_certificate['subject_unique_id'],
            core.NoValue
        )

        self.maxDiff = None
        for extension in extensions:
            self.assertIsInstance(
                extension,
                x509.Extension
            )
        self.assertEqual(
            [
                OrderedDict([
                    ('extn_id', 'key_identifier'),
                    ('critical', False),
                    ('extn_value', b'\x81\xA3\x37\x86\xF9\x99\x28\xF2\x74\x70\x60\x87\xF2\xD3\x7E\x8D\x19\x61\xA8\xBE'),
                ]),
                OrderedDict([
                    ('extn_id', 'authority_key_identifier'),
                    ('critical', False),
                    (
                        'extn_value',
                        OrderedDict([
                            ('key_identifier', b'\x81\xA3\x37\x86\xF9\x99\x28\xF2\x74\x70\x60\x87\xF2\xD3\x7E\x8D\x19\x61\xA8\xBE'),
                            ('authority_cert_issuer', None),
                            ('authority_cert_serial_number', None),
                        ])
                    ),
                ]),
                OrderedDict([
                    ('extn_id', 'basic_constraints'),
                    ('critical', False),
                    (
                        'extn_value',
                        OrderedDict([
                            ('ca', True),
                            ('path_len_constraint', None)
                        ])
                    ),
                ]),
            ],
            extensions.native
        )

    def test_parse_ec_certificate(self):
        with open(os.path.join(fixtures_dir, 'keys/test-ec-der.crt'), 'rb') as f:
            cert = x509.Certificate.load(f.read())

        tbs_certificate = cert['tbs_certificate']
        signature = tbs_certificate['signature']
        issuer = tbs_certificate['issuer']
        validity = tbs_certificate['validity']
        subject = tbs_certificate['subject']
        subject_public_key_info = tbs_certificate['subject_public_key_info']
        subject_public_key_algorithm = subject_public_key_info['algorithm']
        public_key_params = subject_public_key_info['algorithm']['parameters'].chosen
        field_id = public_key_params['field_id']
        curve = public_key_params['curve']
        subject_public_key = subject_public_key_info['public_key'].parsed
        extensions = tbs_certificate['extensions']

        self.assertEqual(
            'v3',
            tbs_certificate['version'].native
        )
        self.assertEqual(
            15854128451240978884,
            tbs_certificate['serial_number'].native
        )
        self.assertEqual(
            'sha256_ecdsa',
            signature['algorithm'].native
        )
        self.assertEqual(
            None,
            signature['parameters'].native
        )
        self.assertEqual(
            OrderedDict([
                ('country_name', 'US'),
                ('state_or_province_name', 'Massachusetts'),
                ('locality_name', 'Newbury'),
                ('organization_name', 'Codex Non Sufficit LC'),
                ('organizational_unit_name', 'Testing'),
                ('common_name', 'Will Bond'),
                ('email_address', 'will@codexns.io'),
            ]),
            issuer.native
        )
        self.assertEqual(
            datetime(2015, 5, 20, 12, 56, 46, tzinfo=core.timezone.utc),
            validity['not_before'].native
        )
        self.assertEqual(
            datetime(2025, 5, 17, 12, 56, 46, tzinfo=core.timezone.utc),
            validity['not_after'].native
        )
        self.assertEqual(
            OrderedDict([
                ('country_name', 'US'),
                ('state_or_province_name', 'Massachusetts'),
                ('locality_name', 'Newbury'),
                ('organization_name', 'Codex Non Sufficit LC'),
                ('organizational_unit_name', 'Testing'),
                ('common_name', 'Will Bond'),
                ('email_address', 'will@codexns.io'),
            ]),
            subject.native
        )
        self.assertEqual(
            'ec',
            subject_public_key_algorithm['algorithm'].native
        )
        self.assertEqual(
            'ecdpVer1',
            public_key_params['version'].native
        )
        self.assertEqual(
            'prime_field',
            field_id['field_type'].native
        )
        self.assertEqual(
            115792089210356248762697446949407573530086143415290314195533631308867097853951,
            field_id['parameters'].native
        )
        self.assertEqual(
            b'\xFF\xFF\xFF\xFF\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC',
            curve['a'].native
        )
        self.assertEqual(
            b'\x5A\xC6\x35\xD8\xAA\x3A\x93\xE7\xB3\xEB\xBD\x55\x76\x98\x86\xBC\x65\x1D\x06\xB0\xCC\x53\xB0\xF6\x3B\xCE\x3C\x3E\x27\xD2\x60\x4B',
            curve['b'].native
        )
        self.assertEqual(
            b'\xC4\x9D\x36\x08\x86\xE7\x04\x93\x6A\x66\x78\xE1\x13\x9D\x26\xB7\x81\x9F\x7E\x90',
            curve['seed'].native
        )
        self.assertEqual(
            b'\x04\x6B\x17\xD1\xF2\xE1\x2C\x42\x47\xF8\xBC\xE6\xE5\x63\xA4\x40\xF2\x77\x03\x7D\x81\x2D\xEB\x33\xA0\xF4\xA1\x39\x45\xD8\x98\xC2\x96\x4F\xE3\x42\xE2\xFE\x1A\x7F\x9B\x8E\xE7\xEB\x4A\x7C\x0F\x9E\x16\x2B\xCE\x33\x57\x6B\x31\x5E\xCE\xCB\xB6\x40\x68\x37\xBF\x51\xF5',
            public_key_params['base'].native
        )
        self.assertEqual(
            115792089210356248762697446949407573529996955224135760342422259061068512044369,
            public_key_params['order'].native
        )
        self.assertEqual(
            1,
            public_key_params['cofactor'].native
        )
        self.assertEqual(
            None,
            public_key_params['hash'].native
        )
        self.assertEqual(
            b'G\x9f\xcbs$\x1d\xc9\xdd\xd1-\xf1:\x9f\xb7\x04\xde \xd0X\x00\x93T\xf6\x89\xc7/\x87+\xf7\xf9=;4\xed\x9e{\x0e=WB\xdfx\x03\x0b\xcc1\xc6\x03\xd7\x9f`\x01',
            subject_public_key.native
        )
        self.assertEqual(
            None,
            tbs_certificate['issuer_unique_id'].native
        )
        self.assertIsInstance(
            tbs_certificate['issuer_unique_id'],
            core.NoValue
        )
        self.assertEqual(
            None,
            tbs_certificate['subject_unique_id'].native
        )
        self.assertIsInstance(
            tbs_certificate['subject_unique_id'],
            core.NoValue
        )

        self.maxDiff = None
        for extension in extensions:
            self.assertIsInstance(
                extension,
                x509.Extension
            )
        self.assertEqual(
            [
                OrderedDict([
                    ('extn_id', 'key_identifier'),
                    ('critical', False),
                    ('extn_value', b'\x54\xAA\x54\x70\x6C\x34\x1A\x6D\xEB\x5D\x97\xD7\x1E\xFC\xD5\x24\x3C\x8A\x0E\xD7'),
                ]),
                OrderedDict([
                    ('extn_id', 'authority_key_identifier'),
                    ('critical', False),
                    (
                        'extn_value',
                        OrderedDict([
                            ('key_identifier', b'\x54\xAA\x54\x70\x6C\x34\x1A\x6D\xEB\x5D\x97\xD7\x1E\xFC\xD5\x24\x3C\x8A\x0E\xD7'),
                            ('authority_cert_issuer', None),
                            ('authority_cert_serial_number', None),
                        ])
                    ),
                ]),
                OrderedDict([
                    ('extn_id', 'basic_constraints'),
                    ('critical', False),
                    (
                        'extn_value',
                        OrderedDict([
                            ('ca', True),
                            ('path_len_constraint', None)
                        ])
                    ),
                ]),
            ],
            extensions.native
        )
