from __future__ import unicode_literals, division, absolute_import, print_function

import hashlib
import os
import sys

from asn1crypto import cades
from tests import test_cms

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures', 'cades')


class CADESTests(test_cms.CMSTests):
    """Cades RFC 5126 Tests"""

    def test_parse_cades_bes_implicit(self):
        with open(os.path.join(fixtures_dir, 'cades-bes-implicit.der'), 'rb') as f:
            info = cades.ContentInfo.load(f.read())

        self.assertEqual(
            'signed_data',                  # type signed_data
            info['content_type'].native
        )
        content = info['content']
        self.assertEqual(
            'v1',                           # CMS v1
            content['version'].native
        )
        self.assertEqual(                   # This is the signed content
            'Hello world!\n',
            content[u'encap_content_info'].native['content']
        )
        self.assertEqual(
            'sha512',                       # message digest algorithm: SHA512
            content['digest_algorithms'][0]['algorithm'].native
        )
        signer_info = content['signer_infos'][0]
        self.assertEqual(
            'rsassa_pkcs1v15',
            signer_info['signature_algorithm']['algorithm'].native
        )
        # check how signing certicate is specified
        self.assertEqual(
            'issuer_and_serial_number',
            signer_info['sid'].name
        )
        self.assertEqual(
            'AC FNMT Usuarios',
            signer_info['sid'].chosen['issuer'].native['common_name']
        )
        signer_certificate_serial = signer_info['sid'].chosen['serial_number'].native
        self.assertEqual(
            40136907034564109132020389771952983570L,
            signer_certificate_serial
        )
        signature = signer_info['signature'].native
        self.assertEqual(
            'a47bb19e77f531c1c34a4d6e2e59a9341d8066ab',
            hashlib.sha1(signature).hexdigest()
        )
        signed_attrs = signer_info['signed_attrs']
        signed_attrs = {s['type'].native: s['values'] for s in signed_attrs}
        self.assertIn(
            'signing_certificate_v2',
            signed_attrs
        )
        self.assertEqual(
            signer_certificate_serial,
            signed_attrs['signing_certificate_v2'][0]['certs'][0]['issuer_serial']['serial_number'].native
        )
        self.assertIn(
            'message_digest',
            signed_attrs
        )
        # no signature policy
        self.assertNotIn(
            'signature_policy',
            signed_attrs
        )
        self.assertIn(
            'content_hints',
            signed_attrs,
        )
        self.assertEqual(
            'net.sf.jmimemagic.detectors.TextFileDetector',
            signed_attrs['content_hints'][0]['content_description'].native,
        )
        self.assertEqual(
            'data',
            signed_attrs['content_hints'][0]['content_type'].native,
        )
        self.assertIn(
            'content_type',
            signed_attrs
        )
        self.assertIn(
            'signing_time',
            signed_attrs
        )
        self.assertEqual(
            '2017-03-14 22:04:22+00:00',
            str(signed_attrs['signing_time'][0].native)
        )

    def test_parse_cades_epes_explicit(self):
        with open(os.path.join(fixtures_dir, 'cades-epes-explicit.der'), 'rb') as f:
            info = cades.ContentInfo.load(f.read())
        content = info['content']
        self.assertEqual(
            'sha1',
            content['digest_algorithms'][0]['algorithm'].native
        )
        # now we have no content, signature is 'explicit'
        self.assertEqual(
            None,
            content[u'encap_content_info'].native['content']
        )
        signer_info = content['signer_infos'][0]
        signed_attrs = signer_info['signed_attrs']
        signed_attrs = {s['type'].native: s['values'] for s in signed_attrs}
        # now we have signature policy
        self.assertIn(
            'signature_policy',
            signed_attrs
        )
        self.assertEqual(
            'signature_policy_id',
            signed_attrs['signature_policy'][0].name
        )
        self.assertEqual(
            'https://sede.060.gob.es/politica_de_firma_anexo_1.pdf',
            signed_attrs['signature_policy'][0].chosen['sig_policy_qualifiers'][0]['sig_qualifier'].native
        )
