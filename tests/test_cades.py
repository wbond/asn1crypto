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
            'signed_data',
            info['content_type'].native
        )
        content = info['content']
        self.assertEqual(
            'v1',
            content['version'].native
        )
        self.assertEqual(
            'Hello world!\n',
            content[u'encap_content_info'].native['content']
        )
        self.assertEqual(
            'sha512',
            content['digest_algorithms'][0]['algorithm'].native
        )
        signer_info = content['signer_infos'][0]
        self.assertEqual(
            'rsassa_pkcs1v15',
            signer_info['signature_algorithm']['algorithm'].native
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
        self.assertIn(
            'message_digest',
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
        unsigned_attrs = signer_info['unsigned_attrs']
        unsigned_attrs = {s['type'].native: s['values'] for s in unsigned_attrs}
