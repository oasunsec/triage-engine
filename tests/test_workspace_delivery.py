"""Browser asset delivery and cache isolation regression coverage."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
import server


class WorkspaceDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(server.app)
        server._reset_security_state_for_tests()

    def tearDown(self):
        self.client.close()

    def test_all_referenced_assets_are_shipped_and_served_with_correct_types(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        for name, mime in [('dashboard.css','text/css'),('workspace.css','text/css'),
                           ('dashboard.js','text/javascript'),('workspace.js','text/javascript'),
                           ('forensics.js','text/javascript')]:
            with self.subTest(asset=name):
                self.assertIn('/assets/'+name, response.text)
                asset = self.client.get('/assets/'+name)
                self.assertEqual(asset.status_code, 200)
                self.assertIn(mime, asset.headers['content-type'])
                self.assertEqual(asset.headers['cache-control'], 'no-cache')
                self.assertGreater(len(asset.content), 100)

    def test_unknown_files_in_static_directory_are_not_exposed(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'private.json').write_text('{"secret":true}')
            with patch.object(server, 'STATIC_DIR', directory):
                self.assertEqual(self.client.get('/assets/private.json').status_code,404)
                self.assertEqual(self.client.get('/assets/dashboard.js').status_code,404)

    def test_success_and_error_responses_have_browser_protection_headers(self):
        for path in ['/', '/api/health', '/api/cases', '/assets/not-found.js']:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.headers['cache-control'], 'no-store')
                self.assertEqual(response.headers['x-content-type-options'], 'nosniff')
                self.assertEqual(response.headers['referrer-policy'], 'no-referrer')
                self.assertEqual(response.headers['x-frame-options'], 'DENY')
                self.assertIn("frame-ancestors 'none'", response.headers['content-security-policy'])
                self.assertTrue(response.headers['x-request-id'])


if __name__ == '__main__':
    unittest.main()
