"""Conversion authentication, public subscription and managed-core isolation."""
import base64
from http.client import HTTPConnection
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
from urllib.parse import quote, unquote

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server'))
import core
import panel


class ConverterHttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.app = panel.Panel(self.tmp.name, runner=lambda args, **kw:
                               subprocess.CompletedProcess(args, 0, 'sing-box version 1.14.3-singlite', ''))
        self.app.init_admin('admin', '123456')
        self.cookie, self.csrf = '', ''
        self.server = panel.PanelServer(('127.0.0.1', 0), self.app)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close)
        key = base64.b64encode(b'k' * 16).decode()
        self.source = 'ss://2022-blake3-aes-128-gcm:' + quote(key, safe='') + '@192.0.2.8:8388#HK'

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.app.close()

    def request(self, method, path, payload=None, extra=None):
        connection = HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        headers = {'Cookie': self.cookie, 'X-CSRF-Token': self.csrf,
                   'Content-Type': 'application/json', **(extra or {})}
        connection.request(method, path, json.dumps(payload) if payload is not None else None, headers)
        result = connection.getresponse()
        body = result.read()
        response = (result.status, dict(result.getheaders()), body)
        connection.close()
        return response

    def login(self):
        code, headers, body = self.request('POST', '/api/login', {'username': 'admin', 'password': '123456'})
        self.assertEqual(code, 200)
        self.cookie = headers['Set-Cookie'].split(';')[0]
        self.csrf = json.loads(body)['csrf']

    def create(self):
        code, _, body = self.request('POST', '/api/conversions', {'name': 'HK 手工节点', 'source': self.source})
        self.assertEqual(code, 200, body)
        return json.loads(body)

    def test_management_requires_login_csrf_and_same_origin(self):
        self.assertEqual(self.request('GET', '/api/conversions')[0], 401)
        self.assertEqual(self.request('POST', '/api/conversions', {})[0], 401)
        self.login()
        self.assertEqual(self.request('POST', '/api/conversions', {}, {'X-CSRF-Token': ''})[0], 403)
        self.assertEqual(self.request('POST', '/api/conversions', {}, {'Origin': 'https://other.example'})[0], 403)
        created = self.create()
        path = '/api/conversions/' + created['conversion']['id']
        cookie, self.cookie = self.cookie, ''
        for method in ('GET', 'PUT', 'DELETE'):
            self.assertEqual(self.request(method, path, {} if method != 'GET' else None)[0], 401)
        self.cookie = cookie
        self.assertEqual(self.request('DELETE', path, {}, {'X-CSRF-Token': ''})[0], 403)
        code, _, body = self.request('GET', path)
        self.assertEqual(code, 200)
        self.assertIn('source', json.loads(body)['conversion'])

    def test_mihomo_get_head_fixed_title_no_usage_and_no_runtime_mutation(self):
        self.login()
        before = core.render_singbox(self.app.control.bundle())
        self.app.runtime.wake.clear()
        with mock.patch.object(self.app.runtime, 'collect') as collect:
            created = self.create()
            collect.assert_not_called()
        self.assertFalse(self.app.runtime.wake.is_set())
        code, _, body = self.request('GET', '/api/state')
        state = json.loads(body)
        self.assertEqual(code, 200)
        self.assertEqual((state['nodes'], state['users']), ([], []))
        self.assertEqual(len(state['conversions']), 1)
        for secret in ('source', 'token', 'password', 'paths'):
            self.assertNotIn(secret, state['conversions'][0])
        self.assertEqual(core.render_singbox(self.app.control.bundle()), before)
        self.app.control.running(False)
        self.cookie = ''
        for method in ('GET', 'HEAD'):
            code, headers, body = self.request(method, created['paths']['clash'])
            self.assertEqual(code, 200)
            self.assertEqual(headers['Cache-Control'], 'no-store')
            self.assertEqual(headers['Content-Type'], 'text/yaml; charset=utf-8')
            self.assertEqual(base64.b64decode(headers['Profile-Title'][7:]).decode(), 'Singlite · Proxy')
            self.assertEqual(unquote(headers['Content-Disposition'].split("filename*=UTF-8''")[1]), 'Singlite · Proxy.yaml')
            self.assertNotIn('Subscription-Userinfo', headers)
            if method == 'GET':
                self.assertIn(b'"server": "192.0.2.8"', body)
                self.assertIn(b'"name": "HK"', body)
            else:
                self.assertEqual(body, b'')
                self.assertGreater(int(headers['Content-Length']), 0)

    def test_edit_rotate_delete_and_invalid_public_paths(self):
        self.login()
        created = self.create()
        path, old_url = '/api/conversions/' + created['conversion']['id'], created['paths']['clash']
        source = self.source.replace('192.0.2.8:8388', 'relay.example.com:443')
        code, _, body = self.request('PUT', path, {'source': source})
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)['paths']['clash'], old_url)
        self.assertIn(b'"server": "relay.example.com"', self.request('GET', old_url)[2])
        self.assertIn(b'"port": 443', self.request('GET', old_url)[2])
        code, _, body = self.request('POST', path + '/rotate-token', {})
        self.assertEqual(code, 200)
        url = json.loads(body)['paths']['clash']
        self.assertNotEqual(url, old_url)
        self.assertEqual(self.request('GET', old_url)[0], 404)
        self.assertEqual(self.request('GET', url)[0], 200)
        for invalid in (url.replace('clash.yaml', 'base64.txt'), url.replace('clash.yaml', 'clashXyaml'), url + '/extra', '/convert/bad/clash.yaml', '/convert/' + 'x' * 43 + '/clash.yaml'):
            self.assertEqual(self.request('GET', invalid)[0], 404)
        self.assertEqual(self.request('DELETE', path, {})[0], 200)
        self.assertEqual(self.request('GET', url)[0], 404)
        self.assertEqual(json.loads(self.request('GET', '/api/conversions')[2]), {'conversions': []})

    def test_bad_input_is_rejected_without_exposing_credentials(self):
        self.login()
        secret = 'DO-NOT-ECHO-THIS-SECRET'
        for payload in ({'name': 'bad', 'source': 'https://example.com/' + secret},
                        {'name': 'bad', 'source': self.source + '%ZZ'},
                        {'name': '\ud800', 'source': self.source},
                        {'name': 'bad', 'source': []}):
            code, _, body = self.request('POST', '/api/conversions', payload)
            self.assertEqual(code, 400, body)
            self.assertNotIn(secret.encode(), body)
        self.assertEqual(self.app.conversions.summaries(), [])


if __name__ == '__main__':
    unittest.main()
