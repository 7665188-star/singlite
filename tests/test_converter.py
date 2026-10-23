"""Imported subscriptions stay private, persistent and separate from local nodes."""
import base64
import json
from pathlib import Path
import sys
import tempfile
import unittest
from urllib.parse import quote, urlencode

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server'))
import control
import converter
import panel


def ss_link(method='2022-blake3-aes-128-gcm', name='HK', host='192.0.2.8', port=8388,
            dual=True, encoded=False):
    size = control.METHODS[method]
    password = base64.b64encode(b's' * size).decode()
    if dual:
        password += ':' + base64.b64encode(b'u' * size).decode()
    user = method + ':' + password
    if encoded:
        user = base64.urlsafe_b64encode(user.encode()).decode().rstrip('=')
    else:
        user = quote(method, safe='') + ':' + quote(password, safe='')
    return f'ss://{user}@{host}:{port}#{quote(name, safe="")}'


def vless_link(**changes):
    params = {'security': 'reality', 'encryption': 'none', 'type': 'tcp',
              'sni': 'www.amd.com', 'fp': 'firefox', 'flow': 'xtls-rprx-vision',
              'pbk': base64.urlsafe_b64encode(b'p' * 32).decode().rstrip('='),
              'sid': 'AA1122', 'alpn': 'h2,http/1.1'}
    params.update(changes)
    return 'vless://198ad191-8549-4f99-9f25-5d3a65a334a2@[2001:db8::8]:443?' + urlencode(params) + '#vmiss'


def proxies_in_yaml(value):
    return [json.loads(line[4:]) for line in value.splitlines()
            if line.startswith('  - {') and '"server"' in line]


class ParserTests(unittest.TestCase):
    def test_yaml_uses_mihomo_supported_warning_level(self):
        content = control.clash_yaml(converter.parse_source(ss_link()))
        self.assertIn('\nlog-level: warning\n', content)
        self.assertNotIn('\nlog-level: warn\n', content)

    def bad(self, source, message=None):
        with self.assertRaises(control.ControlError) as caught:
            converter.parse_source(source)
        self.assertEqual(caught.exception.status, 400)
        if message:
            self.assertIn(message, caught.exception.message)
        return caught.exception.message

    def test_ss2022_key_sizes_single_and_dual_and_encoded_userinfo(self):
        for method in control.METHODS:
            for dual in (False, True):
                for encoded in (False, True):
                    with self.subTest(method=method, dual=dual, encoded=encoded):
                        proxy = converter.parse_source(ss_link(method, dual=dual, encoded=encoded))[0]
                        self.assertEqual(proxy['cipher'], method)
                        keys = proxy['password'].split(':')
                        self.assertEqual(len(keys), 2 if dual else 1)
                        self.assertTrue(all(len(base64.b64decode(key)) == control.METHODS[method] for key in keys))
                        self.assertEqual(converter.parse_source(control.proxy_uri(proxy)), [proxy])

    def test_unicode_names_ipv6_domain_percent_encoding_and_base64_input(self):
        first = ss_link(name='香港 · <HK> "Proxy"', host='[2001:db8::7]', encoded=True)
        second = ss_link(name='HK-2', host='relay.example.com', dual=False)
        source = first + '\r\n\r\n' + second
        proxies = converter.parse_source(source)
        self.assertEqual(proxies[0]['name'], '香港 · <HK> "Proxy"')
        self.assertEqual(proxies[0]['server'], '2001:db8::7')
        self.assertEqual(proxies[1]['server'], 'relay.example.com')
        encoded = base64.b64encode(source.encode()).decode().rstrip('=')
        wrapped = '\n'.join(encoded[index:index + 72] for index in range(0, len(encoded), 72))
        self.assertEqual(converter.parse_source(wrapped), proxies)
        self.assertEqual(proxies_in_yaml(control.clash_yaml(proxies)), proxies)

    def test_reality_preserves_credentials_fingerprint_flow_and_alpn(self):
        proxy = converter.parse_source(vless_link())[0]
        self.assertEqual(proxy['server'], '2001:db8::8')
        self.assertEqual(proxy['port'], 443)
        self.assertEqual(proxy['client-fingerprint'], 'firefox')
        self.assertEqual(proxy['flow'], 'xtls-rprx-vision')
        self.assertEqual(proxy['alpn'], ['h2', 'http/1.1'])
        self.assertEqual(proxy['reality-opts']['short-id'], 'aa1122')
        self.assertEqual(converter.parse_source(control.proxy_uri(proxy)), [proxy])
        plain = converter.parse_source(vless_link(type='raw', flow='', fp='chrome', sid=''))[0]
        self.assertNotIn('flow', plain)
        self.assertEqual(plain['network'], 'tcp')
        self.assertEqual(converter.parse_source(control.proxy_uri(plain)), [plain])

    def test_names_and_input_limits(self):
        self.bad(ss_link() + '\n' + ss_link(), '节点名称重复')
        self.bad(ss_link(name='DIRECT'), '保留名称')
        self.bad(ss_link(name='a' * 129), '节点名称')
        self.bad('a' * (converter.MAX_SOURCE + 1), '256 KiB')
        self.bad('\n'.join(ss_link(name=str(index)) for index in range(129)), '128')
        unnamed = ss_link(name='') + '\n' + vless_link().split('#')[0]
        self.assertEqual([p['name'] for p in converter.parse_source(unnamed)], ['节点 1', '节点 2'])

    def test_bad_input_and_errors_do_not_echo_secrets_or_raise_internal_errors(self):
        secret = 'sensitive-token-DO-NOT-ECHO'
        bad_inputs = [None, {}, [], '', 'https://example.com/' + secret,
                      'ss://bad@192.0.2.8:0#HK', 'ss://bad@192.0.2.8:65536#HK',
                      'ss://bad@192.0.2.8:abc#HK', 'ss://bad@[broken:1#HK',
                      'ss://bad@192.0.2.8#HK', 'ss://bad@192.0.2.8:1/path#HK',
                      ss_link() + '%ZZ', ss_link(name='bad\nname'),
                      ss_link().replace(':8388#', ':8388?plugin=' + secret + '#'),
                      ss_link().replace('2022-blake3-aes-128-gcm', 'aes-128-gcm'),
                      ss_link().replace(quote(base64.b64encode(b's' * 16).decode(), safe=''), secret),
                      vless_link(security='tls'), vless_link(type='ws'),
                      vless_link(headerType='http'), vless_link(encryption='auto'),
                      vless_link(flow='unsupported'), vless_link(pbk='bad'),
                      vless_link(sid='abc'), vless_link(sid='zz'), vless_link(sni=''),
                      vless_link(alpn='h2,'), vless_link(fp=''), vless_link(spx='/'),
                      vless_link(unknown=secret),
                      vless_link().replace('security=reality', 'security=reality&security=reality'),
                      vless_link().replace('198ad191-8549-4f99-9f25-5d3a65a334a2', secret),
                      '!!!!', 'YQ', '\ud800']
        for source in bad_inputs:
            with self.subTest(source=repr(source)[:100]):
                message = self.bad(source)
                self.assertNotIn(secret, message)
        message = self.bad(ss_link(name='valid') + '\n' + vless_link(type='ws'))
        self.assertTrue(message.startswith('第 2 行：'))


class ConversionStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.control = control.Controller(self.tmp.name, panel.hostname, '192.0.2.4')
        self.addCleanup(self.control.db.close)
        self.converter = converter.Converter(self.control)

    def create(self, **changes):
        payload = {'name': 'HK 手工节点', 'source': ss_link() + '\n' + vless_link()}
        payload.update(changes)
        return self.converter.api('POST', '/api/conversions', payload)

    def test_saved_source_detail_safe_summaries_and_separation_from_core_state(self):
        before_bundle, before_state = self.control.bundle(), self.control.state()
        item = self.create()
        identifier = item['conversion']['id']
        self.assertEqual(set(item['paths']), {'clash'})
        self.assertEqual(item['conversion']['nodeCount'], 2)
        self.assertIn('source', item['conversion'])
        self.assertEqual(self.converter.api('GET', '/api/conversions/' + identifier, {}), item)
        summaries = self.converter.summaries()
        self.assertEqual(set(summaries[0]), set(converter.SUMMARY_KEYS))
        for forbidden in ('source', 'token', 'password', 'uuid', 'pbk', 'paths'):
            self.assertNotIn('"' + forbidden + '"', json.dumps(summaries))
        self.assertEqual(self.converter.api('GET', '/api/conversions', {}), {'conversions': summaries})
        self.assertEqual(self.control.bundle(), before_bundle)
        self.assertEqual(self.control.state(), before_state)
        token = item['paths']['clash'].split('/')[2]
        content = self.converter.subscription(token, 'clash.yaml')
        self.assertEqual(len(proxies_in_yaml(content)), 2)
        self.assertIn('Singlite · Proxy', content)
        self.assertNotIn('Subscription-Userinfo', content)

    def test_restart_edit_token_rotation_and_deletion(self):
        created = self.create()
        path = '/api/conversions/' + created['conversion']['id']
        token = created['paths']['clash'].split('/')[2]
        another = control.Controller(self.tmp.name, panel.hostname)
        try:
            reopened = converter.Converter(another)
            self.assertEqual(reopened.api('GET', path, {}), created)
            edited = reopened.api('PUT', path, {'name': 'New name'})
            self.assertEqual(edited['paths'], created['paths'])
            self.assertEqual(edited['conversion']['source'], created['conversion']['source'])
            edited = reopened.api('PUT', path, {'source': ss_link(name='Only')})
            self.assertEqual(edited['conversion']['nodeCount'], 1)
            self.assertEqual(edited['paths'], created['paths'])
            rotated = reopened.api('POST', path + '/rotate-token', {})
            new_token = rotated['paths']['clash'].split('/')[2]
            self.assertNotEqual(new_token, token)
            with self.assertRaises(control.ControlError) as caught:
                reopened.subscription(token, 'clash.yaml')
            self.assertEqual(caught.exception.status, 404)
            self.assertEqual(len(proxies_in_yaml(reopened.subscription(new_token, 'clash.yaml'))), 1)
            self.assertEqual(reopened.api('DELETE', path, {}), {'ok': True})
            self.assertEqual(reopened.summaries(), [])
            with self.assertRaises(control.ControlError):
                reopened.subscription(new_token, 'clash.yaml')
        finally:
            another.db.close()

    def test_failed_update_is_atomic_and_invalid_payloads_are_client_errors(self):
        created = self.create()
        path = '/api/conversions/' + created['conversion']['id']
        for method, endpoint, payload in [
            ('POST', '/api/conversions', None),
            ('POST', '/api/conversions', {'name': 'No source'}),
            ('POST', '/api/conversions', {'name': [], 'source': ss_link()}),
            ('POST', '/api/conversions', {'name': '\ud800', 'source': ss_link()}),
            ('PUT', path, {'source': vless_link(type='ws')}),
            ('PUT', path, {'extra': True}),
            ('POST', path + '/rotate-token', {'extra': True}),
        ]:
            with self.subTest(method=method, endpoint=endpoint):
                with self.assertRaises(control.ControlError) as caught:
                    self.converter.api(method, endpoint, payload)
                self.assertEqual(caught.exception.status, 400)
        self.assertEqual(self.converter.api('GET', path, {}), created)
        for method, endpoint in [('PATCH', path), ('GET', path + '/rotate-token'),
                                  ('GET', '/api/conversions/not-an-id')]:
            with self.assertRaises(control.ControlError) as caught:
                self.converter.api(method, endpoint, {})
            self.assertEqual(caught.exception.status, 404)
        for token, format in [('bad', 'clash.yaml'), ('x' * 43, 'clash.yaml'),
                              (created['paths']['clash'].split('/')[2], 'base64.txt')]:
            with self.assertRaises(control.ControlError) as caught:
                self.converter.subscription(token, format)
            self.assertEqual(caught.exception.status, 404)

    def test_record_limit(self):
        for index in range(converter.MAX_CONVERSIONS):
            self.create(name=str(index), source=ss_link())
        with self.assertRaises(control.ControlError) as caught:
            self.create()
        self.assertEqual(caught.exception.status, 400)
        self.assertEqual(len(self.converter.summaries()), converter.MAX_CONVERSIONS)


if __name__ == '__main__':
    unittest.main()
