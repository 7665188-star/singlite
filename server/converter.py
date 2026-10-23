"""Local-only link conversion; imported nodes never enter the managed core."""
from __future__ import annotations
import base64
import binascii
import ipaddress
import json
import re
import secrets
import time
from urllib.parse import parse_qsl, unquote, urlsplit
import uuid

from control import ControlError, METHODS, clash_yaml, digest, encode, new_id, proxy_uri, text

MAX_SOURCE = 256 * 1024
MAX_NODES = 128
MAX_CONVERSIONS = 64
SUMMARY_KEYS = ('id', 'name', 'nodeCount', 'createdAt', 'updatedAt')


def _bad(message):
    raise ControlError(400, message)


def _decode(value, field):
    if re.search(r'%(?![0-9a-fA-F]{2})', value):
        _bad(field + '的 URL 编码无效')
    try:
        decoded = unquote(value, encoding='utf-8', errors='strict')
        decoded.encode('utf-8')
    except UnicodeError:
        _bad(field + '的文字编码无效')
    if any(ord(char) < 32 or ord(char) == 127 for char in decoded):
        _bad(field + '包含控制字符')
    return decoded


def _base64(value, field):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9+/_-]*={0,2}', value):
        _bad(field + '的 Base64 编码无效')
    try:
        return base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
    except (ValueError, binascii.Error):
        _bad(field + '的 Base64 编码无效')


def _host(value, field, allow_ip=True):
    if not isinstance(value, str) or not value or '%' in value:
        _bad(field + '格式无效')
    value = value.rstrip('.')
    try:
        result = str(ipaddress.ip_address(value))
    except ValueError:
        try:
            result = value.encode('idna').decode('ascii').lower()
        except UnicodeError:
            _bad(field + '格式无效')
        if len(result) > 253 or not re.fullmatch(
            r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*'
            r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', result
        ):
            _bad(field + '请填写 IP 或域名，不含路径')
        return result
    if not allow_ip:
        _bad(field + '请填写域名')
    return result


def _params(query, allowed):
    _decode(query, '参数')
    try:
        pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True,
                          encoding='utf-8', errors='strict', max_num_fields=32)
    except (ValueError, UnicodeError):
        _bad('链接参数格式无效')
    result = {}
    for key, value in pairs:
        if key not in allowed:
            _bad('链接含有不支持的参数，请使用 TCP Reality 或无插件的 SS2022 链接')
        if key in result:
            _bad('链接包含重复参数')
        result[key] = value
    return result


def _parse_link(line, index):
    if any(ord(char) < 33 or ord(char) == 127 for char in line):
        _bad('链接包含空格或控制字符，请使用 URL 编码')
    try:
        url = urlsplit(line)
        server, port = url.hostname, url.port
    except (ValueError, UnicodeError):
        _bad('链接地址或端口格式无效')
    if url.scheme not in ('ss', 'vless'):
        _bad('只支持 SS2022 或 VLESS Reality 节点链接，不支持远程订阅网址')
    if url.path not in ('', '/') or '@' not in url.netloc:
        _bad('节点链接格式无效')
    if port is None or not 1 <= port <= 65535:
        _bad('端口必须为 1–65535')
    server = _host(server, '节点地址')
    name = text(_decode(url.fragment, '节点名称') or f'节点 {index}', '节点名称', 128)
    userinfo = _decode(url.netloc.rsplit('@', 1)[0], '节点凭据')
    common = {'name': name, 'server': server, 'port': port, 'udp': True}
    if url.scheme == 'ss':
        _params(url.query, set())
        if ':' not in userinfo:
            try:
                userinfo = _base64(userinfo, '节点凭据').decode('utf-8')
            except UnicodeError:
                _bad('节点凭据的文字编码无效')
        if ':' not in userinfo:
            _bad('SS2022 凭据应包含加密方式和密钥')
        method, password = userinfo.split(':', 1)
        if method not in METHODS:
            _bad('只支持 SS2022 AES-128 或 AES-256')
        keys = password.split(':')
        if not 1 <= len(keys) <= 2:
            _bad('SS2022 仅支持单密钥或服务端密钥:用户密钥')
        normalized = []
        for key in keys:
            decoded = _base64(key, 'SS2022 密钥')
            if len(decoded) != METHODS[method]:
                _bad('SS2022 密钥长度与加密方式不符')
            normalized.append(base64.b64encode(decoded).decode('ascii'))
        return common | {'type': 'ss', 'cipher': method, 'password': ':'.join(normalized)}

    params = _params(url.query, {'encryption', 'security', 'type', 'sni', 'fp', 'pbk',
                                 'sid', 'flow', 'alpn', 'headerType', 'spx'})
    if params.get('security') != 'reality':
        _bad('VLESS 只支持 Reality 安全模式')
    if params.get('type', 'tcp') not in ('tcp', 'raw') or params.get('headerType', 'none') != 'none':
        _bad('VLESS 只支持无伪装头的 TCP 传输')
    if params.get('encryption', 'none') != 'none':
        _bad('VLESS encryption 必须为 none')
    if params.get('spx'):
        _bad('Mihomo 转换不支持 spx 参数，请移除该参数后重试')
    try:
        identity = str(uuid.UUID(userinfo))
    except (ValueError, AttributeError):
        _bad('VLESS UUID 格式无效')
    key = _base64(params.get('pbk', ''), 'Reality 公钥')
    if len(key) != 32:
        _bad('Reality 公钥必须为 32 字节')
    short_id = params.get('sid', '')
    if not re.fullmatch(r'(?:[0-9a-fA-F]{2}){0,8}', short_id):
        _bad('Reality short ID 必须为最多 16 位的偶数位十六进制字符')
    fingerprint = params.get('fp', 'chrome')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,32}', fingerprint):
        _bad('客户端指纹格式无效')
    flow = params.get('flow', '')
    if flow not in ('', 'xtls-rprx-vision'):
        _bad('VLESS 只支持空 flow 或 xtls-rprx-vision')
    proxy = common | {'type': 'vless', 'uuid': identity, 'network': 'tcp', 'tls': True,
                      'servername': _host(params.get('sni', ''), 'Reality SNI', False),
                      'client-fingerprint': fingerprint,
                      'reality-opts': {'public-key': base64.urlsafe_b64encode(key).decode('ascii').rstrip('='),
                                       'short-id': short_id.lower()}}
    if flow:
        proxy['flow'] = flow
    if 'alpn' in params:
        protocols = params['alpn'].split(',')
        if len(protocols) > 16 or not all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9./_-]{0,31}', item) for item in protocols):
            _bad('ALPN 格式无效')
        proxy['alpn'] = list(dict.fromkeys(protocols))
    return proxy


def parse_source(value):
    """Parse pasted links without network access; errors never echo credentials."""
    if not isinstance(value, str):
        _bad('节点链接必须为文本')
    try:
        size = len(value.encode('utf-8'))
    except UnicodeError:
        _bad('节点链接的文字编码无效')
    if size > MAX_SOURCE:
        _bad('节点链接最多 256 KiB')
    source = value.strip()
    if not source:
        _bad('请粘贴至少一个节点链接')
    if '://' not in source:
        try:
            source = _base64(''.join(source.split()), '订阅内容').decode('utf-8')
        except UnicodeError:
            _bad('订阅内容的文字编码无效')
    proxies = []
    for line_number, raw in enumerate(source.replace('\r\n', '\n').replace('\r', '\n').split('\n'), 1):
        line = raw.strip(' ')
        if not line:
            continue
        if len(proxies) >= MAX_NODES:
            _bad('每组最多 128 个节点')
        try:
            proxies.append(_parse_link(line, len(proxies) + 1))
        except ControlError as error:
            raise ControlError(400, f'第 {line_number} 行：{error.message}') from None
    if not proxies:
        _bad('请粘贴至少一个节点链接')
    try:
        clash_yaml(proxies)
    except ControlError:
        _bad('节点名称重复或使用了客户端保留名称，请修改节点名称')
    return proxies


class Converter:
    def __init__(self, control):
        self.control = control
        self.lock, self.db = control.lock, control.db
        with self.lock, self.db:
            self.db.execute('CREATE TABLE IF NOT EXISTS converted_subscriptions('
                            'id TEXT PRIMARY KEY, data TEXT NOT NULL, token_hash TEXT UNIQUE NOT NULL)')

    def summaries(self):
        with self.lock:
            return [{key: item[key] for key in SUMMARY_KEYS}
                    for (value,) in self.db.execute('SELECT data FROM converted_subscriptions ORDER BY rowid')
                    for item in [json.loads(value)]]

    def _get(self, identifier):
        if not re.fullmatch(r'[a-f0-9]{32}', identifier):
            raise ControlError(400, '记录标识格式无效')
        row = self.db.execute('SELECT data FROM converted_subscriptions WHERE id=?', (identifier,)).fetchone()
        if not row:
            raise ControlError(404, '转换记录不存在')
        return json.loads(row[0])

    @staticmethod
    def _detail(item):
        return {'conversion': {key: item[key] for key in SUMMARY_KEYS + ('source',)},
                'paths': {'clash': '/convert/' + item['token'] + '/clash.yaml'}}

    def _put(self, item):
        self.db.execute('INSERT INTO converted_subscriptions(id,data,token_hash) VALUES(?,?,?) '
                        'ON CONFLICT(id) DO UPDATE SET data=excluded.data,token_hash=excluded.token_hash',
                        (item['id'], encode(item), digest(item['token'])))

    def api(self, method, path, payload):
        if path == '/api/conversions' and method == 'GET':
            return {'conversions': self.summaries()}
        match = re.fullmatch(r'/api/conversions(?:/([a-f0-9]{32})(/rotate-token)?)?', path)
        if not match:
            raise ControlError(404, '接口不存在')
        identifier, rotate = match.groups()
        if not isinstance(payload, dict):
            _bad('请求内容必须是对象')
        if not identifier and method == 'POST':
            with self.lock, self.db:
                if self.db.execute('SELECT COUNT(*) FROM converted_subscriptions').fetchone()[0] >= MAX_CONVERSIONS:
                    _bad('最多保存 64 组转换记录')
                return self._save(payload)
        if identifier and not rotate:
            with self.lock, self.db:
                item = self._get(identifier)
                if method == 'GET':
                    return self._detail(item)
                if method == 'PUT':
                    return self._save(payload, item)
                if method == 'DELETE':
                    self.db.execute('DELETE FROM converted_subscriptions WHERE id=?', (identifier,))
                    return {'ok': True}
        if identifier and rotate and method == 'POST':
            if payload:
                _bad('重置订阅地址不接受额外字段')
            with self.lock, self.db:
                item = self._get(identifier)
                item.update(token=secrets.token_urlsafe(32), updatedAt=int(time.time()))
                self._put(item)
                return self._detail(item)
        raise ControlError(404, '接口不存在')

    def _save(self, payload, old=None):
        if set(payload) - {'name', 'source'}:
            _bad('转换记录包含不支持的字段')
        item = dict(old or {})
        item['name'] = text(payload.get('name', item.get('name')), '转换名称')
        if 'source' in payload or not old:
            proxies = parse_source(payload.get('source'))
            item.update(source='\n'.join(proxy_uri(proxy) for proxy in proxies), nodeCount=len(proxies))
        now = int(time.time())
        if not old:
            item.update(id=new_id(), token=secrets.token_urlsafe(32), createdAt=now)
        item['updatedAt'] = now
        self._put(item)
        return self._detail(item)

    def subscription(self, token, format):
        if format != 'clash.yaml' or not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', token):
            raise ControlError(404, '订阅不存在或已失效')
        with self.lock:
            row = self.db.execute('SELECT data FROM converted_subscriptions WHERE token_hash=?', (digest(token),)).fetchone()
            if not row:
                raise ControlError(404, '订阅不存在或已失效')
            return clash_yaml(parse_source(json.loads(row[0])['source']))
