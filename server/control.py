"""Single-machine users, nodes and transactional bidirectional accounting."""
from __future__ import annotations
import base64
import calendar
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import threading
import time
from urllib.parse import quote, urlencode
import uuid
from zoneinfo import ZoneInfo

GB = 1_000_000_000
SUBSCRIPTION_TITLE = 'Singlite · Proxy'
TZ = ZoneInfo('Asia/Shanghai')
METHODS = {'2022-blake3-aes-128-gcm': 16, '2022-blake3-aes-256-gcm': 32}

class ControlError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message
        super().__init__(message)

def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), sort_keys=True)

def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()

def new_id():
    return uuid.uuid4().hex

def text(value, field, limit=64, optional=False):
    if not isinstance(value, str) or len(value.strip()) > limit or (not optional and not value.strip()) or any(ord(c) < 32 or ord(c)==127 for c in value):
        raise ControlError(400, f'{field}格式无效，最多 {limit} 个字符')
    try:value.encode('utf-8')
    except UnicodeError:raise ControlError(400,f'{field}文字编码无效') from None
    return value.strip()

def boolean(value, field):
    if not isinstance(value, bool):
        raise ControlError(400, f'{field}必须为布尔值')
    return value

def integer(value, field, lower=0, upper=2**53-1):
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        raise ControlError(400, f'{field}必须为 {lower}–{upper} 的整数')
    return value

def reality_keys():
    # Use the system cryptographic library, never a handwritten curve implementation.
    try:
        private = subprocess.run(['openssl', 'genpkey', '-algorithm', 'X25519', '-outform', 'DER'], capture_output=True, check=True, timeout=10).stdout
        public = subprocess.run(['openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER'], input=private, capture_output=True, check=True, timeout=10).stdout
        if len(private) != 48 or len(public) != 44:
            raise ValueError('Unexpected X25519 encoding')
        b64 = lambda data: base64.urlsafe_b64encode(data[-32:]).decode().rstrip('=')
        return b64(private), b64(public)
    except (OSError, subprocess.SubprocessError, ValueError):
        raise ControlError(503, '无法生成 Reality 密钥，请安装 OpenSSL 并检查 X25519 支持') from None

def next_reset(now, day):
    local = datetime.fromtimestamp(now, TZ)
    def stamp(year, month):
        return int(datetime(year, month, min(day, calendar.monthrange(year, month)[1]), tzinfo=TZ).timestamp())
    due = stamp(local.year, local.month)
    if due <= now:
        year, month = (local.year+1, 1) if local.month == 12 else (local.year, local.month+1)
        due = stamp(year, month)
    return due

def user_reason(user, now=None):
    now = time.time() if now is None else now
    if not user['enabled']: return 'disabled'
    if user.get('expiresAt') and user['expiresAt'] <= now: return 'expired'
    if user['quotaBytes'] and user['uploadBytes'] + user['downloadBytes'] >= user['quotaBytes']: return 'quota'
    return 'active'

def user_public(user):
    keys = ('id','name','note','enabled','quotaBytes','uploadBytes','downloadBytes','expiresAt','resetDay','cycle','nextResetAt','nodeIds','createdAt')
    result = {k:user.get(k) for k in keys}
    result.update(status=user_reason(user), usedBytes=user['uploadBytes']+user['downloadBytes'])
    return result

def node_public(node):
    return {k:node.get(k) for k in ('id','name','protocol','port','enabled','sni','method','connectHost','connectPort','createdAt')}

def client_proxy(node, user, host, name):
    host, port = node.get('connectHost') or host, node.get('connectPort') or node['port']
    if node['protocol'] == 'vless':
        return {'name':name,'type':'vless','server':host,'port':port,'uuid':user['uuid'],'network':'tcp','tls':True,'udp':True,'servername':node['sni'],'flow':'xtls-rprx-vision','client-fingerprint':'chrome','reality-opts':{'public-key':node['publicKey'],'short-id':node['shortId']}}
    psk = user['psk128'] if node['method'] == '2022-blake3-aes-128-gcm' else user['psk256']
    return {'name':name,'type':'ss','server':host,'port':port,'cipher':node['method'],'password':node['serverKey']+':'+psk,'udp':True}

def proxy_uri(proxy):
    host = '['+proxy['server']+']' if ':' in proxy['server'] else proxy['server']
    address = f"{host}:{proxy['port']}"
    tag = quote(proxy['name'], safe='')
    if proxy['type']=='ss':
        return f"ss://{quote(proxy['cipher'],safe='')}:{quote(proxy['password'],safe='')}@{address}#{tag}"
    params = {'encryption':'none','security':'reality','sni':proxy['servername'],'fp':proxy.get('client-fingerprint') or 'chrome','pbk':proxy['reality-opts']['public-key'],'sid':proxy['reality-opts']['short-id'],'type':'tcp'}
    if proxy.get('flow'):params['flow']=proxy['flow']
    if proxy.get('alpn'):params['alpn']=','.join(proxy['alpn'])
    query = urlencode(params)
    return f"vless://{proxy['uuid']}@{address}?{query}#{tag}"

def clash_yaml(proxies):
    names = [p['name'] for p in proxies]
    if len(names)!=len(set(names)) or set(names)&{'DIRECT','REJECT','REJECT-DROP','PASS','GLOBAL','节点选择','自动选择'}:
        raise ControlError(409,'订阅中的节点名称重复或与客户端保留名称冲突，请在面板修改名称后重试')
    groups = [{'name':'节点选择','type':'select','proxies':['自动选择']+names+['DIRECT']}, {'name':'自动选择','type':'url-test','url':'https://www.gstatic.com/generate_204','interval':300,'tolerance':50,'proxies':names or ['DIRECT']}]
    title = base64.b64encode(SUBSCRIPTION_TITLE.encode('utf-8')).decode('ascii')
    return f'#<title>{SUBSCRIPTION_TITLE}</title>\n#profile-title: base64:{title}\n# Mihomo / Clash Meta\nmixed-port: 7890\nallow-lan: false\nmode: rule\nlog-level: warning\nproxies:\n'+(''.join('  - '+json.dumps(p,ensure_ascii=False)+'\n' for p in proxies) if proxies else '  []\n')+'proxy-groups:\n'+''.join('  - '+json.dumps(g,ensure_ascii=False)+'\n' for g in groups)+'rules:\n  - MATCH,节点选择\n'

class Controller:
    def __init__(self, data_dir, validate_host, public_host=''):
        self.root=Path(data_dir);self.root.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.path=self.root/'singlite.sqlite';self.host=validate_host
        self.lock=threading.RLock()
        self.db=sqlite3.connect(self.path,check_same_thread=False,timeout=20)
        os.chmod(self.path,0o600)
        self.db.execute('PRAGMA foreign_keys=ON')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.executescript('\n        CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);\n        CREATE TABLE IF NOT EXISTS nodes(id TEXT PRIMARY KEY,data TEXT NOT NULL);\n        CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,data TEXT NOT NULL,token_hash TEXT UNIQUE NOT NULL);\n        CREATE TABLE IF NOT EXISTS counters(scope TEXT NOT NULL,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,generation TEXT NOT NULL,up INTEGER NOT NULL,down INTEGER NOT NULL,PRIMARY KEY(scope,user_id));\n        ')
        with self.lock,self.db:
            if 'scope' not in {row[1] for row in self.db.execute('PRAGMA table_info(counters)')}:
                self.db.execute('ALTER TABLE counters RENAME TO counters_previous')
                self.db.execute('CREATE TABLE counters(scope TEXT NOT NULL,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,generation TEXT NOT NULL,up INTEGER NOT NULL,down INTEGER NOT NULL,PRIMARY KEY(scope,user_id))')
                self.db.execute("INSERT INTO counters SELECT '',user_id,generation,up,down FROM counters_previous")
                self.db.execute('DROP TABLE counters_previous')
            self.db.execute('CREATE INDEX IF NOT EXISTS counters_user ON counters(user_id)')
            if not self.db.execute("SELECT 1 FROM meta WHERE key='settings'").fetchone():
                self._set_meta('settings',{'publicHost':self.host(public_host,'节点公网地址',allow_ip=True) if public_host else ''})
                self._set_meta('running',True)

    def _meta(self,key):
        return json.loads(self.db.execute('SELECT value FROM meta WHERE key=?',(key,)).fetchone()[0])

    def _set_meta(self,key,value):
        self.db.execute('INSERT INTO meta VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',(key,encode(value)))

    def _all(self, table):
        return [json.loads(row[0]) for row in self.db.execute(f'SELECT data FROM {table} ORDER BY rowid')]

    def _get(self, table, identifier):
        if not isinstance(identifier,str) or not re.fullmatch('[a-f0-9]{32}',identifier):raise ControlError(400,'记录标识格式无效')
        row = self.db.execute(f'SELECT data FROM {table} WHERE id=?',(identifier,)).fetchone()
        if not row: raise ControlError(404, '记录不存在')
        return json.loads(row[0])

    def _put(self, table, item):
        if table=='users':
            self.db.execute('INSERT INTO users(id,data,token_hash) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data,token_hash=excluded.token_hash',(item['id'],encode(item),digest(item['token'])))
        else:
            self.db.execute(f'INSERT INTO {table}(id,data) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data',(item['id'],encode(item)))

    def _roll_periods(self):
        now = int(time.time())
        for u in self._all('users'):
            if u['cycle']=='monthly' and u['nextResetAt'] and now>=u['nextResetAt']:
                u.update(uploadBytes=0,downloadBytes=0,nextResetAt=next_reset(now,u['resetDay']))
                self._put('users',u)


    def nodes_save(self,p,identifier=None):
        if set(p)-{'name','protocol','port','enabled','sni','method','connectHost','connectPort'}: raise ControlError(400,'节点包含不支持的字段')
        with self.lock,self.db:
            old=self._get('nodes',identifier) if identifier else {}
            n=dict(old)
            n.update(id=identifier or new_id(),createdAt=old.get('createdAt',int(time.time())))
            n['name']=text(p.get('name',old.get('name')),'节点名称')
            n['protocol']=p.get('protocol',old.get('protocol','vless'))
            if n['protocol'] not in ('vless','shadowsocks'):raise ControlError(400,'只支持 Reality 和 SS2022')
            if old and n['protocol']!=old['protocol']:raise ControlError(400,'已有节点不能更改协议，请新建节点')
            n['port']=integer(p.get('port',old.get('port')),'端口',1,65535)
            if n['port'] in (80,443,8787,10085):raise ControlError(400,'80、443、8787、10085 为管理保留端口')
            for other in self._all('nodes'):
                if other['id']!=n['id'] and other['port']==n['port']:raise ControlError(409,'该端口已被其他节点使用')
            n['enabled']=boolean(p.get('enabled',old.get('enabled',True)),'启用状态')
            n['connectHost']=self.host(p.get('connectHost',old.get('connectHost','')),'前置机 IP / 域名',optional=True,allow_ip=True)
            port=p.get('connectPort',old.get('connectPort'))
            n['connectPort']=integer(port,'前置机端口',1,65535) if port is not None else None
            if n['connectPort'] is not None and not n['connectHost']:raise ControlError(400,'请同时填写前置机 IP / 域名，或清空前置机端口以恢复直连')
            if n['protocol']=='vless':
                n['sni']=self.host(p.get('sni',old.get('sni','www.amd.com')),'Reality SNI')
                n['method']=None
                if not old:n['privateKey'],n['publicKey']=reality_keys();n['shortId']=secrets.token_hex(8)
            else:
                n['method']=p.get('method',old.get('method','2022-blake3-aes-128-gcm'))
                if not isinstance(n['method'],str) or n['method']not in METHODS:raise ControlError(400,'请选择 SS2022 AES-128 或 AES-256')
                n['sni']=None
                if not old or n['method']!=old.get('method'):n['serverKey']=base64.b64encode(secrets.token_bytes(METHODS[n['method']])).decode()
            if len(self._all('nodes'))>=128 and not identifier:raise ControlError(400,'节点数量已达上限')
            self._put('nodes',n);return {'node':node_public(n)}

    def users_save(self,p,identifier=None):
        if set(p)-{'name','note','enabled','quotaGB','quotaBytes','expiresAt','resetDay','cycle','nodeIds'}:raise ControlError(400,'用户包含不支持的字段')
        with self.lock,self.db:
            self._roll_periods()
            old=self._get('users',identifier) if identifier else {}
            u=dict(old)
            if not old:
                if len(self._all('users'))>=512:raise ControlError(400,'最多管理 512 个用户')
                u={'id':new_id(),'createdAt':int(time.time()),'uploadBytes':0,'downloadBytes':0,'uuid':str(uuid.uuid4()),'psk128':base64.b64encode(secrets.token_bytes(16)).decode(),'psk256':base64.b64encode(secrets.token_bytes(32)).decode(),'token':secrets.token_urlsafe(32),'cycle':'monthly','resetDay':1,'nodeIds':['*']}
            u['name']=text(p.get('name',u.get('name')),'用户名称')
            u['note']=text(p.get('note',u.get('note','')),'备注',256,True)
            u['enabled']=boolean(p.get('enabled',u.get('enabled',True)),'启用状态')
            if 'quotaGB'in p:
                q=p['quotaGB']
                if isinstance(q,bool) or not isinstance(q,(int,float)) or not math.isfinite(q) or not 0<=q<=1_000_000:raise ControlError(400,'配额需为 0–1000000 GB；0 表示不限量')
                if 0 < q*GB < 1:raise ControlError(400,'配额最小为 1 字节')
                u['quotaBytes']=int(q*GB)
            else:u['quotaBytes']=integer(p.get('quotaBytes',u.get('quotaBytes',100*GB)),'流量配额',0,1_000_000*GB)
            expiry=p.get('expiresAt',u.get('expiresAt'))
            u['expiresAt']=integer(expiry,'到期时间',0,253402300799) if expiry is not None else None
            u['cycle']=p.get('cycle',u['cycle'])
            if u['cycle']not in ('monthly','never'):raise ControlError(400,'重置周期无效')
            u['resetDay']=integer(p.get('resetDay',u['resetDay']),'重置日',1,31)
            ids=p.get('nodeIds',u['nodeIds'])
            if not isinstance(ids,list) or len(ids)>128 or not all(isinstance(v,str) for v in ids) or ('*'in ids and ids!=['*']):raise ControlError(400,'节点权限格式无效')
            known={n['id'] for n in self._all('nodes')}
            if ids!=['*'] and set(ids)-known:raise ControlError(400,'节点权限中包含不存在的节点')
            u['nodeIds']=list(dict.fromkeys(ids))
            if not old or (u['cycle'],u['resetDay'])!=(old['cycle'],old['resetDay']):u['nextResetAt']=next_reset(time.time(),u['resetDay']) if u['cycle']=='monthly' else None
            self._put('users',u);return {'user':user_public(u)}

    def users_delete(self,identifier):
        with self.lock,self.db:
            self._get('users',identifier);self.db.execute('DELETE FROM users WHERE id=?',(identifier,));return {'ok':True}

    def users_reset(self,identifier):
        with self.lock,self.db:
            u=self._get('users',identifier);u.update(uploadBytes=0,downloadBytes=0)
            self._put('users',u);return {'user':user_public(u)}

    def users_rotate(self,identifier):
        with self.lock,self.db:
            u=self._get('users',identifier);u['token']=secrets.token_urlsafe(32);self._put('users',u)
            return {'token':u['token'],'path':'/sub/'+u['token']+'/clash.yaml'}

    def user_subscription(self,identifier):
        with self.lock,self.db:
            self._roll_periods();u=self._get('users',identifier)
            return {'token':u['token'],'path':'/sub/'+u['token']+'/clash.yaml','user':user_public(u)}

    def _authorized(self,n,u):
        return u['nodeIds']==['*'] or n['id']in u['nodeIds']

    def nodes_delete(self,identifier):
        with self.lock,self.db:
            self._get('nodes',identifier);self.db.execute('DELETE FROM nodes WHERE id=?',(identifier,))
            for u in self._all('users'):
                if identifier in u['nodeIds']:
                    u['nodeIds'].remove(identifier);self._put('users',u)
            return {'ok':True}

    def settings_save(self,p):
        if set(p)!={'publicHost'}:raise ControlError(400,'请填写本机节点的公网 IP 或直连域名')
        with self.lock,self.db:
            settings={'publicHost':self.host(p['publicHost'],'节点公网地址',allow_ip=True)}
            self._set_meta('settings',settings);return {'settings':settings}

    def running(self,value=None):
        with self.lock,self.db:
            if value is not None:self._set_meta('running',boolean(value,'运行状态'))
            return self._meta('running')

    def bundle(self,allow_users=True):
        with self.lock,self.db:
            self._roll_periods();nodes=[n for n in self._all('nodes') if n['enabled']]
            users=[]
            if allow_users and self._meta('running'):
                for u in self._all('users'):
                    if user_reason(u)!='active':continue
                    access=[n['id'] for n in nodes if self._authorized(n,u)]
                    if access:users.append({k:u[k] for k in ('id','uuid','psk128','psk256')}|{'nodeIds':access})
            return {'nodes':nodes,'users':users}

    def sample(self,raw,generation,scope='',roll_periods=True):
        # The cursor and both usage totals commit together; no separate replay ledger.
        with self.lock,self.db:
            if roll_periods:self._roll_periods()
            for uid,values in raw.items():
                row=self.db.execute('SELECT data FROM users WHERE id=?',(uid,)).fetchone()
                if not row:continue
                previous=self.db.execute('SELECT generation,up,down FROM counters WHERE scope=? AND user_id=?',(scope,uid)).fetchone()
                before=previous[1:] if previous and previous[0]==generation else (0,0)
                now=(values.get('uplink',before[0]),values.get('downlink',before[1]))
                if previous and previous[0]==generation and before==now:continue
                delta=tuple(v-old if v>=old else v for v,old in zip(now,before))
                if any(delta):
                    u=json.loads(row[0]);u['uploadBytes']+=delta[0];u['downloadBytes']+=delta[1];self._put('users',u)
                self.db.execute('INSERT INTO counters VALUES(?,?,?,?,?) ON CONFLICT(scope,user_id) DO UPDATE SET generation=excluded.generation,up=excluded.up,down=excluded.down',(scope,uid,generation,*now))

    def forget_scope(self,scope):
        with self.lock,self.db:
            self.db.execute('DELETE FROM counters WHERE scope=?',(scope,))

    def state(self):
        with self.lock,self.db:
            self._roll_periods()
            return {'edition':'single','version':'3.1.1','settings':self._meta('settings'),'running':self._meta('running'),'nodes':[node_public(n) for n in self._all('nodes')],'users':[user_public(u) for u in self._all('users')],'billing':{'mode':'upload+download','unit':'GB','bytesPerGB':GB,'timezone':'Asia/Shanghai'}}

    def _profiles(self,u):
        host=self._meta('settings')['publicHost']
        profiles=[]
        for n in self._all('nodes'):
            if not n['enabled'] or not self._authorized(n,u):continue
            proxy=client_proxy(n,u,host,n['name'])
            if not proxy['server']:raise ControlError(409,'请填写节点默认公网地址，或在节点中填写前置机地址')
            profiles.append((n,proxy))
        return profiles

    def user_links(self,identifier):
        with self.lock,self.db:
            self._roll_periods();u=self._get('users',identifier)
            if user_reason(u)!='active':raise ControlError(403,'用户已停用、到期或用尽额度')
            return {'user':user_public(u),'links':[{'nodeId':n['id'],'name':n['name'],'protocol':n['protocol'],'port':proxy['port'],'uri':proxy_uri(proxy)} for n,proxy in self._profiles(u)]}

    def subscription(self,token):
        with self.lock,self.db:
            self._roll_periods()
            row=self.db.execute('SELECT data FROM users WHERE token_hash=?',(digest(token),)).fetchone()
            if not row:raise ControlError(404,'订阅不存在或已重置')
            u=json.loads(row[0])
            if user_reason(u)!='active':raise ControlError(403,'用户已停用、到期或用尽额度')
            profiles=self._profiles(u)
            if not profiles:raise ControlError(409,'暂无授权且启用的节点')
            return clash_yaml([proxy for _,proxy in profiles]),u

    def api(self,method,path,p):
        if path=='/api/nodes' and method=='POST':return self.nodes_save(p)
        if path=='/api/users' and method=='POST':return self.users_save(p)
        if path=='/api/settings' and method=='PUT':return self.settings_save(p)
        match=re.fullmatch(r'/api/(users|nodes)/([a-f0-9]{32})(?:/(links|subscription|reset-traffic|rotate-token))?',path)
        if match:
            table,uid,action=match.groups()
            if not action and method=='PUT':return (self.users_save if table=='users' else self.nodes_save)(p,uid)
            if not action and method=='DELETE':return (self.users_delete if table=='users' else self.nodes_delete)(uid)
            if table=='users':
                if action=='links' and method=='GET':return self.user_links(uid)
                if action=='subscription' and method=='GET':return self.user_subscription(uid)
                if action=='reset-traffic' and method=='POST':return self.users_reset(uid)
                if action=='rotate-token' and method=='POST':return self.users_rotate(uid)
        raise ControlError(404,'接口不存在')
