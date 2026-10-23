"""Single-machine permissions, transactional metering, exports and local lifecycle."""
import base64
from http.client import HTTPConnection
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
from urllib.parse import parse_qs,unquote,urlsplit
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'server'))
import panel,control,core

class StoreTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.c=control.Controller(self.tmp.name,panel.hostname,'2001:db8::1');self.addCleanup(self.c.db.close)
  self.n=self.c.nodes_save({'name':'Reality','port':8443})['node']
  self.s=self.c.nodes_save({'name':'SS','protocol':'shadowsocks','port':8388})['node']
  self.u=self.c.users_save({'name':'Alice','quotaBytes':1000})['user'];self.uid=self.u['id']
 def sample(self,up,down,generation='boot:1:1'):
  self.c.sample({self.uid:{'uplink':up,'downlink':down}},generation)
 def user(self):return self.c.state()['users'][0]
 def test_state_has_no_servers_or_pairing_and_no_credentials(self):
  state=self.c.state();self.assertEqual(state['edition'],'single');self.assertNotIn('servers',state)
  for word in ('serverId','token','psk128','privateKey','uuid'):self.assertNotIn('"'+word+'"',json.dumps(state))
  self.assertEqual(self.n['sni'],'www.amd.com')
  self.assertEqual(self.c.path.stat().st_mode&0o777,0o600)
 def test_permissions_render_and_each_user_has_own_credentials(self):
  self.c.users_save({'name':'Bob','nodeIds':[self.s['id']]})
  config=core.render_singbox(self.c.bundle(),'127.0.0.1')
  reality,ss=config['inbounds'];self.assertEqual(len(reality['users']),1);self.assertEqual(len(ss['users']),2)
  self.assertEqual(reality['tls']['server_name'],'www.amd.com');self.assertEqual(reality['users'][0]['flow'],'xtls-rprx-vision')
  self.assertNotEqual(ss['users'][0]['password'],ss['users'][1]['password'])
  self.assertNotIn('network',ss)
 def test_ss2022_both_key_lengths_and_revoked_parent_key(self):
  for method,size in control.METHODS.items():
   self.c.nodes_save({'method':method},self.s['id']);conf=core.render_singbox(self.c.bundle())['inbounds'][1]
   self.assertEqual(len(base64.b64decode(conf['password'])),size);self.assertEqual(len(base64.b64decode(conf['users'][0]['password'])),size)
  self.c.users_save({'enabled':False},self.uid)
  self.assertEqual(core.render_singbox(self.c.bundle())['inbounds'],[])
 def test_replay_out_of_process_restart_and_double_direction_quota(self):
  self.sample(100,200);self.sample(100,200);self.assertEqual(self.user()['usedBytes'],300)
  self.sample(150,250);self.assertEqual(self.user()['usedBytes'],400)
  self.sample(25,50,'boot:2:2');self.assertEqual(self.user()['usedBytes'],475)
  self.sample(400,400,'boot:2:2');self.assertEqual(self.user()['status'],'quota');self.assertEqual(self.c.bundle()['users'],[])
 def test_reset_does_not_rebill_existing_core_counters(self):
  self.sample(100,200);self.c.users_reset(self.uid);self.sample(100,200);self.assertEqual(self.user()['usedBytes'],0)
  self.sample(130,240);self.assertEqual(self.user()['usedBytes'],70)
 def test_idle_samples_do_not_write_but_generation_changes_remain_persistent(self):
  self.sample(100,200);before=self.c.db.total_changes
  self.sample(100,200);self.assertEqual(self.c.db.total_changes,before)
  self.sample(0,0,'boot:2:2');self.assertEqual(self.user()['usedBytes'],300)
  self.assertEqual(self.c.db.execute('SELECT generation FROM counters WHERE user_id=?',(self.uid,)).fetchone()[0],'boot:2:2')
  self.sample(10,20,'boot:2:2');self.assertEqual(self.user()['usedBytes'],330)
 def test_monthly_rollover_preserves_counter_cursor(self):
  self.sample(100,200)
  with self.c.lock,self.c.db:
   u=self.c._get('users',self.uid);u['nextResetAt']=int(time.time())-1;self.c._put('users',u)
  self.assertEqual(self.user()['usedBytes'],0);self.sample(110,220);self.assertEqual(self.user()['usedBytes'],30)
 def test_database_reopen_preserves_cursor(self):
  self.sample(20,30);another=control.Controller(self.tmp.name,panel.hostname)
  try:another.sample({self.uid:{'uplink':20,'downlink':30}},'boot:1:1');self.assertEqual(another.state()['users'][0]['usedBytes'],50)
  finally:another.db.close()
 def test_links_match_actual_users_and_ipv6_and_subscription_is_optional(self):
  links=self.c.user_links(self.uid)['links'];bundle=self.c.bundle();u=bundle['users'][0]
  uri=urlsplit(links[0]['uri']);q=parse_qs(uri.query)
  self.assertEqual(uri.hostname,'2001:db8::1');self.assertEqual(uri.username,u['uuid']);self.assertEqual(q['sni'],['www.amd.com'])
  ss=urlsplit(links[1]['uri']);self.assertEqual(unquote(ss.password),bundle['nodes'][1]['serverKey']+':'+u['psk128'])
  token=self.c.user_subscription(self.uid)['token'];content,_=self.c.subscription(token);self.assertIn('proxy-groups:',content)
  self.c.users_rotate(self.uid)
  with self.assertRaises(control.ControlError):self.c.subscription(token)
  self.assertEqual(self.c.user_links(self.uid)['links'],links)
 def test_ss_forward_entry_changes_exports_without_changing_core_or_credentials(self):
  before=core.render_singbox(self.c.bundle());links=self.c.user_links(self.uid)['links']
  node=self.c.nodes_save({'connectHost':'198.51.100.7','connectPort':443},self.s['id'])['node']
  self.assertEqual(node['port'],8388);self.assertEqual(node['connectPort'],443)
  self.assertEqual(core.render_singbox(self.c.bundle()),before)
  exported=self.c.user_links(self.uid)['links'];self.assertEqual(exported[0],links[0]);self.assertEqual(exported[1]['port'],443)
  old,new=urlsplit(links[1]['uri']),urlsplit(exported[1]['uri'])
  self.assertEqual((new.hostname,new.port),('198.51.100.7',443))
  self.assertEqual((new.username,new.password,new.fragment),(old.username,old.password,old.fragment))
  token=self.c.user_subscription(self.uid)['token'];yaml,_=self.c.subscription(token)
  proxies=[json.loads(line[4:]) for line in yaml.splitlines() if line.startswith('  - {')]
  ss=next(p for p in proxies if p.get('type')=='ss')
  self.assertEqual((ss['server'],ss['port']),('198.51.100.7',443))
  self.assertEqual(ss['password'],unquote(new.password))
 def test_ss_forward_entry_ipv6_default_port_persistence_and_direct_restore(self):
  for host in ('relay.example.com','2001:db8::5'):
   self.c.nodes_save({'connectHost':host,'connectPort':None},self.s['id'])
   uri=urlsplit(self.c.user_links(self.uid)['links'][1]['uri'])
   self.assertEqual((uri.hostname,uri.port),(host,8388))
  another=control.Controller(self.tmp.name,panel.hostname)
  try:self.assertEqual(another.state()['nodes'][1]['connectHost'],'2001:db8::5')
  finally:another.db.close()
  self.c.nodes_save({'connectHost':'','connectPort':None},self.s['id'])
  uri=urlsplit(self.c.user_links(self.uid)['links'][1]['uri'])
  self.assertEqual((uri.hostname,uri.port),('2001:db8::1',8388))
 def test_ss_forward_entry_can_supply_address_without_a_global_host(self):
  with self.c.lock,self.c.db:self.c._set_meta('settings',{'publicHost':''})
  self.c.users_save({'nodeIds':[self.s['id']]},self.uid)
  self.c.nodes_save({'connectHost':'relay.example.com','connectPort':18443},self.s['id'])
  self.assertEqual(urlsplit(self.c.user_links(self.uid)['links'][0]['uri']).hostname,'relay.example.com')
  self.c.nodes_save({'connectHost':'','connectPort':None},self.s['id'])
  with self.assertRaises(control.ControlError):self.c.user_links(self.uid)
 def test_ss_forward_entry_validation_and_legacy_nodes(self):
  for node in (self.n,self.s):
   for payload in ({'connectHost':'https://relay.example.com'},{'connectHost':'relay.example.com:443'},{'connectHost':[]},{'connectPort':443},{'connectHost':'relay.example.com','connectPort':0},{'connectHost':'relay.example.com','connectPort':65536},{'connectHost':'relay.example.com','connectPort':True}):
    with self.subTest(protocol=node['protocol'],payload=payload),self.assertRaises((control.ControlError,panel.ApiError)):self.c.nodes_save(payload,node['id'])
   with self.c.lock,self.c.db:
    n=self.c._get('nodes',node['id']);n.pop('connectHost',None);n.pop('connectPort',None);self.c._put('nodes',n)
  self.assertEqual(urlsplit(self.c.user_links(self.uid)['links'][0]['uri']).port,8443)
  self.assertEqual(urlsplit(self.c.user_links(self.uid)['links'][1]['uri']).port,8388)
 def test_vless_forward_entry_changes_exports_without_changing_core_or_identity(self):
  before=core.render_singbox(self.c.bundle());original=self.c.user_links(self.uid)['links']
  node=self.c.nodes_save({'connectHost':'relay.example.com','connectPort':443},self.n['id'])['node']
  self.assertEqual((node['port'],node['connectPort']),(8443,443))
  self.assertEqual(core.render_singbox(self.c.bundle()),before)
  exported=self.c.user_links(self.uid)['links'];old,new=urlsplit(original[0]['uri']),urlsplit(exported[0]['uri'])
  self.assertEqual((new.hostname,new.port),('relay.example.com',443))
  self.assertEqual((new.username,new.query,new.fragment),(old.username,old.query,old.fragment))
  self.assertEqual(exported[0]['port'],443);self.assertEqual(exported[1],original[1])
  yaml,_=self.c.subscription(self.c.user_subscription(self.uid)['token'])
  reality=next(json.loads(line[4:]) for line in yaml.splitlines() if line.startswith('  - {') and '"type": "vless"' in line)
  self.assertEqual((reality['server'],reality['port']),('relay.example.com',443))
  self.assertEqual(reality['servername'],'www.amd.com')
  self.assertEqual(reality['uuid'],old.username)
 def test_vless_forward_entry_ipv6_default_port_persistence_and_direct_restore(self):
  original=self.c.user_links(self.uid)['links'][0]
  before=core.render_singbox(self.c.bundle())
  for host in ('relay.example.com','2001:db8::9'):
   self.c.nodes_save({'connectHost':host,'connectPort':None},self.n['id'])
   uri=urlsplit(self.c.user_links(self.uid)['links'][0]['uri'])
   self.assertEqual((uri.hostname,uri.port),(host,8443))
  another=control.Controller(self.tmp.name,panel.hostname)
  try:
   self.assertEqual(another.state()['nodes'][0]['connectHost'],'2001:db8::9')
   self.assertEqual(urlsplit(another.user_links(self.uid)['links'][0]['uri']).hostname,'2001:db8::9')
  finally:another.db.close()
  self.c.nodes_save({'connectHost':'','connectPort':None},self.n['id'])
  self.assertEqual(self.c.user_links(self.uid)['links'][0],original)
  self.assertEqual(core.render_singbox(self.c.bundle()),before)
 def test_vless_forward_entry_can_supply_address_without_a_global_host(self):
  with self.c.lock,self.c.db:self.c._set_meta('settings',{'publicHost':''})
  self.c.users_save({'nodeIds':[self.n['id']]},self.uid)
  self.c.nodes_save({'connectHost':'relay.example.com','connectPort':14443},self.n['id'])
  uri=urlsplit(self.c.user_links(self.uid)['links'][0]['uri'])
  self.assertEqual((uri.hostname,uri.port),('relay.example.com',14443))
  self.c.nodes_save({'connectHost':'','connectPort':None},self.n['id'])
  with self.assertRaises(control.ControlError):self.c.user_links(self.uid)
 def test_vless_uri_preserves_fingerprint_optional_flow_and_alpn(self):
  node=self.c.bundle()['nodes'][0];user=self.c.bundle()['users'][0]
  proxy=control.client_proxy(node,user,'2001:db8::1','Reality')
  proxy.update({'client-fingerprint':'firefox','flow':'','alpn':['h2','http/1.1']})
  uri=urlsplit(control.proxy_uri(proxy));query=parse_qs(uri.query)
  self.assertEqual(query['fp'],['firefox']);self.assertEqual(query['alpn'],['h2,http/1.1'])
  self.assertNotIn('flow',query)
 def test_expiry_disabled_quota_revoke_feed_and_user(self):
  token=self.c.user_subscription(self.uid)['token']
  for payload in ({'enabled':False},{'enabled':True,'expiresAt':1},{'expiresAt':None,'quotaBytes':1}):
   self.c.users_save(payload,self.uid)
   if payload.get('quotaBytes'):self.sample(2,0)
   self.assertEqual(self.c.bundle()['users'],[])
   with self.assertRaises(control.ControlError):self.c.subscription(token)
 def test_validation_and_node_deletion_cleanup(self):
  for p in ({'name':'bad','port':443},{'name':'bad','port':8388},{'name':'bad','port':9000,'serverId':'external'},{'name':'bad','port':True}):
   with self.assertRaises(control.ControlError):self.c.nodes_save(p)
  for p in ({'quotaGB':float('nan')},{'quotaGB':True},{'nodeIds':['missing']},{'cycle':[]},{'resetDay':0}):
   with self.assertRaises(control.ControlError):self.c.users_save(p,self.uid)
  self.c.users_save({'nodeIds':[self.n['id']]},self.uid);self.c.nodes_delete(self.n['id']);self.assertEqual(self.user()['nodeIds'],[])
 def test_text_fields_reject_invalid_unicode_and_control_characters(self):
  for value in ('bad\x7fname','\ud800'):
   with self.subTest(value=repr(value)),self.assertRaises(control.ControlError):self.c.nodes_save({'name':value},self.n['id'])
 def test_sample_transaction_rolls_back_totals_and_cursor(self):
  self.sample(10,20)
  with mock.patch.object(self.c,'_put',side_effect=RuntimeError('disk failure')):
   with self.assertRaises(RuntimeError):self.sample(30,40)
  self.assertEqual(self.user()['usedBytes'],30);self.sample(30,40);self.assertEqual(self.user()['usedBytes'],70)

class HttpTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.app=panel.Panel(self.tmp.name,runner=lambda args,**k:subprocess.CompletedProcess(args,0,'sing-box version 1.14.3-singlite',''))
  self.app.control.settings_save({'publicHost':'127.0.0.1'});self.app.init_admin('admin','123456');self.cookie='';self.csrf=''
  self.server=panel.PanelServer(('127.0.0.1',0),self.app);self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start();self.addCleanup(self.close)
 def close(self):self.server.shutdown();self.server.server_close();self.thread.join();self.app.close()
 def request(self,method,path,p=None,extra=None):
  c=HTTPConnection('127.0.0.1',self.server.server_port,timeout=5);headers={'Content-Type':'application/json','Cookie':self.cookie,'X-CSRF-Token':self.csrf,**(extra or {})}
  c.request(method,path,body=json.dumps(p) if p is not None else None,headers=headers);r=c.getresponse();data=r.read();code=r.status;headers=dict(r.getheaders());c.close()
  return code,headers,json.loads(data) if data else None
 def login(self):
  code,h,data=self.request('POST','/api/login',{'username':'admin','password':'123456'},{'X-Forwarded-Proto':'https'});self.assertEqual(code,200);self.cookie=h['Set-Cookie'].split(';')[0];self.csrf=data['csrf'];return h
 def feed(self,token,method='GET'):
  c=HTTPConnection('127.0.0.1',self.server.server_port,timeout=5)
  c.request(method,'/sub/'+token+'/clash.yaml');r=c.getresponse();body=r.read();result=(r.status,dict(r.getheaders()),body);c.close();return result
 def test_subscription_title_is_fixed_and_no_client_usage_is_exposed(self):
  self.app.control.nodes_save({'name':'vmiss','port':8443})
  user=self.app.control.users_save({'name':'Me','quotaGB':100,'expiresAt':None})['user'];uid=user['id']
  self.app.control.sample({uid:{'uplink':100_000_000,'downlink':44_526_950}},'generation')
  token=self.app.control.user_subscription(uid)['token']
  for method in ('GET','HEAD'):
   code,h,body=self.feed(token,method);self.assertEqual(code,200)
   title=base64.b64decode(h['Profile-Title'].removeprefix('base64:')).decode()
   self.assertEqual(title,'Singlite · Proxy');self.assertNotIn('Subscription-Userinfo',h)
   self.assertEqual(h['Cache-Control'],'no-store')
   self.assertEqual(unquote(h['Content-Disposition'].split("filename*=UTF-8''")[1]),'Singlite · Proxy.yaml')
   if method=='HEAD':self.assertEqual(body,b'')
   else:self.assertIn(b'"name": "vmiss"',body)
  self.assertEqual(self.app.control.state()['users'][0]['usedBytes'],144_526_950)
  links=self.app.control.user_links(uid)['links']
  self.app.control.sample({uid:{'uplink':150_000_000,'downlink':100_000_000}},'generation')
  h=self.feed(token)[1]
  self.assertEqual(base64.b64decode(h['Profile-Title'][7:]).decode(),'Singlite · Proxy')
  self.assertEqual(self.app.control.state()['users'][0]['usedBytes'],250_000_000)
  self.assertEqual(self.app.control.user_links(uid)['links'],links)
 def test_subscription_hides_expiry_but_still_enforces_expiry_and_quota(self):
  self.app.control.nodes_save({'name':'vmiss','port':8443})
  expiry=int(time.time())+3600
  user=self.app.control.users_save({'name':'Me','quotaGB':100,'expiresAt':expiry})['user'];uid=user['id']
  token=self.app.control.user_subscription(uid)['token']
  self.assertNotIn('Subscription-Userinfo',self.feed(token)[1])
  self.app.control.users_save({'expiresAt':None},uid)
  self.assertNotIn('Subscription-Userinfo',self.feed(token)[1])
  self.app.control.users_save({'expiresAt':1},uid);self.assertEqual(self.feed(token)[0],403)
  self.app.control.users_save({'expiresAt':None,'quotaBytes':1},uid)
  self.app.control.sample({uid:{'uplink':1,'downlink':1}},'generation');self.assertEqual(self.feed(token)[0],403)
 def test_six_digit_login_csrf_and_session_logout(self):
  self.assertEqual(self.request('GET','/api/state')[0],401);h=self.login()
  for flag in ('HttpOnly','SameSite=Strict','Secure'):self.assertIn(flag,h['Set-Cookie'])
  code,_,state=self.request('GET','/api/state');self.assertEqual(code,200);self.assertEqual(state['edition'],'single');self.assertNotIn('servers',state)
  self.assertEqual(self.request('POST','/api/users',{'name':'bad'},{'X-CSRF-Token':''})[0],403)
  self.assertEqual(self.request('POST','/api/logout',{})[0],200);self.assertEqual(self.request('GET','/api/state')[0],401)
 def test_create_local_node_and_user_without_token_then_export(self):
  self.login();code,_,n=self.request('POST','/api/nodes',{'name':'Reality','port':8443});self.assertEqual(code,200);self.assertNotIn('serverId',n['node'])
  code,_,u=self.request('POST','/api/users',{'name':'Me'});self.assertEqual(code,200)
  code,_,links=self.request('GET','/api/users/'+u['user']['id']+'/links');self.assertEqual(code,200);self.assertTrue(links['links'][0]['uri'].startswith('vless://'))
  self.assertEqual(self.request('GET','/api/servers')[0],404)
  self.assertEqual(self.request('POST','/api/agent/sync',{})[0],404)
 def test_node_crud_responds_while_worker_is_busy_without_sampling(self):
  self.login();locked=threading.Event();release=threading.Event()
  def hold():
   with self.app.runtime.lock:locked.set();release.wait(5)
  worker=threading.Thread(target=hold);worker.start();self.assertTrue(locked.wait(2))
  try:
   with mock.patch.object(self.app.runtime,'collect',side_effect=AssertionError('HTTP must not sample')):
    started=time.monotonic();code,_,result=self.request('POST','/api/nodes',{'name':'Fast','protocol':'shadowsocks','port':15321})
    self.assertEqual(code,200);self.assertLess(time.monotonic()-started,1)
    self.assertEqual(self.request('DELETE','/api/nodes/'+result['node']['id'],{})[0],200)
    self.assertEqual(self.request('GET','/api/state')[0],200)
  finally:release.set();worker.join()
 def test_ss_forward_entry_survives_http_create_edit_and_export(self):
  self.login()
  code,_,data=self.request('POST','/api/nodes',{'name':'SS relay','protocol':'shadowsocks','port':8388,'connectHost':'198.51.100.10','connectPort':18443})
  self.assertEqual(code,200);node=data['node'];self.assertEqual(node['port'],8388)
  code,_,data=self.request('POST','/api/users',{'name':'Relay user'});self.assertEqual(code,200);uid=data['user']['id']
  code,_,data=self.request('GET','/api/users/'+uid+'/links');self.assertEqual(code,200)
  uri=urlsplit(data['links'][0]['uri']);self.assertEqual((uri.hostname,uri.port),('198.51.100.10',18443))
  code,_,_=self.request('PUT','/api/nodes/'+node['id'],{'connectHost':'','connectPort':None});self.assertEqual(code,200)
  code,_,data=self.request('GET','/api/users/'+uid+'/links');self.assertEqual(code,200)
  uri=urlsplit(data['links'][0]['uri']);self.assertEqual((uri.hostname,uri.port),('127.0.0.1',8388))
 def test_vless_forward_entry_survives_http_create_edit_and_export(self):
  self.login()
  code,_,data=self.request('POST','/api/nodes',{'name':'Reality relay','protocol':'vless','port':8443,'connectHost':'2001:db8::10','connectPort':443})
  self.assertEqual(code,200);node=data['node'];self.assertEqual(node['port'],8443)
  code,_,data=self.request('POST','/api/users',{'name':'Reality user'});self.assertEqual(code,200);uid=data['user']['id']
  code,_,data=self.request('GET','/api/users/'+uid+'/links');self.assertEqual(code,200)
  exported=urlsplit(data['links'][0]['uri']);self.assertEqual((exported.hostname,exported.port),('2001:db8::10',443))
  self.assertEqual(parse_qs(exported.query)['sni'],['www.amd.com'])
  code,_,_=self.request('PUT','/api/nodes/'+node['id'],{'connectHost':'','connectPort':None});self.assertEqual(code,200)
  code,_,data=self.request('GET','/api/users/'+uid+'/links');self.assertEqual(code,200)
  direct=urlsplit(data['links'][0]['uri']);self.assertEqual((direct.hostname,direct.port),('127.0.0.1',8443))
  self.assertEqual((direct.username,direct.query),(exported.username,exported.query))
 def test_cross_origin_and_static_traversal_are_rejected(self):
  self.assertEqual(self.request('POST','/api/login',{'username':'admin','password':'123456'},{'Origin':'https://other.example'})[0],403)
  for path in ('/.git/config','/%2e%2e/server/panel.py','/missing.js'):self.assertEqual(self.request('GET',path)[0],404)
 def test_password_bounds_and_rate_limit(self):
  self.app.admin_path.unlink()
  for p in ('12345','x'*1025):
   with self.assertRaises(ValueError):self.app.init_admin('admin',p)
  self.app.init_admin('admin','123456')
  for _ in range(8):self.assertEqual(self.request('POST','/api/login',{'username':'admin','password':'wrong'})[0],401)
  self.assertEqual(self.request('POST','/api/login',{'username':'admin','password':'123456'})[0],429)

class SubscriptionDisplayTests(unittest.TestCase):
 def test_title_matches_header_yaml_html_and_filename_fallbacks(self):
  h=panel.subscription_headers();title=base64.b64decode(h['Profile-Title'][7:]).decode()
  self.assertEqual(title,'Singlite · Proxy');self.assertNotIn('Subscription-Userinfo',h)
  self.assertEqual(unquote(h['Content-Disposition'].split("filename*=UTF-8''")[1]),title+'.yaml')
  content=control.clash_yaml([])
  self.assertIn('#<title>'+title+'</title>',content)
  self.assertIn('#profile-title: '+h['Profile-Title'],content)
  self.assertIn('<title>'+title+'</title>',(ROOT/'dist/index.html').read_text())
  self.assertNotIn('Subscription-Userinfo',content)

if __name__=='__main__':unittest.main()
