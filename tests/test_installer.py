"""Full terminal installation and interrupted-install recovery with isolated files."""
import hashlib,os,pty,select,shutil,signal,socket,tempfile,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def terminal_run(argv, answers=(), env=None):
    pid,fd=pty.fork()
    if pid==0:
        os.execvpe(argv[0],argv,env or os.environ.copy())
    output=b''
    pending=list(answers)
    deadline=time.monotonic()+25
    status=None
    try:
        while time.monotonic()<deadline:
            ready,_,_=select.select([fd],[],[],.1)
            if ready:
                try:data=os.read(fd,65536)
                except OSError:break
                if not data:break
                output+=data
                if pending and pending[0][0].encode() in output:
                    _,answer=pending.pop(0)
                    os.write(fd,(answer+'\n').encode())
            ended,status_now=os.waitpid(pid,os.WNOHANG)
            if ended:
                status=status_now
                break
        else:raise AssertionError('Terminal timed out: '+output.decode(errors='replace'))
        if status is None:_,status=os.waitpid(pid,0)
        if pending:raise AssertionError('Missing prompts: '+output.decode(errors='replace'))
        return os.waitstatus_to_exitcode(status),output.decode(errors='replace')
    finally:
        os.close(fd)
        if status is None:
            try:os.kill(pid,signal.SIGKILL);os.waitpid(pid,0)
            except ProcessLookupError:pass

class InstallerTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.base=Path(self.tmp.name)
  self.source=self.base/'source';shutil.copytree(ROOT,self.source,ignore=shutil.ignore_patterns('.git','__pycache__','singlite-panel.tar.gz'))
  self.fs=self.base/'fs'
  for name in ('run/systemd/system','run/lock','etc/systemd/system','root'):(self.fs/name).mkdir(parents=True,exist_ok=True)
  self.bin=self.base/'bin';self.bin.mkdir();self.calls=self.base/'calls'
  for name in ('systemctl','apt-get','curl','caddy','chown'):
   extra=''
   if name=='systemctl':extra='case "$1" in show) echo not-found;; is-active) exit 1;; esac\n'
   if name=='curl':extra='exit "${TEST_FAIL_HEALTH:-0}"\n'
   p=self.bin/name;p.write_text('#!/bin/sh\nprintf "%s\\n" "'+name+' $*" >> "$TEST_CALLS"\n'+extra+'exit 0\n');p.chmod(0o755)
  self.env=dict(os.environ,PATH=str(self.bin)+':'+os.environ['PATH'],TEST_CALLS=str(self.calls))
  for name in ('install.sh','scripts/reset-admin.py'):
   p=self.source/name;s=p.read_text().replace('"$EUID" == 0',f'"$EUID" == {os.geteuid()}').replace('if os.geteuid()!=0:',f'if os.geteuid()!={os.geteuid()}:')
   s=s.replace('tar -czf "$backup" -C / opt/singlite etc/singlite var/lib/singlite',f'tar -czf "$backup" -C {self.fs} opt/singlite etc/singlite var/lib/singlite')
   for prefix in ('/opt/singlite','/etc/singlite','/var/lib/singlite','/etc/systemd/system','/run/systemd/system','/run/lock','/root/singlite-backup'):s=s.replace(prefix,str(self.fs)+prefix)
   p.write_text(s.replace('sleep 1','true'))
  (self.source/'scripts/build-singbox.sh').write_text('''#!/bin/sh
[ "${TEST_BUILD_FAIL:-0}" != 1 ] || exit 42
mkdir -p "$1"
printf '#!/bin/sh\necho "sing-box version 1.14.3-singlite with_v2ray_api"\n' > "$1/sing-box"
printf '#!/bin/sh\necho "{}"\n' > "$1/singbox-stats"
chmod 755 "$1/sing-box" "$1/singbox-stats"
printf test-build > "$1/core-build"
printf license > "$1/LICENSE"
''')
  self.admin=self.fs/'var/lib/singlite/admin.json';self.config=self.fs/'etc/singlite/panel.env'
 def run_install(self,mode='--with-caddy',answers=None,**extra):
  if answers is None:answers=[('面板域名','panel.example.com')]+self.credentials()
  return terminal_run(['bash',str(self.source/'install.sh'),mode],answers,dict(self.env,**extra))
 def credentials(self):return [('管理员用户名','admin'),('管理员密码','123456'),('再次输入密码','123456')]
 def assert_release_files(self):
  d=self.fs/'opt/singlite/dist';a=d/'singlite-panel.tar.gz'
  self.assertTrue(a.is_file());self.assertEqual(hashlib.sha256(a.read_bytes()).hexdigest(),(d/'singlite-panel.tar.gz.sha256').read_text().split()[0])
  self.assertTrue((self.fs/'opt/singlite/bin/sing-box').is_file());self.assertTrue((self.fs/'etc/systemd/system/singlite-node@.service').is_file())
  self.assertNotIn('agentToken',self.config.read_text());self.assertFalse((self.fs/'opt/singlite-agent').exists())
 def test_one_script_installs_panel_core_and_download_and_accepts_six_digits(self):
  status,out=self.run_install();self.assertEqual(status,0,out);self.assertNotIn('123456',out)
  self.assertTrue(self.admin.is_file());self.assertEqual(self.admin.stat().st_mode&0o777,0o600)
  self.assertEqual((self.fs/'etc/singlite/edition').read_text(),'single\n');self.assert_release_files()
  calls=self.calls.read_text();self.assertIn('enable --now singlite-panel',calls);self.assertNotIn('enable --now singlite-core',calls)
  self.assertNotIn('服务器接入令牌',out)
 def test_existing_proxy_mode_preserves_occupied_web_port(self):
  with socket.socket() as occupied:
   occupied.bind(('127.0.0.1',0));occupied.listen();p=self.source/'install.sh';p.write_text(p.read_text().replace('check_ports web 80 443','check_ports web '+str(occupied.getsockname()[1])))
   status,out=self.run_install('--existing-proxy')
  self.assertEqual(status,0,out);self.assertFalse((self.fs/'etc/systemd/system/singlite-web.service').exists());self.assert_release_files()
 def test_resume_after_disconnect_before_password_initialization(self):
  p=self.source/'install.sh';original=p.read_text();p.write_text(original.replace('if [[ ! -e /var/lib/singlite/admin.json ]];then','if [[ ! -e /var/lib/singlite/admin.json ]];then'))
  marker='if [[ ! -e '+str(self.admin)+' ]];then';self.assertIn(marker,original)
  p.write_text(original.replace(marker,'exit 42\n'+marker))
  status,out=self.run_install(answers=[('面板域名','panel.example.com')]);self.assertEqual(status,42,out)
  self.assertTrue(self.config.is_file());self.assertFalse(self.admin.exists())
  p.write_text(original);status,out=self.run_install('--resume',self.credentials());self.assertEqual(status,0,out)
  self.assertTrue(self.admin.is_file());self.assert_release_files()
  self.assertNotIn('systemctl stop singlite-panel',self.calls.read_text())
 def test_repeat_resume_preserves_admin_settings_and_data(self):
  status,out=self.run_install();self.assertEqual(status,0,out);before=self.admin.read_bytes();cfg=self.config.read_bytes()
  sentinel=self.fs/'var/lib/singlite/sentinel';sentinel.write_text('preserve')
  status,out=self.run_install('--resume',[]);self.assertEqual(status,0,out)
  self.assertEqual(self.admin.read_bytes(),before);self.assertEqual(self.config.read_bytes(),cfg);self.assertEqual(sentinel.read_text(),'preserve')
  self.assertTrue(list((self.fs/'root').glob('singlite-backup-*.tar.gz')))
 def test_build_failure_does_not_create_installation(self):
  status,out=self.run_install(answers=[('面板域名','panel.example.com')],TEST_BUILD_FAIL='1')
  self.assertEqual(status,42,out);self.assertFalse(self.config.exists());self.assertFalse((self.fs/'opt/singlite').exists())
 def test_health_failure_can_resume_with_existing_admin(self):
  status,out=self.run_install(TEST_FAIL_HEALTH='1');self.assertNotEqual(status,0);self.assertIn('--resume',out)
  before=self.admin.read_bytes();status,out=self.run_install('--resume',[]);self.assertEqual(status,0,out);self.assertEqual(self.admin.read_bytes(),before)
 def test_real_tcp_conflict_is_clear_and_precedes_package_install(self):
  for call in ('check_ports web 80 443','check_ports panel 8787'):
   with self.subTest(port_call=call),socket.socket() as occupied:
    occupied.bind(('127.0.0.1',0));occupied.listen();port=occupied.getsockname()[1]
    p=self.source/'install.sh';original=p.read_text();p.write_text(original.replace(call,call.rsplit(' ',1)[0].split(' 80')[0]+' '+str(port)))
    if self.calls.exists():self.calls.unlink()
    status,out=self.run_install(answers=[('面板域名','panel.example.com')]);self.assertNotEqual(status,0);self.assertIn(f'TCP {port}',out);self.assertNotIn('Traceback',out)
    self.assertNotIn('apt-get',self.calls.read_text());self.assertFalse(self.config.exists());p.write_text(original)
 def test_ipv6_conflict_and_legacy_agent_are_not_overwritten(self):
  try:
   occupied=socket.socket(socket.AF_INET6);self.addCleanup(occupied.close);occupied.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1);occupied.bind(('::1',0));occupied.listen()
  except OSError as e:self.skipTest(str(e))
  p=self.source/'install.sh';original=p.read_text();p.write_text(original.replace('check_ports web 80 443','check_ports web '+str(occupied.getsockname()[1])))
  status,out=self.run_install(answers=[('面板域名','panel.example.com')]);self.assertNotEqual(status,0);self.assertIn('IPv6',out);p.write_text(original)
  (self.fs/'etc/singlite-agent').mkdir();status,out=self.run_install(answers=[]);self.assertNotEqual(status,0);self.assertIn('旧多 VPS',out)
 def test_reset_admin_uses_six_digits_and_private_backup(self):
  status,out=self.run_install();self.assertEqual(status,0,out);before=self.admin.read_bytes()
  status,out=terminal_run(['python3',str(self.source/'scripts/reset-admin.py')],[('管理员用户名','newadmin'),('新密码','654321'),('再次输入密码','654321')],self.env)
  self.assertEqual(status,0,out);self.assertNotIn('654321',out);self.assertNotEqual(self.admin.read_bytes(),before)
  self.assertEqual(next(self.admin.parent.glob('admin.backup.*.json')).read_bytes(),before)

if __name__=='__main__':unittest.main()
