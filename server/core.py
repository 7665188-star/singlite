"""Local sing-box configuration and lifecycle. No remote control listener."""
import hashlib,json,os,re,socket,subprocess,tempfile,threading,time
from pathlib import Path

API_PORT=10085

def render_singbox(bundle, listen="::", stats_port=API_PORT):
    """Both protocols use a stable user name for sing-box's per-user counters."""
    names=[u['id']+'@singlite' for u in bundle.get('users',[])]
    config={'log':{'level':'warn'},'dns':{'servers':[{'type':'local','tag':'local'}]},'inbounds':[],'outbounds':[{'type':'direct','tag':'direct'}],'route':{'final':'direct','default_domain_resolver':'local'},'experimental':{'v2ray_api':{'listen':'127.0.0.1:'+str(stats_port),'stats':{'enabled':True,'users':names}}}}
    for node in bundle.get('nodes',[]):
        users=[u for u in bundle.get('users',[]) if node['id'] in u['nodeIds']]
        # Do not permit the SS server key to authenticate after the last user is revoked.
        if not users:continue
        base={'tag':'node-'+node['id'],'listen':listen,'listen_port':node['port']}
        if node['protocol']=='vless':
            base.update(type='vless',users=[{'name':u['id']+'@singlite','uuid':u['uuid'],'flow':'xtls-rprx-vision'} for u in users],tls={'enabled':True,'server_name':node['sni'],'reality':{'enabled':True,'handshake':{'server':node['sni'],'server_port':443},'private_key':node['privateKey'],'short_id':[node['shortId']]}})
        elif node['protocol']=='shadowsocks':
            if node['method'] not in ('2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm'):raise ValueError('Unsupported multi-user SS cipher')
            base.update(type='shadowsocks',method=node['method'],password=node['serverKey'],users=[{'name':u['id']+'@singlite','password':u['psk128'] if node['method']=='2022-blake3-aes-128-gcm' else u['psk256']} for u in users])
        else:raise ValueError('Unknown inbound protocol')
        config['inbounds'].append(base)
    return config

def config_hash(config):
    return hashlib.sha256(json.dumps(config,sort_keys=True).encode()).hexdigest()


class Runtime:
    """One independent core per authorized node; all I/O stays on the worker."""
    def __init__(self,store,binary='/opt/singlite/bin/sing-box',stats_binary='/opt/singlite/bin/singbox-stats',runner=None,clock=None,listen=None):
        self.store=store;self.binary=binary;self.stats_binary=stats_binary
        self.runner=runner or subprocess.run;self.clock=clock or time.monotonic
        self.root=store.root/'nodes';self.root.mkdir(mode=0o700,exist_ok=True)
        self.lock=threading.RLock();self.wake=threading.Event();self.stopping=threading.Event();self.thread=None
        self.workers={};self.force=False;self.last_error='';self.version='sing-box'
        self.listen=listen or self._listen_address()
        self.boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self._status={'version':self.version,'service':'inactive','accounting':'unavailable','ready':False,'error':'','lastSampleAt':None,'nodes':{}}
        try:
            result=self.run([self.binary,'version'])
            self.version=(result.stdout.splitlines() or ['sing-box'])[0][:120]
        except (OSError,subprocess.SubprocessError):pass
        # Adopt existing files so a failed previous shutdown cannot leave an orphan.
        for path in self.root.glob('*.json'):
            if re.fullmatch('[a-f0-9]{32}',path.stem) and not path.is_symlink():
                try:
                    config=json.loads(path.read_text())
                    address=config['experimental']['v2ray_api']['listen']
                    if not re.fullmatch(r'127\.0\.0\.1:[0-9]{1,5}',address):continue
                    port=int(address.rsplit(':',1)[1])
                    if 1<=port<=65535:self.workers[path.stem]=self._worker(path.stem,port)
                except (OSError,ValueError,KeyError,TypeError):continue

    @staticmethod
    def _listen_address():
        try:
            with socket.socket(socket.AF_INET6) as listener:listener.bind(('::',0))
            return '::'
        except OSError:return '0.0.0.0'

    def run(self,args,timeout=10,**kwargs):
        return self.runner(args,capture_output=True,text=True,timeout=timeout,check=False,**kwargs)

    def _worker(self,identifier,port):
        return {'id':identifier,'service':'singlite-node@'+identifier+'.service','path':self.root/(identifier+'.json'),
                'port':port,'active':False,'hash':'','attemptHash':'','attemptAt':-100.,'started':self.clock(),
                'healthy':0.,'sample':None,'suspended':False,'error':''}

    def _new_worker(self,identifier,excluded):
        for _ in range(128):
            with socket.socket() as listener:
                listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
            if port not in excluded and port not in {w['port'] for w in self.workers.values()}:
                return self._worker(identifier,port)
        raise RuntimeError('无法分配本机统计端口')

    def _snapshot(self,workers):
        if not workers:return {}
        result=self.run(['systemctl','show','--property=Id,MainPID,ActiveState',*[w['service'] for w in workers]],5)
        if result.returncode:raise RuntimeError('无法读取节点运行状态')
        states={}
        for block in result.stdout.strip().split('\n\n'):
            values=dict(line.split('=',1) for line in block.splitlines() if '=' in line)
            if values.get('Id'):states[values['Id']]=values
        return states

    def _identity(self,pid):
        if not pid.isdigit() or pid=='0':raise RuntimeError('节点未运行')
        ticks=Path('/proc/'+pid+'/stat').read_text().rsplit(')',1)[1].split()[19]
        return self.boot+':'+pid+':'+ticks

    @staticmethod
    def _counters(obj):
        if not isinstance(obj,dict) or 'error' in obj or not isinstance(obj.get('stat',[]),list):
            raise RuntimeError('节点统计不可用')
        raw={}
        for stat in obj.get('stat',[]):
            if not isinstance(stat,dict):raise RuntimeError('节点统计格式无效')
            match=re.fullmatch(r'user>>>([a-f0-9]{32})@singlite>>>traffic>>>(uplink|downlink)',str(stat.get('name','')))
            if not match:continue
            value=stat.get('value',0)
            if isinstance(value,bool) or not isinstance(value,(str,int)) or not re.fullmatch(r'\d+',str(value)) or int(value)>2**63-1:
                raise RuntimeError('节点统计格式无效')
            raw.setdefault(match[1],{})[match[2]]=int(value)
        return raw

    def collect(self):
        workers=list(self.workers.values())
        if not workers:return
        failures=[];targets={};identities={}
        before=self._snapshot(workers)
        for worker in workers:
            values=before.get(worker['service'],{})
            worker['active']=values.get('ActiveState')=='active' and values.get('MainPID','0')!='0'
            if not worker['active']:
                if worker['hash']:worker['error']='节点未保持运行，请检查端口冲突与服务日志'
                worker['hash']='';worker['healthy']=0
                continue
            try:
                identities[worker['id']]=self._identity(values['MainPID'])
                targets[worker['id']]='127.0.0.1:'+str(worker['port'])
            except (OSError,ValueError,IndexError,RuntimeError):failures.append(worker)
        if targets:
            try:
                result=self.run([self.stats_binary,'-batch'],5,input=json.dumps(targets))
                if result.returncode:raise RuntimeError('节点统计不可用')
                samples=json.loads(result.stdout)
                if not isinstance(samples,dict):raise RuntimeError('节点统计格式无效')
                after=self._snapshot(workers)
            except (OSError,ValueError,subprocess.SubprocessError,RuntimeError):
                samples={};after={}
            roll_periods=True
            for worker in workers:
                identifier=worker['id']
                if identifier not in targets:continue
                try:
                    values=after.get(worker['service'],{})
                    if values.get('ActiveState')!='active' or self._identity(values.get('MainPID','0'))!=identities[identifier]:
                        raise RuntimeError('采样期间节点已重启')
                    raw=self._counters(samples.get(identifier))
                    self.store.sample(raw,identities[identifier],identifier,roll_periods=roll_periods)
                    roll_periods=False
                    worker.update(healthy=self.clock(),sample=int(time.time()),suspended=False,error='')
                except (OSError,ValueError,IndexError,RuntimeError):failures.append(worker)
        for worker in failures:
            worker['error']='流量统计暂不可用'
            if self.clock()-(worker['healthy'] or worker['started'])>=5:worker['suspended']=True
        if failures:raise RuntimeError('部分节点统计暂不可用，请稍后重试')

    def _stop(self,worker):
        result=self.run(['systemctl','stop',worker['service']],15)
        if result.returncode:raise RuntimeError('无法停止该节点，请检查系统服务')
        worker.update(active=False,hash='',healthy=0)

    def _config(self,node,users,port):
        return render_singbox({'nodes':[node],'users':[user for user in users if node['id'] in user['nodeIds']]},self.listen,port)

    def _apply(self,worker,config):
        checksum=config_hash(config)
        if worker['active'] and worker['hash']==checksum and not self.force:return
        if not self.force and worker['attemptHash']==checksum and self.clock()-worker['attemptAt']<3:return
        worker.update(attemptHash=checksum,attemptAt=self.clock())
        fd,temporary=tempfile.mkstemp(prefix='.check-',suffix='.json',dir=self.root)
        try:
            os.fchmod(fd,0o600)
            with os.fdopen(fd,'w') as output:json.dump(config,output);output.flush();os.fsync(output.fileno())
            result=self.run([self.binary,'check','-c',temporary],15)
            if result.returncode:raise RuntimeError('配置校验失败，请检查节点参数')
            # HTTP changes may arrive while a slow check is running.
            latest=self.store.bundle()
            node=next((n for n in latest['nodes'] if n['id']==worker['id'] and any(n['id'] in u['nodeIds'] for u in latest['users'])),None)
            if node is None:self._stop(worker);return
            current=self._config(node,latest['users'],worker['port'])
            if worker['suspended']:current=render_singbox({'nodes':[],'users':[]},self.listen,worker['port'])
            if config_hash(current)!=checksum:self.wake.set();return
            os.replace(temporary,worker['path'])
            result=self.run(['systemctl','restart',worker['service']],20)
            if result.returncode:raise RuntimeError('启动失败，请检查端口是否占用')
            worker.update(active=True,hash=checksum,healthy=0,started=self.clock(),error='')
        except (OSError,subprocess.SubprocessError,RuntimeError):
            self._stop(worker)
            raise
        finally:
            if os.path.exists(temporary):os.unlink(temporary)

    def reconcile(self):
        bundle=self.store.bundle()
        desired={node['id']:node for node in bundle['nodes'] if any(node['id'] in user['nodeIds'] for user in bundle['users'])}
        for identifier,worker in list(self.workers.items()):
            if identifier not in desired:
                try:
                    self._stop(worker);worker['path'].unlink(missing_ok=True)
                    self.store.forget_scope(identifier);del self.workers[identifier]
                except (OSError,subprocess.SubprocessError,RuntimeError):worker['error']='节点停止失败，请查看日志'
        for identifier,node in desired.items():
            try:
                if identifier not in self.workers:
                    self.workers[identifier]=self._new_worker(identifier,{n['port'] for n in bundle['nodes']})
                worker=self.workers[identifier]
                config=self._config(node,bundle['users'],worker['port'])
                if worker['suspended']:config=render_singbox({'nodes':[],'users':[]},self.listen,worker['port'])
                # A final collection may change quotas; desired is built after collect.
                self._apply(worker,config)
            except (OSError,subprocess.SubprocessError,RuntimeError) as error:
                if identifier in self.workers:
                    self.workers[identifier]['error']=str(error) if isinstance(error,RuntimeError) else '节点管理异常，请检查服务日志'
        self.force=False
        self._publish()

    def _publish(self):
        bundle=self.store.bundle();states={}
        expected={node['id']:node for node in bundle['nodes'] if any(node['id'] in user['nodeIds'] for user in bundle['users'])}
        for identifier,node in expected.items():
            worker=self.workers.get(identifier)
            healthy=bool(worker and worker['healthy'] and self.clock()-worker['healthy']<5)
            ready=bool(worker and worker['active'] and healthy and not worker['suspended'] and worker['hash']==config_hash(self._config(node,bundle['users'],worker['port'])))
            states[identifier]={'ready':ready,'accounting':'ok' if healthy else 'unavailable','error':worker['error'] if worker else '',
                                'service':'active' if worker and worker['active'] else 'inactive','lastSampleAt':worker['sample'] if worker else None}
        for identifier,worker in self.workers.items():
            if identifier not in states and worker['error']:states[identifier]={'ready':False,'accounting':'unavailable','error':worker['error'],'service':'active' if worker['active'] else 'inactive','lastSampleAt':worker['sample']}
        errors=[(expected.get(identifier,{}).get('name','节点')+'：'+value['error']) for identifier,value in states.items() if value['error']]
        self._status={'version':self.version,'service':'active' if any(w['active'] for w in self.workers.values()) else 'inactive',
                      'accounting':'ok' if all(value['accounting']=='ok' for value in states.values()) else 'unavailable',
                      'ready':self.store.running() and all(value['ready'] for value in states.values()),
                      'error':'；'.join(errors[:3]) or self.last_error,'lastSampleAt':max((w['sample'] or 0 for w in self.workers.values()),default=0) or None,'nodes':states}

    def tick(self):
        with self.lock:
            try:self.collect();self.last_error=''
            except (OSError,ValueError,subprocess.SubprocessError,RuntimeError):
                for worker in self.workers.values():
                    if self.clock()-(worker['healthy'] or worker['started'])>=5:worker['suspended']=True
            self.reconcile()

    def start(self):
        if self.thread:return
        self.thread=threading.Thread(target=self.loop,name='singlite-nodes',daemon=True);self.thread.start()

    def loop(self):
        try:
            while not self.stopping.is_set():
                started=self.clock()
                try:self.tick()
                except Exception:
                    self.last_error='节点管理异常，请检查磁盘、权限与服务日志'
                    self._publish()
                self.wake.wait(max(.1,1-(self.clock()-started)));self.wake.clear()
        finally:
            with self.lock:
                try:self.collect()
                except Exception:pass
                services=[w['service'] for w in self.workers.values()]
                if services:
                    try:self.run(['systemctl','stop',*services],45)
                    except Exception:pass

    def close(self):
        self.stopping.set();self.wake.set()
        if self.thread:self.thread.join(timeout=55)

    def status(self):
        # No systemctl, RPC or runtime lock on HTTP requests.
        return self._status

    def logs(self):
        result=self.run(['journalctl','-u','singlite-node@*.service','-u','singlite-core','-n','100','--no-pager','-o','short-iso'],5)
        if result.returncode:return {'lines':['暂时无法读取节点日志，请在 VPS 查看 journalctl -u \'singlite-node@*\'']}
        content=result.stdout[-30000:]
        with self.store.lock:
            for node in self.store._all('nodes'):
                for key in ('privateKey','serverKey','shortId','publicKey'):
                    if node.get(key):content=content.replace(node[key],'[已隐藏]')
            for user in self.store._all('users'):
                for key in ('uuid','psk128','psk256','token'):content=content.replace(user[key],'[已隐藏]')
        content=re.sub(r'(?:ss|vless)://\S+','[节点链接已隐藏]',content)
        content=re.sub(r'\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b','[已隐藏]',content)
        return {'lines':content.splitlines()[-100:]}
