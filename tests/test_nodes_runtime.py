"""Independent lifecycle, failure isolation and transactional multi-node usage."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
import control,core,panel


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=control.Controller(self.tmp.name,panel.hostname,'127.0.0.1');self.addCleanup(self.store.db.close)
        self.a=self.store.nodes_save({'name':'A','protocol':'shadowsocks','port':14000})['node']
        self.user=self.store.users_save({'name':'Me','quotaGB':0})['user'];self.uid=self.user['id']
        self.now=100.;self.serial=10;self.services={};self.counts={};self.calls=[];self.fail_stats=set();self.fail_ports=set();self.fail_check=set()
        self.runtime=core.Runtime(self.store,runner=self.run_command,clock=lambda:self.now,listen='127.0.0.1')
        self.runtime._identity=lambda pid:'boot:'+pid if pid!='0' else self.inactive()

    def inactive(self):raise RuntimeError('inactive')

    def run_command(self,args,**kwargs):
        self.calls.append(args);out='';code=0
        if args[0]=='systemctl':
            if args[1]=='show':
                blocks=[]
                for service in args[3:]:
                    pid=self.services.get(service,0)
                    blocks.append('Id='+service+'\nMainPID='+str(pid)+'\nActiveState='+('active' if pid else 'inactive'))
                out='\n\n'.join(blocks)
            elif args[1]=='restart':
                service=args[2];identifier=service.split('@')[1].split('.')[0]
                config=json.loads((self.runtime.root/(identifier+'.json')).read_text())
                if any(n['listen_port'] in self.fail_ports for n in config['inbounds']):code=1
                else:
                    self.serial+=1;self.services[service]=self.serial;self.counts[identifier]=(0,0)
            elif args[1]=='stop':
                for service in args[2:]:self.services[service]=0
        elif args[1:2]==['version']:out='sing-box version 1.14.3-singlite'
        elif args[1:2]==['check']:
            config=json.loads(Path(args[-1]).read_text())
            code=int(any(n['tag'].removeprefix('node-') in self.fail_check for n in config['inbounds']))
        elif '-batch' in args:
            results={}
            for identifier in json.loads(kwargs['input']):
                if identifier in self.fail_stats:results[identifier]={'error':'unavailable'}
                else:results[identifier]={'stat':[{'name':'user>>>'+self.uid+'@singlite>>>traffic>>>'+d,'value':str(v)} for d,v in zip(('uplink','downlink'),self.counts.get(identifier,(0,0)))]}
            out=json.dumps(results)
        return subprocess.CompletedProcess(args,code,out,'')

    def tick(self):
        self.now+=1;self.runtime.tick()

    def ready(self):self.tick();self.tick();self.assertTrue(self.runtime.status()['ready'])
    def pid(self,node):return self.services.get('singlite-node@'+node['id']+'.service',0)
    def used(self):return self.store.state()['users'][0]['usedBytes']
    def second(self,port=14001):return self.store.nodes_save({'name':'B','protocol':'shadowsocks','port':port})['node']

    def test_repeated_add_delete_preserves_other_process_and_configuration(self):
        self.ready();pid=self.pid(self.a);original=(self.runtime.root/(self.a['id']+'.json')).read_bytes()
        for index in range(20):
            node=self.second(14100+index);self.tick();self.assertTrue(self.pid(node));self.assertEqual(self.pid(self.a),pid)
            self.store.nodes_delete(node['id']);self.tick();self.assertFalse(self.pid(node));self.assertEqual(self.pid(self.a),pid)
            self.assertFalse((self.runtime.root/(node['id']+'.json')).exists())
        self.assertEqual((self.runtime.root/(self.a['id']+'.json')).read_bytes(),original)
        self.assertFalse(any(args[:3]==['systemctl','restart','singlite-core'] for args in self.calls))
        self.assertEqual(len(self.runtime.workers),1)

    def test_metadata_and_export_entry_changes_do_not_restart_nodes(self):
        self.ready();pid=self.pid(self.a)
        self.store.nodes_save({'name':'Renamed','connectHost':'relay.example.com','connectPort':443},self.a['id'])
        self.store.settings_save({'publicHost':'192.0.2.4'});self.tick()
        self.assertEqual(self.pid(self.a),pid)

    def test_new_node_port_failure_and_invalid_config_are_isolated(self):
        self.ready();pid=self.pid(self.a);node=self.second();self.fail_ports.add(node['port']);self.tick()
        self.assertEqual(self.pid(self.a),pid);self.assertTrue(self.runtime.status()['nodes'][self.a['id']]['ready'])
        self.assertIn('启动失败',self.runtime.status()['nodes'][node['id']]['error'])
        self.fail_ports.clear();self.now+=4;self.tick();self.tick();self.assertTrue(self.pid(node))
        self.fail_check.add(node['id']);self.store.nodes_save({'port':14200},node['id']);self.tick()
        self.assertFalse(self.pid(node));self.assertEqual(self.pid(self.a),pid)
        self.assertIn('校验失败',self.runtime.status()['nodes'][node['id']]['error'])

    def test_per_node_counter_generation_reset_and_global_quota(self):
        node=self.second();self.ready()
        self.counts[self.a['id']]=(100,200);self.counts[node['id']]=(300,400);self.tick();self.assertEqual(self.used(),1000)
        changes=self.store.db.total_changes;self.tick();self.assertEqual(self.used(),1000);self.assertEqual(self.store.db.total_changes,changes)
        self.store.users_reset(self.uid);self.tick();self.assertEqual(self.used(),0)
        self.counts[self.a['id']]=(110,220);self.counts[node['id']]=(330,440);self.tick();self.assertEqual(self.used(),100)
        self.store.nodes_save({'port':14200},node['id']);self.tick();self.tick();self.assertEqual(self.used(),100)
        self.counts[node['id']]=(5,10);self.tick();self.assertEqual(self.used(),115)
        self.store.users_save({'quotaBytes':120},self.uid);self.counts[self.a['id']]=(120,220);self.tick()
        self.assertEqual(self.used(),125);self.assertEqual(self.runtime.workers,{})
        self.assertFalse(self.pid(self.a));self.assertFalse(self.pid(node))

    def test_statistics_failure_pauses_only_affected_node_and_recovers(self):
        node=self.second();self.ready();a_pid=self.pid(self.a)
        self.fail_stats.add(node['id']);self.now+=6;self.tick()
        worker=self.runtime.workers[node['id']]
        self.assertTrue(worker['suspended']);self.assertEqual(json.loads(worker['path'].read_text())['inbounds'],[])
        self.assertEqual(self.pid(self.a),a_pid);self.assertTrue(self.runtime.status()['nodes'][self.a['id']]['ready'])
        paused_pid=self.pid(node);self.tick();self.assertEqual(self.pid(node),paused_pid)
        self.fail_stats.clear();self.tick();self.tick()
        self.assertTrue(self.runtime.status()['ready']);self.assertEqual(self.pid(self.a),a_pid)
        self.assertEqual(len(json.loads(worker['path'].read_text())['inbounds']),1)

    def test_no_users_no_process_and_manual_pause_resume(self):
        self.store.users_save({'enabled':False},self.uid);self.tick();self.assertEqual(self.runtime.workers,{})
        self.assertTrue(self.runtime.status()['ready'])
        self.store.users_save({'enabled':True},self.uid);self.ready()
        self.store.running(False);self.tick();self.assertEqual(self.runtime.workers,{})
        self.store.running(True);self.ready()

    def test_permissions_and_expiry_only_stop_required_nodes(self):
        node=self.second();self.ready();pid=self.pid(self.a)
        self.store.users_save({'nodeIds':[self.a['id']]},self.uid);self.tick()
        self.assertEqual(self.pid(self.a),pid);self.assertFalse(self.pid(node))
        self.store.users_save({'expiresAt':1},self.uid);self.tick();self.assertFalse(self.pid(self.a))

    def test_status_uses_cached_snapshot_without_rpc_or_worker_lock(self):
        self.ready();before=len(self.calls)
        for _ in range(100):self.assertTrue(self.runtime.status()['ready'])
        self.assertEqual(len(self.calls),before)

    def test_batch_rollover_scan_happens_once_for_multiple_nodes(self):
        self.second();self.ready()
        with mock.patch.object(self.store,'_roll_periods',wraps=self.store._roll_periods) as rollover:
            self.runtime.collect()
        self.assertEqual(rollover.call_count,1)

    def test_delete_during_configuration_check_cannot_start_stale_node(self):
        self.ready();pid=self.pid(self.a);node=self.second();original=self.runtime.runner
        def deleting(args,**kwargs):
            result=original(args,**kwargs)
            if args[1:2]==['check']:
                config=json.loads(Path(args[-1]).read_text())
                if any(item['tag']=='node-'+node['id'] for item in config['inbounds']):self.store.nodes_delete(node['id'])
            return result
        self.runtime.runner=deleting;self.tick();self.tick()
        self.assertFalse(self.pid(node));self.assertEqual(self.pid(self.a),pid)

    def test_invalid_counters_and_process_changed_during_sample(self):
        self.ready()
        for obj in ({'stat':[{'name':'user>>>'+self.uid+'@singlite>>>traffic>>>uplink','value':v}]} for v in (-1,True,'1.5',2**63)):
            with self.assertRaises(RuntimeError):self.runtime._counters(obj)
        before=self.used();actual=self.runtime._snapshot;calls=0
        def changing(workers):
            nonlocal calls
            result=actual(workers);calls+=1
            if calls==2:
                for state in result.values():state['MainPID']='999'
            return result
        self.counts[self.a['id']]=(100,200)
        with mock.patch.object(self.runtime,'_snapshot',side_effect=changing),self.assertRaises(RuntimeError):self.runtime.collect()
        self.assertEqual(self.used(),before)


class AccountingMigrationTests(unittest.TestCase):
    def test_legacy_cursor_migration_preserves_totals_and_independent_restarts(self):
        with tempfile.TemporaryDirectory() as folder:
            c=control.Controller(folder,panel.hostname);uid=c.users_save({'name':'Me'})['user']['id']
            c.sample({uid:{'uplink':100,'downlink':200}},'old')
            c.db.execute('ALTER TABLE counters RENAME TO newer')
            c.db.execute('CREATE TABLE counters(user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,generation TEXT NOT NULL,up INTEGER NOT NULL,down INTEGER NOT NULL)')
            c.db.execute('INSERT INTO counters SELECT user_id,generation,up,down FROM newer');c.db.execute('DROP TABLE newer');c.db.commit();c.db.close()
            c=control.Controller(folder,panel.hostname)
            try:
                self.assertIn('scope',{row[1] for row in c.db.execute('PRAGMA table_info(counters)')})
                self.assertEqual(c.state()['users'][0]['usedBytes'],300)
                c.sample({uid:{'uplink':100,'downlink':200}},'old');self.assertEqual(c.state()['users'][0]['usedBytes'],300)
                c.sample({uid:{'uplink':10,'downlink':20}},'new','node-a')
                c.sample({uid:{'uplink':30,'downlink':40}},'new','node-b')
                c.sample({uid:{'uplink':10,'downlink':20}},'new','node-a')
                self.assertEqual(c.state()['users'][0]['usedBytes'],400)
                before=c.db.total_changes;c.sample({uid:{'uplink':10,'downlink':20}},'new','node-a');self.assertEqual(c.db.total_changes,before)
            finally:c.db.close()


if __name__=='__main__':unittest.main()
