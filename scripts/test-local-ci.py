#!/usr/bin/env python3
"""Synthetic safety checks for the canonical local CI runner.

Private temporary HOME/trust and fake controllers are fixture-only. These tests
require genuine outer admission; their synthetic receipts are never host proof.
"""
import json
import datetime
from unittest.mock import patch
import os
import signal
import time
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class RunnerSafety(unittest.TestCase):
    repository = 'EdeAbreu23/unraid-templates'
    assets = ('local-ci.py', 'local_ci_evidence.py', 'local-ci-accept.py', 'local-ci-merge.py')
    resources = ('admit.py', 'leases.py', 'observe.py', 'platform_adapter.py',
                 'linux_process.py', 'ci_reservation.py', 'inventory_scope.py',
                 'mac_process.py', 'mac_ancestry.py')

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        home = self.base / 'isolated-home'; home.mkdir(mode=0o700)
        isolated = {'PATH': os.environ.get('PATH', ''), 'HOME': str(home),
                    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
                    'GIT_TERMINAL_PROMPT': '0', 'PYTHONDONTWRITEBYTECODE': '1'}
        environment = patch.dict(os.environ, isolated, clear=True)
        environment.start(); self.addCleanup(environment.stop)
        self.root = self.base / 'repo'; (self.root / 'scripts').mkdir(parents=True)
        for name in self.assets:
            shutil.copy(Path(__file__).with_name(name), self.root / 'scripts' / name)
        for args in [['init','-q'], ['config','user.name','Synthetic CI'],
                     ['config','user.email','ci@example.invalid'],
                     ['remote','add','origin','https://github.com/' + self.repository + '.git']]:
            subprocess.run(['git',*args],cwd=self.root,check=True,stdout=subprocess.DEVNULL)
        self.trust = home / '.config/SlateForge/local-ci'
        self.task = self.trust / 'owner-reviewed/synthetic-task'
        self.run = self.task / 'run'
        self.run.mkdir(parents=True, mode=0o700)
        for directory in (self.trust, self.task.parent, self.task, self.run):
            directory.chmod(0o700)
        self.approval = self.run / 'authorization.json'
        self.out = self.run / 'evidence'
        self.controls = self.base / 'fake-controllers'
        resources = self.controls / 'scripts/resources'; resources.mkdir(parents=True)
        # These bytes are pinned only by this temporary synthetic policy.
        for name in self.resources:
            (resources / name).write_text('# Synthetic controller fixture only.\n')
        (resources / 'ci_reservation.py').write_text(
            'class Reservation:\n'
            ' def __init__(self, *args):\n'
            '  self.binding={"lease_id":"' + 'a'*32 + '","owner":{"pid":101,"start":"1:0","uid":501},"boot_id":"1:0","platform":"synthetic","host_id":"synthetic"}\n'
            ' def tick(self, **kwargs): pass\n'
            ' def before_stage(self, **kwargs): pass\n'
            ' def release(self, verified): return {"state":"RELEASED" if verified else "RECOVERY_REQUIRED"}\n')

    @staticmethod
    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def private_json(path, value):
        path.write_text(json.dumps(value) + '\n'); path.chmod(0o600)

    def prepare(self, spec, dirty=False):
        spec = dict(spec, schema=1, repository=self.repository)
        spec['steps'] = list(spec.get('steps', []))
        if spec.get('cleanup'):
            spec['resource_lifecycle'] = 'cleanup-and-verify'
            spec['resource_verification'] = [{'name':'verify-fixture-resources',
                'command':[sys.executable,'-c',
                    'from pathlib import Path; assert not any((Path('+repr(str(self.base))+')/p).exists() for p in ("survived","startup-survivor","teardown-survivor"))']}]
        else:
            spec['resource_lifecycle'] = 'process-groups-only'
        if not spec['steps'] and not spec.get('cleanup'):
            spec['steps'] = [{'name':'fixture-noop','command':[sys.executable,'-c','pass']}]
        (self.root/'local-ci.json').write_text(json.dumps(spec))
        subprocess.run(['git','add','.'],cwd=self.root,check=True)
        subprocess.run(['git','commit','-qm','Synthetic fixture'],cwd=self.root,check=True)
        head = subprocess.check_output(['git','rev-parse','HEAD'],cwd=self.root,text=True).strip()
        now = datetime.datetime.now(datetime.timezone.utc)
        issued = (now-datetime.timedelta(minutes=1)).isoformat()
        contract = 'owner-reviewed-v1'
        host = {'host_id':'synthetic','platform':'synthetic','boot_id':'1:0'}
        event = self.task/'owner-approval-event.json'
        self.private_json(event, {'actor':'Elvis','source':'authenticated-owner-message',
            'message':'SYNTHETIC fixture only; no production owner authorization',
            'session_id':'synthetic-owner'})
        task = {'contract':contract,'task_id':'synthetic-task','repository':self.repository,
            'checkout':str(self.root),'base':'b'*40,'authorized_host':host,
            'scope':'bounded-local-ci-task','allow_bounded_runs':True,'issued_at':issued,
            'owner_event_sha256':self.digest(event)}
        self.private_json(self.task/'approval.json',task)
        support = {name:self.digest(self.root/'scripts'/name) for name in self.assets[1:]}
        resources = {name:self.digest(self.controls/'scripts/resources'/name) for name in self.resources}
        tools = [{'command':[sys.executable,'--version'],
                  'expected_output':subprocess.check_output([sys.executable,'--version'],text=True).strip()}]
        project = {'runner_sha256':[self.digest(self.root/'scripts/local-ci.py')],
            'manifest_sha256':[self.digest(self.root/'local-ci.json')],
            'support_sha256':support,'resource_sha256':resources,'tools':tools,
            'owner_task_approval_sha256':self.digest(self.task/'approval.json')}
        self.private_json(self.trust/'trust.json',{'schema':3,'contract':contract,
            'repositories':{self.repository:project}})
        self.private_json(self.approval,{'contract':contract,
            'authenticity':'owner-reviewed; NOT cryptographically authenticated',
            'task_id':'synthetic-task','run_id':'synthetic-run','repository':self.repository,
            'commit':head,'candidate':None,'base':'b'*40,'scope':'local-ci',
            'stages':[step['name'] for step in spec['steps']+spec.get('cleanup',[])+spec.get('resource_verification',[])],
            'issued_at':issued,'expires_at':(now+datetime.timedelta(hours=1)).isoformat(),
            'authorized_host':host,'manifest_sha256':project['manifest_sha256'][0],
            'runner_sha256':project['runner_sha256'][0],'support_sha256':support,
            'resource_sha256':resources,'tools':tools})
        if dirty: (self.root/'uncommitted').write_text('preserve')
        runner = self.root/'scripts/local-ci.py'
        return [str(runner),'--report-dir',str(self.out),'--authorization',str(self.approval),
                '--resource-controls',str(self.controls),'--memory-gib','0.25',
                '--output-gib','0.01','--base','b'*40]

    def invocation(self, argv, injection=''):
        runner = self.root/'scripts/local-ci.py'
        # Fixed trust remains fixed in production. Only this isolated fixture
        # child imports the copy with the fixed trust location in temporary HOME.
        wrapper = ('import sys,runpy\nsys.path.insert(0,' + repr(str(runner.parent)) + ')\n'
                   + injection + '\nsys.argv=' + repr(argv) + '\n'
                   + 'runpy.run_path(' + repr(str(runner)) + ',run_name="__main__")')
        return [sys.executable,'-c',wrapper]

    def run_manifest(self,spec,dirty=False):
        argv = self.prepare(spec,dirty)
        result = subprocess.run(self.invocation(argv),capture_output=True,text=True,timeout=30)
        report = json.loads((self.out/'report.json').read_text()) if (self.out/'report.json').exists() else None
        return result,report
    def test_dirty_tree_refuses_execution_and_preserves_input(self):
        result,r=self.run_manifest({'steps':[{'name':'must-not-run','command':[sys.executable,'-c','raise Exception("executed")']}]},True)
        self.assertNotEqual(result.returncode,0);self.assertIsNone(r)
        self.assertIn('dirty source', result.stderr)
        self.assertFalse(self.out.exists())
        self.assertEqual((self.root/'uncommitted').read_text(),'preserve')
    def test_ignored_private_configuration_refuses_before_execution(self):
        (self.root/'.gitignore').write_text('.env\nappsettings.Production.json\n')
        subprocess.run(['git','add','.gitignore'],cwd=self.root,check=True)
        for name in ['.env','appsettings.Production.json']:
            (self.root/name).write_text('synthetic-private-sentinel')
        result,r=self.run_manifest({'steps':[{'name':'must-not-run','command':[sys.executable,'-c','raise Exception("executed")']}]})
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(r['source_status'],'')
        self.assertEqual(r['steps'],[])
        self.assertEqual(sorted(r['refused_private_input_paths']),['.env','appsettings.Production.json'])
        self.assertEqual((self.root/'.env').read_text(),'synthetic-private-sentinel')
    def test_failure_blocks_dependants_but_runs_independent_stage_and_cleanup(self):
        result,r=self.run_manifest({'steps':[{'name':'fail','command':[sys.executable,'-c','raise SystemExit(7)']},{'name':'blocked','command':['not-a-command'],'requires':['fail']},{'name':'independent','command':[sys.executable,'-c','print("static success")']}],'cleanup':[{'name':'cleanup','command':[sys.executable,'-c','print("cleanup")']}]})
        self.assertNotEqual(result.returncode,0)
        self.assertEqual([s['status'] for s in r['steps']],['FAIL','NOT_RUN','PASS','PASS','PASS'])
        self.assertEqual(r['steps'][0]['exit_code'],7)
    def test_timed_out_child_group_stops_before_cleanup(self):
        marker=str(self.base/'survived'); child='import time,pathlib; time.sleep(2); pathlib.Path('+repr(marker)+').write_text("survived")'; code='import subprocess,sys,time; subprocess.Popen([sys.executable,"-c",'+repr(child)+']); time.sleep(60)'
        result,r=self.run_manifest({'steps':[{'name':'timeout','command':[sys.executable,'-c',code],'timeout_seconds':0.1}], 'cleanup':[{'name':'cleanup','command':[sys.executable,'-c','import time,pathlib; time.sleep(2.2); assert not pathlib.Path('+repr(marker)+').exists()']}]})
        self.assertNotEqual(result.returncode,0)
        self.assertTrue(r['steps'][0]['timed_out'])
        self.assertEqual(r['steps'][1]['status'],'PASS')
    def test_original_advisory_failure_is_not_misreported_as_a_pass(self):
        result,r=self.run_manifest({'steps':[{'name':'informational-audit','command':[sys.executable,'-c','raise SystemExit(1)'],'advisory':True}]})
        self.assertEqual(result.returncode,0)
        self.assertEqual(r['status'],'PASS_WITH_ADVISORIES')
        self.assertEqual(r['steps'][0]['status'],'ADVISORY_FAIL')
        self.assertEqual(r['steps'][0]['exit_code'],1)
        self.assertEqual(r['advisory_failures'],['informational-audit'])
    def test_sigterm_stops_descendants_finalizes_failure_and_runs_cleanup(self):
        ready = self.base/'ready'
        survived = self.base/'survived'
        cleanup = self.base/'cleanup'
        child = 'import time,pathlib; time.sleep(2); pathlib.Path('+repr(str(survived))+').write_text("survived")'
        command = 'import subprocess,sys,pathlib,time; subprocess.Popen([sys.executable,"-c",'+repr(child)+']); pathlib.Path('+repr(str(ready))+').touch(); time.sleep(60)'
        spec = {'steps':[{'name':'interrupted','command':[sys.executable,'-c',command]}],
                'cleanup':[{'name':'cleanup','command':[sys.executable,'-c','import time,pathlib; time.sleep(2.2); assert not pathlib.Path('+repr(str(survived))+').exists(); pathlib.Path('+repr(str(cleanup))+').touch()']}]}
        argv = self.prepare(spec)
        out = self.out
        process = subprocess.Popen(self.invocation(argv),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            deadline = time.monotonic()+10
            while not ready.exists() and process.poll() is None and time.monotonic()<deadline:
                time.sleep(0.02)
            self.assertTrue(ready.exists(), 'Stage did not start')
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=15)
            self.assertNotEqual(process.returncode,0,(stdout,stderr))
            report = json.loads((out/'report.json').read_text())
            self.assertEqual(report['status'],'FAIL')
            self.assertEqual(report['steps'][0]['status'],'FAIL')
            self.assertIsNotNone(report['steps'][0]['exit_code'])
            self.assertEqual(report['steps'][1]['status'],'PASS')
            self.assertTrue(cleanup.exists())
            self.assertFalse(survived.exists())
            self.assertIn('SIGTERM',report['failure'])
        finally:
            if process.poll() is None:
                process.kill(); process.communicate()

    def test_sigterm_during_cleanup_finishes_all_cleanup_and_finalizes_failure(self):
        ready = self.base/'cleanup-ready'
        completed = self.base/'cleanup-completed'
        spec = {'steps':[], 'cleanup':[
            {'name':'first','command':[sys.executable,'-c','import pathlib,time; pathlib.Path('+repr(str(ready))+').touch(); time.sleep(0.3)']},
            {'name':'second','command':[sys.executable,'-c','import pathlib; pathlib.Path('+repr(str(completed))+').touch()']}]}
        argv = self.prepare(spec)
        out = self.out
        process = subprocess.Popen(self.invocation(argv),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            deadline = time.monotonic()+10
            while not ready.exists() and process.poll() is None and time.monotonic()<deadline:
                time.sleep(0.01)
            self.assertTrue(ready.exists(), 'Cleanup did not start')
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=15)
            self.assertNotEqual(process.returncode,0,(stdout,stderr))
            report = json.loads((out/'report.json').read_text())
            self.assertEqual(report['status'],'FAIL')
            self.assertEqual([step['status'] for step in report['steps']],['PASS','PASS','PASS'])
            self.assertTrue(completed.exists())
            self.assertIn('SIGTERM',report['failure'])
            self.assertIn('finished_at',report)
        finally:
            if process.poll() is None:
                process.kill(); process.communicate()

    def test_repository_evidence_rejects_remote_credentials_without_recording_them(self):
        subprocess.run(['git','remote','set-url','origin','https://synthetic-user:synthetic-token@example.invalid/repo?synthetic-query#synthetic-fragment'],cwd=self.root,check=True)
        result, report = self.run_manifest({'steps':[]})
        self.assertNotEqual(result.returncode,0)
        self.assertIsNone(report)
        self.assertFalse(self.out.exists())
        self.assertIn('repository identity mismatch',result.stderr)
        evidence = result.stdout+result.stderr
        for value in ['synthetic-user','synthetic-token','synthetic-query','synthetic-fragment']:
            self.assertNotIn(value,evidence)

    def test_repository_evidence_requires_an_exact_origin_remote(self):
        subprocess.run(['git','remote','remove','origin'],cwd=self.root,check=True)
        result, report = self.run_manifest({'steps':[]})
        self.assertNotEqual(result.returncode,0)
        self.assertIsNone(report)
        self.assertFalse(self.out.exists())

    def test_sigterm_during_process_start_cannot_orphan_stage_or_lose_report(self):
        marker = self.base/'startup-survivor'
        spec = {'steps':[{'name':'startup','command':[sys.executable,'-c','import time,pathlib; time.sleep(0.5); pathlib.Path('+repr(str(marker))+').touch(); time.sleep(60)']}]}
        argv = self.prepare(spec)
        out = self.out
        runner = self.root/'scripts/local-ci.py'
        # Inject TERM after the OS child exists but before Popen returns its handle.
        injection = ('import os,signal,subprocess; real=subprocess.Popen\n'
                     'def start(*args,**kwargs):\n'
                     ' p=real(*args,**kwargs)\n'
                     ' if kwargs.get("start_new_session") and '+repr(str(marker))+' in str(args): os.kill(os.getpid(),signal.SIGTERM)\n'
                     ' return p\n'
                     'subprocess.Popen=start\n')
        result = subprocess.run(self.invocation(argv,injection),capture_output=True,text=True,timeout=15)
        self.assertNotEqual(result.returncode,0)
        report = json.loads((out/'report.json').read_text())
        self.assertEqual(report['status'],'FAIL')
        self.assertEqual(report['steps'][0]['status'],'FAIL')
        self.assertIsNotNone(report['steps'][0]['exit_code'])
        self.assertIn('finished_at',report)
        self.assertNotIn('UnboundLocalError',result.stderr)
        time.sleep(0.7)
        self.assertFalse(marker.exists())

    def test_sigterm_during_group_teardown_cannot_skip_kill_escalation(self):
        ready = self.base/'descendant-ready'
        marker = self.base/'teardown-survivor'
        child = 'import signal,pathlib,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); pathlib.Path('+repr(str(ready))+').touch(); time.sleep(2); pathlib.Path('+repr(str(marker))+').touch(); time.sleep(60)'
        parent = 'import subprocess,sys,pathlib,time; subprocess.Popen([sys.executable,"-c",'+repr(child)+']); ready=pathlib.Path('+repr(str(ready))+')\nwhile not ready.exists(): time.sleep(0.01)'
        spec = {'steps':[{'name':'teardown','command':[sys.executable,'-c',parent]}]}
        argv = self.prepare(spec)
        out = self.out
        runner = self.root/'scripts/local-ci.py'
        injection = ('import os,signal; from pathlib import Path; real=os.killpg; sent=False\n'
                     'def stop(pid,sig):\n'
                     ' global sent\n'
                     ' result=real(pid,sig)\n'
                     ' if sig==signal.SIGTERM and not sent and Path('+repr(str(ready))+').exists(): sent=True; os.kill(os.getpid(),signal.SIGTERM)\n'
                     ' return result\n'
                     'os.killpg=stop\n')
        result = subprocess.run(self.invocation(argv,injection),capture_output=True,text=True,timeout=15)
        self.assertNotEqual(result.returncode,0)
        report = json.loads((out/'report.json').read_text())
        self.assertEqual(report['status'],'FAIL')
        self.assertEqual(report['steps'][0]['status'],'FAIL')
        self.assertIn('finished_at',report)
        time.sleep(2.2)
        self.assertFalse(marker.exists())

    def test_committed_whitespace_is_rejected_without_origin_or_dirty_files(self):
        (self.root/'committed.txt').write_text('synthetic trailing whitespace \n')
        subprocess.run(['git','add','committed.txt'],cwd=self.root,check=True)
        # The fixture has no origin/main ref. Canonical authorization now
        # requires an exact origin URL before the committed-tree check runs.
        result, report = self.run_manifest({'steps':[{'name':'whitespace','command':['git','diff','--check','4b825dc642cb6eb9a060e54bf8d69288fbee4904','HEAD']}]})
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(report['source_status'],'')
        self.assertEqual(report['status'],'FAIL')
        self.assertEqual(report['steps'][0]['status'],'FAIL')

    def test_wrong_tool_version_fails_closed(self):
        result,r=self.run_manifest({'steps':[{'name':'pin','command':[sys.executable,'-c','print("wrong")'],'expected_output':'right'}]})
        self.assertNotEqual(result.returncode,0);self.assertEqual(r['status'],'FAIL')
    def test_exact_clean_commit_pass_and_no_github_token_in_environment(self):
        os.environ['GITHUB_TOKEN'] = 'synthetic-token-must-not-pass-to-stages'
        result,r=self.run_manifest({'steps':[{'name':'safe','command':[sys.executable,'-c','import os; assert "GITHUB_TOKEN" not in os.environ; print("synthetic success")']}]})
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(r['status'],'PASS')
        self.assertEqual(r['commit'],r['final_commit']);self.assertEqual(r['final_source_status'],'')
        self.assertEqual(r['repository'],self.repository)
        self.assertEqual(r['authenticity'],'owner-reviewed; NOT cryptographically authenticated')


if __name__=='__main__':unittest.main()
