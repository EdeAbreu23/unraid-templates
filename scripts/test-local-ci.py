#!/usr/bin/env python3
"""Synthetic safety checks for the local CI evidence runner."""
import json
import os
import socket
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
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.base=Path(self.tmp.name)
        self.root=self.base/'repo';(self.root/'scripts').mkdir(parents=True)
        shutil.copy(Path(__file__).with_name('local-ci.py'),self.root/'scripts/local-ci.py')
        for args in [['init','-q'],['config','user.name','Synthetic CI'],['config','user.email','ci@example.invalid'],['remote','add','origin','https://example.invalid/synthetic']]:
            subprocess.run(['git',*args],cwd=self.root,check=True,stdout=subprocess.DEVNULL)
    def tearDown(self):
        self.tmp.cleanup()
    def run_manifest(self,spec,dirty=False):
        (self.root/'local-ci.json').write_text(json.dumps(spec))
        subprocess.run(['git','add','scripts/local-ci.py','local-ci.json'],cwd=self.root,check=True)
        subprocess.run(['git','commit','-qm','Synthetic fixture'],cwd=self.root,check=True)
        if dirty:(self.root/'uncommitted').write_text('preserve')
        out=self.base/'evidence'
        result=subprocess.run([sys.executable,str(self.root/'scripts/local-ci.py'),'--report-dir',str(out),'--authorization','Synthetic fixture only'],capture_output=True,text=True)
        self.assertTrue((out/'report.json').exists(),result.stderr)
        return result,json.loads((out/'report.json').read_text())
    def test_dirty_tree_refuses_execution_and_preserves_input(self):
        result,r=self.run_manifest({'steps':[{'name':'must-not-run','command':[sys.executable,'-c','raise Exception("executed")']}]},True)
        self.assertNotEqual(result.returncode,0);self.assertEqual(r['steps'],[])
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
        self.assertEqual([s['status'] for s in r['steps']],['FAIL','NOT_RUN','PASS','PASS'])
        self.assertEqual(r['steps'][0]['exit_code'],7)
    def test_timed_out_child_group_stops_before_cleanup(self):
        marker=str(self.base/'survived'); child='import time,pathlib; time.sleep(0.8); pathlib.Path('+repr(marker)+').write_text("survived")'; code='import subprocess,sys,time; subprocess.Popen([sys.executable,"-c",'+repr(child)+']); time.sleep(60)'
        result,r=self.run_manifest({'steps':[{'name':'timeout','command':[sys.executable,'-c',code],'timeout_seconds':0.1}], 'cleanup':[{'name':'cleanup','command':[sys.executable,'-c','import time,pathlib; time.sleep(1); assert not pathlib.Path('+repr(marker)+').exists()']}]})
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
        child = 'import time,pathlib; time.sleep(1); pathlib.Path('+repr(str(survived))+').write_text("survived")'
        command = 'import subprocess,sys,pathlib,time; subprocess.Popen([sys.executable,"-c",'+repr(child)+']); pathlib.Path('+repr(str(ready))+').touch(); time.sleep(60)'
        spec = {'steps':[{'name':'interrupted','command':[sys.executable,'-c',command]}],
                'cleanup':[{'name':'cleanup','command':[sys.executable,'-c','import time,pathlib; time.sleep(1.2); assert not pathlib.Path('+repr(str(survived))+').exists(); pathlib.Path('+repr(str(cleanup))+').touch()']}]}
        (self.root/'local-ci.json').write_text(json.dumps(spec))
        subprocess.run(['git','add','.'],cwd=self.root,check=True)
        subprocess.run(['git','commit','-qm','Synthetic signal fixture'],cwd=self.root,check=True)
        out = self.base/'evidence'
        process = subprocess.Popen([sys.executable,str(self.root/'scripts/local-ci.py'),'--report-dir',str(out),'--authorization','Synthetic fixture only'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
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
        (self.root/'local-ci.json').write_text(json.dumps(spec))
        subprocess.run(['git','add','.'],cwd=self.root,check=True)
        subprocess.run(['git','commit','-qm','Synthetic cleanup signal fixture'],cwd=self.root,check=True)
        out = self.base/'evidence'
        process = subprocess.Popen([sys.executable,str(self.root/'scripts/local-ci.py'),'--report-dir',str(out),'--authorization','Synthetic fixture only'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
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
            self.assertEqual([step['status'] for step in report['steps']],['PASS','PASS'])
            self.assertTrue(completed.exists())
            self.assertIn('during resource cleanup',report['failure'])
            self.assertIn('finished_at',report)
        finally:
            if process.poll() is None:
                process.kill(); process.communicate()

    def test_repository_evidence_never_reads_or_records_remote_credentials(self):
        subprocess.run(['git','remote','set-url','origin','https://synthetic-user:synthetic-token@example.invalid/repo?synthetic-query#synthetic-fragment'],cwd=self.root,check=True)
        result, report = self.run_manifest({'steps':[]})
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(report['repository'],'EdeAbreu23/unraid-templates')
        evidence = json.dumps(report)+result.stdout+result.stderr
        for value in ['synthetic-user','synthetic-token','synthetic-query','synthetic-fragment']:
            self.assertNotIn(value,evidence)

    def test_repository_evidence_does_not_require_an_origin_remote(self):
        subprocess.run(['git','remote','remove','origin'],cwd=self.root,check=True)
        result, report = self.run_manifest({'steps':[]})
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(report['repository'],'EdeAbreu23/unraid-templates')
        self.assertEqual(report['status'],'PASS')

    def test_sigterm_during_process_start_cannot_orphan_stage_or_lose_report(self):
        marker = self.base/'startup-survivor'
        spec = {'steps':[{'name':'startup','command':[sys.executable,'-c','import time,pathlib; time.sleep(0.5); pathlib.Path('+repr(str(marker))+').touch(); time.sleep(60)']}]}
        (self.root/'local-ci.json').write_text(json.dumps(spec))
        subprocess.run(['git','add','.'],cwd=self.root,check=True)
        subprocess.run(['git','commit','-qm','Synthetic startup signal fixture'],cwd=self.root,check=True)
        out = self.base/'evidence'
        runner = self.root/'scripts/local-ci.py'
        # Inject TERM after the OS child exists but before Popen returns its handle.
        wrapper = ('import os,signal,subprocess,runpy,sys; real=subprocess.Popen\n'
                   'def start(*args,**kwargs):\n'
                   ' p=real(*args,**kwargs)\n'
                   ' if kwargs.get("start_new_session"): os.kill(os.getpid(),signal.SIGTERM)\n'
                   ' return p\n'
                   'subprocess.Popen=start\n'
                   'sys.argv='+repr([str(runner),'--report-dir',str(out),'--authorization','Synthetic fixture only'])+'\n'
                   'runpy.run_path('+repr(str(runner))+',run_name="__main__")')
        result = subprocess.run([sys.executable,'-c',wrapper],capture_output=True,text=True,timeout=15)
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
        child = 'import signal,pathlib,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); pathlib.Path('+repr(str(ready))+').touch(); time.sleep(0.7); pathlib.Path('+repr(str(marker))+').touch(); time.sleep(60)'
        parent = 'import subprocess,sys,pathlib,time; subprocess.Popen([sys.executable,"-c",'+repr(child)+']); ready=pathlib.Path('+repr(str(ready))+')\nwhile not ready.exists(): time.sleep(0.01)'
        spec = {'steps':[{'name':'teardown','command':[sys.executable,'-c',parent]}]}
        (self.root/'local-ci.json').write_text(json.dumps(spec))
        subprocess.run(['git','add','.'],cwd=self.root,check=True)
        subprocess.run(['git','commit','-qm','Synthetic teardown signal fixture'],cwd=self.root,check=True)
        out = self.base/'evidence'
        runner = self.root/'scripts/local-ci.py'
        wrapper = ('import os,signal,runpy,sys; real=os.killpg; sent=False\n'
                   'def stop(pid,sig):\n'
                   ' global sent\n'
                   ' result=real(pid,sig)\n'
                   ' if sig==signal.SIGTERM and not sent: sent=True; os.kill(os.getpid(),signal.SIGTERM)\n'
                   ' return result\n'
                   'os.killpg=stop\n'
                   'sys.argv='+repr([str(runner),'--report-dir',str(out),'--authorization','Synthetic fixture only'])+'\n'
                   'runpy.run_path('+repr(str(runner))+',run_name="__main__")')
        result = subprocess.run([sys.executable,'-c',wrapper],capture_output=True,text=True,timeout=15)
        self.assertNotEqual(result.returncode,0)
        report = json.loads((out/'report.json').read_text())
        self.assertEqual(report['status'],'FAIL')
        self.assertEqual(report['steps'][0]['status'],'FAIL')
        self.assertIn('finished_at',report)
        time.sleep(0.9)
        self.assertFalse(marker.exists())

    def test_committed_whitespace_is_rejected_without_origin_or_dirty_files(self):
        (self.root/'committed.txt').write_text('synthetic trailing whitespace \n')
        subprocess.run(['git','add','committed.txt'],cwd=self.root,check=True)
        subprocess.run(['git','remote','remove','origin'],cwd=self.root,check=True)
        result, report = self.run_manifest({'steps':[{'name':'whitespace','command':['git','diff','--check','4b825dc642cb6eb9a060e54bf8d69288fbee4904','HEAD']}]})
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(report['source_status'],'')
        self.assertEqual(report['status'],'FAIL')
        self.assertEqual(report['steps'][0]['status'],'FAIL')

    def test_wrong_tool_version_fails_closed(self):
        result,r=self.run_manifest({'steps':[{'name':'pin','command':[sys.executable,'-c','print("wrong")'],'expected_output':'right'}]})
        self.assertNotEqual(result.returncode,0);self.assertEqual(r['status'],'FAIL')
    def test_exact_clean_commit_pass_and_no_github_token_in_environment(self):
        result,r=self.run_manifest({'steps':[{'name':'safe','command':[sys.executable,'-c','import os; assert "GITHUB_TOKEN" not in os.environ; print("synthetic success")']}]})
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(r['status'],'PASS')
        self.assertEqual(r['commit'],r['final_commit']);self.assertEqual(r['final_source_status'],'')


if __name__=='__main__':unittest.main()
