#!/usr/bin/env python3
"""Synthetic safety checks for the local CI evidence runner."""
import json
import os
import socket
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
    def test_wrong_tool_version_fails_closed(self):
        result,r=self.run_manifest({'steps':[{'name':'pin','command':[sys.executable,'-c','print("wrong")'],'expected_output':'right'}]})
        self.assertNotEqual(result.returncode,0);self.assertEqual(r['status'],'FAIL')
    def test_exact_clean_commit_pass_and_no_github_token_in_environment(self):
        result,r=self.run_manifest({'steps':[{'name':'safe','command':[sys.executable,'-c','import os; assert "GITHUB_TOKEN" not in os.environ; print("synthetic success")']}]})
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(r['status'],'PASS')
        self.assertEqual(r['commit'],r['final_commit']);self.assertEqual(r['final_source_status'],'')


if __name__=='__main__':unittest.main()
