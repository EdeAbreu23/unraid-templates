#!/usr/bin/env python3
"""Run this repository's reviewed local CI manifest; never post GitHub statuses."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import shutil
import subprocess
import sys
import time


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report-dir', required=True, type=Path)
    parser.add_argument('--authorization', required=True, help='Current owner approval source and exact scope; recording text does not grant permission.')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    spec = json.loads((root / 'local-ci.json').read_text())
    report_dir = args.report_dir.expanduser().resolve()
    if report_dir == root or root in report_dir.parents:
        parser.error('Evidence must be private and outside the source checkout.')
    os.umask(0o077)
    report_dir.mkdir(parents=True, exist_ok=False)
    git = lambda *a: subprocess.check_output(['git', *a], cwd=root, text=True).strip()
    report = {'schema': 1, 'repository': git('remote', 'get-url', 'origin'),
              'commit': git('rev-parse', 'HEAD'), 'source_status': git('status', '--porcelain'),
              'started_at': utc(), 'os': platform.platform(), 'machine': platform.machine(),
              'python': platform.python_version(), 'status': 'RUNNING', 'steps': [],
              'validator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'manifest_sha256': hashlib.sha256((root/'local-ci.json').read_bytes()).hexdigest(),
              'authorization': args.authorization,
              'reviews': 'Recorded separately against this exact commit in the PR/global report.',
              'unavailable_checks': spec.get('exceptions', [])}
    def save():
        (report_dir/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    save()
    if report['source_status']:
        report.update(status='FAIL', failure='Refusing a dirty checkout; no exact-commit pass is possible.', finished_at=utc())
        save()
        return 2
    # Clean tracked status does not exclude ignored application/provider settings.
    # Inspect names only; never open or copy private input values into the gate.
    generated = {'node_modules', 'bin', 'obj', '.angular', 'dist', 'coverage', 'test-results', 'playwright-report', 'local-artifacts'}
    private_inputs = []
    for name in git('ls-files', '--others', '--ignored', '--exclude-standard', '-z').split('\0'):
        path = Path(name)
        if not name or generated.intersection(path.parts):
            continue
        base = path.name.lower()
        if (base == '.env' or base.startswith('.env.') or base in {'.npmrc', 'nuget.config', 'secrets.yaml', 'secrets.yml'}
                or (base.startswith('appsettings.') and base.endswith('.json'))
                or base.startswith(('docker-compose.override.', 'compose.override.'))):
            private_inputs.append(name)
    if private_inputs:
        report.update(status='FAIL', failure='Refusing ignored private configuration inputs; use an owner-authorized clean isolated checkout without copying private files.',
                      refused_private_input_paths=private_inputs, finished_at=utc())
        save()
        return 2
    home = report_dir/'home'
    home.mkdir()
    # Install only a reference inside this fresh HOME; never alter private Docker config.
    compose=shutil.which('docker-compose')
    if compose:
        plugin_dir=home/'.docker/cli-plugins';plugin_dir.mkdir(parents=True)
        (plugin_dir/'docker-compose').symlink_to(compose)
    for name in ['user.npmrc', 'global.npmrc']:
        (report_dir/name).write_text('')
    env = {k: os.environ[k] for k in ('PATH', 'SYSTEMROOT', 'TMPDIR') if k in os.environ}
    env.update(HOME=str(home), LANG='C.UTF-8', LC_ALL='C.UTF-8', CI='true',
               DOTNET_CLI_HOME=str(home), DOTNET_CLI_TELEMETRY_OPTOUT='1',
               DOTNET_NOLOGO='1', DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1',
               NUGET_PACKAGES=str(report_dir/'nuget'), REPORT=str(report_dir),
               npm_config_userconfig=str(report_dir/'user.npmrc'),
               npm_config_globalconfig=str(report_dir/'global.npmrc'),
               ASTRO_TELEMETRY_DISABLED='1', WRANGLER_SEND_METRICS='false',
               PYTHONDONTWRITEBYTECODE='1')
    # Only named, non-secret runtime locations may pass through. No .env sourcing.
    for name in spec.get('environment_passthrough', []):
        if name in os.environ:
            env[name] = os.environ[name]
    env.update({k:v.replace('${REPORT}', str(report_dir)) for k,v in spec.get('environment', {}).items()})
    env['PATH']=os.pathsep.join([v.replace('${REPORT}',str(report_dir)) for v in spec.get('path_prepend',[])]+[env.get('PATH','')])
    states = {}
    def run(step):
        name = step['name']
        missing = [x for x in step.get('requires', []) if states.get(x) != 'PASS']
        record = {'name':name, 'command':step['command'], 'cwd':step.get('cwd','.'),
                  'started_at':utc(), 'exit_code':None, 'timeout_seconds':step.get('timeout_seconds',21600),
                  'counts':{'passed':None,'failed':None,'skipped':None}}
        report['steps'].append(record)
        if missing:
            record.update(status='NOT_RUN', reason='Unsuccessful prerequisites: '+', '.join(missing))
            states[name]='NOT_RUN'; save(); return
        directory = (root/step.get('cwd','.')).resolve()
        if directory != root and root not in directory.parents:
            raise ValueError('Command cwd escapes checkout')
        command = [x.replace('${REPORT}',str(report_dir)) for x in step['command']]
        record.update(command=command, cwd=str(directory))
        started=time.monotonic()
        log=report_dir/(name+'.log')
        try:
            with log.open('w') as output:
                process=subprocess.Popen(command,cwd=directory,env=env,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
                try:
                    process.wait(timeout=step.get('timeout_seconds',21600))
                except subprocess.TimeoutExpired:
                    record['reason']='Stage exceeded its recorded deadline.'
                    record['timed_out']=True
                except BaseException:
                    record['reason']='Stage interrupted.'
                    raise
                finally:
                    # The group belongs exclusively to this stage. Stop descendants
                    # before any later resource cleanup, including after interruption.
                    try:os.killpg(process.pid,signal.SIGTERM)
                    except ProcessLookupError:pass
                    try:process.wait(timeout=5)
                    except subprocess.TimeoutExpired:pass
                    try:os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    process.wait()
                result=process
            data=log.read_text(errors='replace')
            clean=re.sub(r'\x1b\[[0-9;]*m','',data)
            record['exit_code']=result.returncode
            dotnet=re.findall(r'Failed:\s*(\d+),\s*Passed:\s*(\d+),\s*Skipped:\s*(\d+)',clean)
            if dotnet:
                failed,passed_count,skipped=dotnet[-1]
                record['counts']={'passed':int(passed_count),'failed':int(failed),'skipped':int(skipped)}
            record['suite_summaries']=[line.strip() for line in clean.splitlines() if re.search(r'(^|\s)(Tests|Test Files|Ran|TOTAL:)|\d+ (passed|failed|skipped)',line)]
            passed = result.returncode == 0 and not record.get('timed_out')
            if 'expected_output' in step:
                passed = passed and clean.strip() == step['expected_output']
                if not passed:record['reason']='Required tool version/output did not match.'
            record['status']='PASS' if passed else ('ADVISORY_FAIL' if step.get('advisory') else 'FAIL')
            # Retain actual summaries, including separate suite counts; never invent zeros.
            record['result_lines']=[s.strip() for s in clean.splitlines() if re.search(r'\b(passed|failed|skipped|succeeded|error\(s\)|Tests:|Test Files|TOTAL:)\b',s,re.I)][-100:]
        except KeyboardInterrupt:
            record.update(status='FAIL',reason='Stage interrupted; owned process group stopped.')
            states[name]='FAIL';save();raise
        except OSError as exc:
            record.update(status='FAIL',reason=str(exc))
        record.update(log=str(log),seconds=round(time.monotonic()-started,2),finished_at=utc())
        states[name]=record['status'];save()
        print(record['status'],name,flush=True)
    try:
        for step in spec['steps']:
            run(step)
    except (Exception, KeyboardInterrupt) as exc:
        report['failure']=type(exc).__name__+': '+str(exc)
    finally:
        for step in spec.get('cleanup', []):
            run(step)
        report['final_commit']=git('rev-parse','HEAD')
        report['final_source_status']=git('status','--porcelain')
        report['finished_at']=utc()
        report['status']='PASS' if (not report.get('failure') and all(x['status'] in ('PASS','ADVISORY_FAIL') for x in report['steps']) and report['final_commit']==report['commit'] and not report['final_source_status']) else 'FAIL'
        report['advisory_failures']=[x['name'] for x in report['steps'] if x['status']=='ADVISORY_FAIL']
        if report['status']=='PASS' and report['advisory_failures']:report['status']='PASS_WITH_ADVISORIES'
        save()
    print(report['status'],str(report_dir/'report.json'),flush=True)
    return 0 if report['status'] in ('PASS','PASS_WITH_ADVISORIES') else 1


if __name__ == '__main__':
    sys.exit(main())
