#!/usr/bin/env python3
"""Run this repository's reviewed local CI manifest; never post GitHub statuses."""
import argparse
import codecs
from collections import deque
import datetime
import hashlib
import io
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

from local_ci_evidence import authorize, digest, manifest, Rejected, is_owner_reviewed, bound_reviews, AUTHENTICITY


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def summarize_log(log, expected_output=None):
    """Read bounded chunks; the complete original log remains the evidence."""
    chunk_limit, record_limit, line_limit, summary_limit = 65536, 16384, 2048, 100
    ansi = re.compile(r'\x1b\[[0-9;]*m')
    suite = re.compile(r'(^|\s)(Tests|Test Files|Ran|TOTAL:)|\d+ (passed|failed|skipped)')
    result = re.compile(r'\b(passed|failed|skipped|succeeded|error\(s\)|Tests:|Test Files|TOTAL:)\b', re.I)
    dotnet = re.compile(r'Failed:\s*(\d+),\s*Passed:\s*(\d+),\s*Skipped:\s*(\d+)')
    digest, byte_count = hashlib.sha256(), 0
    summaries, results = [], deque(maxlen=summary_limit)
    suite_matches = result_matches = oversized_records = 0
    counts = {'passed': None, 'failed': None, 'skipped': None}
    pending, oversized = '', False
    expected_text, expected_exceeded = '', False
    decoder = io.IncrementalNewlineDecoder(codecs.getincrementaldecoder('utf-8')(errors='replace'), translate=True)

    def consume_record():
        nonlocal counts, suite_matches, result_matches, oversized_records
        if oversized:
            oversized_records += 1
            return
        clean = ansi.sub('', pending)
        for match in dotnet.finditer(clean):
            try:
                failed, passed, skipped = (int(value) for value in match.groups())
                counts = {'passed': passed, 'failed': failed, 'skipped': skipped}
            except ValueError:
                counts = {'passed': None, 'failed': None, 'skipped': None}
        line = clean.strip()
        if len(line) > line_limit:
            line = line[:line_limit] + ' [truncated; see complete log]'
        if suite.search(clean):
            suite_matches += 1
            if len(summaries) < summary_limit:
                summaries.append(line)
        if result.search(clean):
            result_matches += 1
            results.append(line)

    def consume_text(text):
        nonlocal pending, oversized, expected_text, expected_exceeded
        # Expected-output comparison uses the whole cleaned output or fails closed.
        # Never accept a retained prefix, including when discarded bytes are spaces.
        if expected_output is not None and not expected_exceeded:
            if len(expected_text) + len(text) <= chunk_limit:
                expected_text += text
            else:
                expected_text, expected_exceeded = '', True
        parts = re.split(r'[\n\v\f\x1c-\x1e\x85\u2028\u2029]', text)
        for index, part in enumerate(parts):
            if not oversized:
                if len(pending) + len(part) <= record_limit:
                    pending += part
                else:
                    pending, oversized = '', True
            if index < len(parts) - 1:
                consume_record()
                pending, oversized = '', False

    with log.open('rb') as source:
        while True:
            chunk = source.read(chunk_limit)
            if not chunk:
                break
            digest.update(chunk)
            byte_count += len(chunk)
            consume_text(decoder.decode(chunk))
        consume_text(decoder.decode(b'', final=True))
    if pending or oversized:
        consume_record()
    # A skipped record could contain the final count; do not claim earlier counts.
    if oversized_records:
        counts = {'passed': None, 'failed': None, 'skipped': None}
    details = {'log_sha256': digest.hexdigest(), 'log_bytes': byte_count,
               'counts': counts, 'suite_summaries': summaries, 'result_lines': list(results),
               'suite_summaries_omitted': max(0, suite_matches - summary_limit),
               'result_lines_omitted': max(0, result_matches - summary_limit),
               'oversized_log_records_omitted': oversized_records,
               'summary_limits': {'record_characters': record_limit, 'line_characters': line_limit,
                                  'lines_per_list': summary_limit},
               'summary_coverage': 'INCOMPLETE: oversized records omitted' if oversized_records else 'complete records scanned'}
    if expected_output is not None:
        details['expected_output_limit_characters'] = chunk_limit
        details['expected_output_limit_exceeded'] = expected_exceeded
        details['expected_output_matches'] = (not expected_exceeded and
                                               ansi.sub('', expected_text).strip() == expected_output)
    return details


def main():
    # A signal must never unwind Popen before its handle is registered, or
    # interrupt owned cleanup/release. Poll the request at safe stage boundaries.
    requested = []
    previous = {}
    def request_shutdown(signum, _frame):
        if not requested:
            requested.append(signum)
    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, request_shutdown)
        return run_main(requested)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def run_main(shutdown_requested):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report-dir', required=True, type=Path)
    parser.add_argument('--authorization', required=True, type=Path, help='Exact-head authorization under the fixed host-selected evidence policy.')
    parser.add_argument('--resource-controls', required=True, type=Path, help='Reviewed primary slateforge-config checkout.')
    parser.add_argument('--memory-gib', required=True, type=float)
    parser.add_argument('--output-gib', required=True, type=float)
    parser.add_argument('--signing-key', type=Path, help='Externally provisioned runner SSH signing key.')
    parser.add_argument('--candidate')
    parser.add_argument('--base')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    spec, manifest_hash = manifest(root)
    runner_hash = digest(Path(__file__))
    policy, approval = authorize(args.authorization, root, spec, runner_hash)
    report_dir = args.report_dir.expanduser().absolute()
    if is_owner_reviewed(policy):
        if args.signing_key is not None:
            raise Rejected('owner-reviewed mode must not imply signature authentication')
        from local_ci_evidence import owner_task, owner_report_directory
        task_root, _ = owner_task(policy, approval)
        report_dir = owner_report_directory(report_dir, task_root)
    else:
        if args.signing_key is None:
            raise Rejected('selected signed mode requires runner signing key')
        report_dir = report_dir.resolve()
    if args.candidate is not None and args.candidate != approval['commit']:
        raise Rejected('merge-candidate execution unsupported; only exact PR-head source is run')
    if args.candidate != approval.get('candidate') or args.base != approval.get('base'):
        raise Rejected('candidate/base approval scope mismatch')
    resources = args.resource_controls.resolve() / 'scripts/resources'
    # Resource source bytes are included in the externally trusted tool policy.
    resource_hashes = approval.get('resource_sha256', {})
    required_resources = ('admit.py', 'leases.py', 'observe.py', 'platform_adapter.py', 'linux_process.py', 'ci_reservation.py', 'inventory_scope.py', 'mac_process.py', 'mac_ancestry.py')
    if set(resource_hashes) != set(required_resources) or any(digest(resources / name) != resource_hashes[name] for name in required_resources):
        raise Rejected('resource controller provenance mismatch')
    sys.path.insert(0, str(resources))
    from ci_reservation import Reservation
    if report_dir == root or root in report_dir.parents:
        parser.error('Evidence must be private and outside the source checkout.')
    os.umask(0o077)
    report_dir.mkdir(parents=True, exist_ok=False)
    git = lambda *a: subprocess.check_output(['git', *a], cwd=root, text=True).strip()
    report = {'schema': 1, 'repository': spec['repository'],
              'checkout': str(root), 'resource_sha256': resource_hashes,
              'commit': git('rev-parse', 'HEAD'), 'source_status': git('status', '--porcelain'),
              'started_at': utc(), 'os': platform.platform(), 'machine': platform.machine(),
              'python': platform.python_version(), 'status': 'RUNNING', 'steps': [],
              'validator_sha256': runner_hash,
              'manifest_sha256': manifest_hash,
              'authorization_sha256': approval.sha256, 'candidate': args.candidate, 'base': args.base,
              'reviews': 'Recorded separately against this exact commit in the PR/global report.',
              'unavailable_checks': spec.get('exceptions', [])}
    from local_ci_evidence import is_v2, BINDINGS
    if bound_reviews(policy):
        report.update({name: approval[name] for name in BINDINGS})
    if is_owner_reviewed(policy):
        report.update(task_id=approval['task_id'], authenticity=AUTHENTICITY)
    def save():
        temporary = report_dir/'report.json.tmp'
        temporary.write_text(json.dumps(report, indent=2)+'\n')
        os.replace(temporary, report_dir/'report.json')
    save()
    if report['source_status']:
        report.update(status='FAIL', failure='Refusing a dirty checkout; no exact-commit pass is possible.', finished_at=utc())
        save()
        return 2
    if spec.get('require_no_ignored_inputs'):
        ignored = sorted(name for name in git('ls-files', '--others', '--ignored', '--exclude-standard', '-z').split('\0') if name)
        if ignored:
            report.update(status='FAIL', failure='Refusing pre-existing ignored inputs and build outputs; preserve them and use an owner-authorized pristine checkout.',
                          refused_ignored_input_paths=ignored, finished_at=utc())
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
    env.update({k:v.replace('${REPORT}', str(report_dir)).replace('${ROOT}', str(root)) for k,v in spec.get('environment', {}).items()})
    env['PATH']=os.pathsep.join([v.replace('${REPORT}',str(report_dir)) for v in spec.get('path_prepend',[])]+[env.get('PATH','')])
    if shutdown_requested:
        return 130
    reservation = Reservation(report_dir, args.memory_gib, args.output_gib, 'local-ci-' + str(os.getpid()))
    report['lease'] = dict(reservation.binding, state='ACTIVE')
    if bound_reviews(policy):
        if any(reservation.binding.get(k) != v for k,v in approval['authorized_host'].items()):
            # No stage was launched. Release only this newly acquired reservation.
            reservation.release(True)
            raise Rejected('admitted host differs from owner-authorized host')
        report['reservation_evidence'] = {'state': 'RESERVED', 'binding': dict(reservation.binding), 'recorded_at': utc()}
    report['tools'] = []
    report['tool_steps'] = []
    owned_groups = set()
    group_records = {}
    report['unresolved_process_groups'] = []
    cleanup_started = False
    ownership_uncertain = False  # Sticky: later successful cleanup cannot clear it.
    states = {}
    def verify_group_absence(groups):
        # Only observe registered stage groups; never signal guessed/reused PIDs.
        # Reaping descendants can lag SIGKILL. Bound the wait and keep heartbeats.
        pending = set(groups) & owned_groups
        deadline = time.monotonic() + 2.0
        try:
            while pending:
                reservation.tick()
                for pgid in tuple(pending):
                    observation = group_records[pgid].setdefault('process_group_verification',
                        {'checks': 0, 'absence_verified': False, 'wait_limit_seconds': 2.0})
                    observation['checks'] += 1
                    observation['checked_at'] = utc()
                    try:
                        os.killpg(pgid, 0)
                    except ProcessLookupError:
                        observation.update(last_observation='ABSENT', absence_verified=True)
                        owned_groups.discard(pgid)
                        pending.discard(pgid)
                    except OSError as exc:
                        observation.update(last_observation='UNKNOWN', error_type=type(exc).__name__)
                    else:
                        observation['last_observation'] = 'PRESENT'
                remaining = deadline - time.monotonic()
                if not pending or remaining <= 0:
                    break
                time.sleep(min(0.05, remaining))
        except Exception as exc:
            # A later disappearance must not erase a failed lease heartbeat.
            report['process_group_verification_error'] = type(exc).__name__
            raise
        finally:
            report['unresolved_process_groups'] = sorted(owned_groups)
            save()

    def run(step, cleanup=False):
        nonlocal ownership_uncertain
        process = None
        name = step['name']
        if shutdown_requested and not cleanup:
            raise KeyboardInterrupt('Shutdown requested before stage launch')
        if owned_groups and not cleanup:
            report['blocked_normal_stage'] = {'name': name,
                                             'unresolved_process_groups': sorted(owned_groups)}
            save()
            raise Rejected('Prior owned process group absence unverified; refusing normal stage: ' + name)
        reservation.before_stage(cleanup=cleanup)
        missing = [x for x in step.get('requires', []) if states.get(x) != 'PASS']
        record = {'name':name, 'command':step['command'], 'cwd':step.get('cwd','.'),
                  'started_at':utc(), 'status':'RUNNING', 'exit_code':None, 'timeout_seconds':step.get('timeout_seconds',21600),
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
                try:
                    if shutdown_requested and not cleanup_started:
                        raise KeyboardInterrupt('Shutdown requested before stage launch')
                    try:
                        process=subprocess.Popen(command,cwd=directory,env=env,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
                        owned_groups.add(process.pid)
                    except BaseException:
                        # Popen may have created a child without returning a handle.
                        # No guessed PID/group may be signaled or treated as absent.
                        ownership_uncertain = True
                        record['process_group_ownership'] = 'UNKNOWN: launch handle not registered'
                        report['process_ownership_uncertain'] = True
                        save()
                        raise
                    record.update(process_id=process.pid, process_group_id=process.pid,
                                  process_group_registered_at=utc(),
                                  process_group_ownership='start_new_session returned handle')
                    group_records[process.pid] = record
                    report['unresolved_process_groups'] = sorted(owned_groups)
                    save()
                    if shutdown_requested and not cleanup_started:
                        raise KeyboardInterrupt('Shutdown requested during stage launch')
                    deadline = time.monotonic() + step.get('timeout_seconds',21600)
                    while process.poll() is None:
                        if shutdown_requested and not cleanup_started:
                            raise KeyboardInterrupt('Shutdown requested during stage')
                        reservation.tick()
                        if time.monotonic() >= deadline:
                            raise subprocess.TimeoutExpired(command, step.get('timeout_seconds',21600))
                        try:
                            process.wait(timeout=1)
                        except subprocess.TimeoutExpired:
                            pass
                except subprocess.TimeoutExpired:
                    record['reason']='Stage exceeded its recorded deadline.'
                    record['timed_out']=True
                except BaseException:
                    record['reason']='Stage interrupted.'
                    raise
                finally:
                    # The group belongs exclusively to this stage. Stop descendants
                    # before any later resource cleanup, including after interruption.
                    if process is not None:
                        try:os.killpg(process.pid,signal.SIGTERM)
                        except ProcessLookupError:pass
                        try:process.wait(timeout=5)
                        except subprocess.TimeoutExpired:pass
                        try:os.killpg(process.pid,signal.SIGKILL)
                        except ProcessLookupError:pass
                        process.wait()
                        verify_group_absence({process.pid})
                if shutdown_requested and not cleanup_started:
                    raise KeyboardInterrupt('Shutdown requested after stage cleanup')
                result=process
            record.update(summarize_log(log, step.get('expected_output')))
            record['exit_code']=result.returncode
            passed = result.returncode == 0 and not record.get('timed_out')
            if 'expected_output' in step:
                passed = passed and record.get('expected_output_matches', False)
                if not passed:record['reason']='Required tool version/output did not match.'
            record['status']='PASS' if passed else ('ADVISORY_FAIL' if step.get('advisory') else 'FAIL')
        except KeyboardInterrupt:
            record.update(status='FAIL', exit_code=process.returncode if process is not None else None,
                          reason=('Stage interrupted; process ownership or cleanup uncertain.'
                                  if ownership_uncertain or owned_groups else
                                  'Stage interrupted; no owned process group remains.'))
            states[name]='FAIL';save();raise
        except OSError as exc:
            record.update(status='FAIL',reason=str(exc))
        record.update(log=str(log),seconds=round(time.monotonic()-started,2),finished_at=utc())
        states[name]=record['status'];save()
        print(record['status'],name,flush=True)
    try:
        for index, tool in enumerate(approval['tools']):
            probe = {'name': 'tool-' + str(index), 'command': tool['command'], 'expected_output': tool['expected_output'], 'timeout_seconds': 30}
            run(probe)
            record = report['steps'].pop()
            report['tool_steps'].append(record)
            if record['status'] != 'PASS':
                raise Rejected('trusted tool version mismatch')
            report['tools'].append(tool)
        for step in spec['steps']:
            run(step)
    except (Exception, KeyboardInterrupt) as exc:
        report['failure']=type(exc).__name__+': '+str(exc)
    finally:
        cleanup_started = True
        for step in spec.get('cleanup', []):
            try:
                run(step, cleanup=True)
            except (Exception, KeyboardInterrupt) as exc:
                report['failure'] = 'cleanup uncertain: ' + type(exc).__name__
        for step in spec.get('resource_verification', []):
            try:
                run(step, cleanup=True)
            except (Exception, KeyboardInterrupt) as exc:
                report['failure'] = 'resource verification uncertain: ' + type(exc).__name__
        completion_steps = spec.get('cleanup', []) + spec.get('resource_verification', [])
        completion_names = [step['name'] for step in completion_steps]
        completed = [row for row in report['steps'] if row['name'] in completion_names]
        cleanup_verified = (len(completed) == len(completion_steps) and
                            all(row['status'] == 'PASS' and row['exit_code'] == 0 for row in completed))
        # Recheck only still-unresolved registered groups after all owned cleanup.
        # Absence already proved is not revisited: a recycled group is unrelated.
        try:
            verify_group_absence(owned_groups)
        except Exception as exc:
            report.setdefault('failure', 'Owned group verification uncertain: ' + type(exc).__name__)
        if owned_groups:
            report.setdefault('failure', 'Owned process group absence unverified')
        report['process_ownership_uncertain'] = ownership_uncertain
        if shutdown_requested:
            report['failure'] = signal.Signals(shutdown_requested[0]).name + ' requested local CI shutdown'
        try:
            report['lease'] = dict(reservation.binding, **reservation.release(not ownership_uncertain and not owned_groups and cleanup_verified and not report.get('process_group_verification_error')))
        except Exception as exc:
            report['lease'] = dict(reservation.binding, state='RECOVERY_REQUIRED')
            report['failure'] = 'lease release uncertain: ' + type(exc).__name__
        report['final_commit']=git('rev-parse','HEAD')
        report['final_source_status']=git('status','--porcelain')
        if shutdown_requested:
            report['failure'] = signal.Signals(shutdown_requested[0]).name + ' requested local CI shutdown'
        report['finished_at']=utc()
        report['status']='PASS' if (not report.get('failure') and report['lease']['state']=='RELEASED' and report['tools']==approval['tools'] and all(x['status'] in ('PASS','ADVISORY_FAIL') for x in report['steps']) and report['final_commit']==report['commit'] and not report['final_source_status']) else 'FAIL'
        report['advisory_failures']=[x['name'] for x in report['steps'] if x['status']=='ADVISORY_FAIL']
        if report['status']=='PASS' and report['advisory_failures']:report['status']='PASS_WITH_ADVISORIES'
        save()
    import hashlib
    from local_ci_evidence import read_payload, verify
    if is_owner_reviewed(policy):
        verify(report_dir/'report.json', 'runner', policy)
        print(AUTHENTICITY, report['status'], str(report_dir/'report.json'), flush=True)
        return 0 if report['status'] in ('PASS', 'PASS_WITH_ADVISORIES') else 1
    final_payload_hash = hashlib.sha256(read_payload(report_dir/'report.json')).hexdigest()
    signed = subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(args.signing_key), '-n', 'slateforge-local-ci-runner', str(report_dir/'report.json')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not signed.returncode:
        verified = verify(report_dir/'report.json', 'runner', policy)
        if verified.sha256 != final_payload_hash:
            raise Rejected('report bytes changed between finalization/signing')
    if signed.returncode:
        print('Evidence signature unavailable; acceptance UNKNOWN', flush=True)
        return 2
    print(report['status'],str(report_dir/'report.json'),flush=True)
    return 0 if report['status'] in ('PASS','PASS_WITH_ADVISORIES') else 1


if __name__ == '__main__':
    sys.exit(main())
