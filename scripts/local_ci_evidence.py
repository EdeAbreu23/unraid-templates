"""Local CI signed evidence acceptance. Host trust is provisioned out of band.

Same-user coordination is not an adversarial-user security sandbox. A repository
cannot provide its own trust policy, signers, approval or accepted runner hashes.
"""
import datetime
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

TRUST_ROOT = Path.home() / '.config/SlateForge/local-ci'
LIMIT = 1048576
V2 = 'owner-ratified-reviews-v2'
OWNER_REVIEWED = 'owner-reviewed-v1'
AUTHENTICITY = 'owner-reviewed; NOT cryptographically authenticated'
BINDINGS = ('contract', 'run_id', 'repository', 'commit', 'candidate', 'base',
            'manifest_sha256', 'runner_sha256', 'support_sha256', 'resource_sha256',
            'tools', 'authorized_host')


def is_v2(policy):
    return policy.get('schema') == 2 and policy.get('contract') == V2


def is_owner_reviewed(policy):
    return policy.get('schema') == 3 and policy.get('contract') == OWNER_REVIEWED


def bound_reviews(policy):
    return is_v2(policy) or is_owner_reviewed(policy)


def trusted_bytes(path):
    # This is a SAME-UID/HUMAN custody check, not authenticated isolation.
    path = Path(path)
    if not path.is_absolute() or path != path.resolve() or TRUST_ROOT not in path.parents:
        raise Rejected('owner-reviewed records require fixed external host custody')
    for item in (TRUST_ROOT, *reversed(tuple(path.relative_to(TRUST_ROOT).parents)[:-1]), path):
        item = item if item.is_absolute() else TRUST_ROOT / item
        info = item.lstat()
        if item.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise Rejected('owner-reviewed record custody/permissions invalid')
    return read_payload(path)



def owner_report_directory(path, task_root):
    """Check a possibly nonexistent destination before any runner side effects.

    Same-UID custody assumes no hostile concurrent path replacement, as with the
    existing external policy store; this is not an adversarial filesystem sandbox.
    """
    requested = Path(path).expanduser().absolute()
    canonical = requested.resolve()
    if ('..' in requested.parts or requested != canonical or
            task_root not in canonical.parents):
        raise Rejected('report must remain in fixed external task custody')
    # Unlike trusted_bytes(), the new report and some of its parents may not yet
    # exist. Validate every existing component; mkdir later uses private umask.
    for item in (task_root, *reversed(tuple(requested.relative_to(task_root).parents)[:-1]), requested):
        item = item if item.is_absolute() else task_root / item
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if (item.is_symlink() or not stat.S_ISDIR(info.st_mode) or
                info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise Rejected('report directory custody/permissions invalid')
    return canonical


def owner_task(policy, value):
    task = value.get('task_id')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', str(task)):
        raise Rejected('bounded owner task required')
    task_root = TRUST_ROOT / 'owner-reviewed' / task
    raw = trusted_bytes(task_root / 'approval.json')
    approval = json.loads(raw, object_pairs_hook=unique)
    project = policy.get('repositories', {}).get(value.get('repository'), {})
    if hashlib.sha256(raw).hexdigest() != project.get('owner_task_approval_sha256'):
        raise Rejected('task not independently owner selected')
    validity(approval)
    if (approval.get('contract') != OWNER_REVIEWED or approval.get('task_id') != task or
            approval.get('repository') != value.get('repository') or
            approval.get('scope') != 'bounded-local-ci-task' or
            approval.get('allow_bounded_runs') is not True or
            approval.get('revoked') is True or
            value.get('base') != approval.get('base') or
            value.get('authorized_host') != approval.get('authorized_host')):
        raise Rejected('outside bounded owner project/task approval')
    event = json.loads(trusted_bytes(task_root / 'owner-approval-event.json'), object_pairs_hook=unique)
    if (secure_digest(task_root / 'owner-approval-event.json') != approval.get('owner_event_sha256') or
            event.get('actor') != 'Elvis' or event.get('source') != 'authenticated-owner-message' or
            not isinstance(event.get('message'), str) or not event['message'].strip() or
            not isinstance(event.get('session_id'), str) or not event['session_id']):
        raise Rejected('actual owner authorization capture required')
    return task_root, approval


def owner_reviewed_payload(path, role, policy):
    path = Path(path)
    raw = trusted_bytes(path)
    value = json.loads(raw, object_pairs_hook=unique)
    if (not isinstance(value, dict) or value.get('contract') != OWNER_REVIEWED or
            value.get('authenticity') != AUTHENTICITY):
        raise Rejected('explicit owner-reviewed payload contract required')
    task_root, task = owner_task(policy, value)
    if task_root not in path.parents:
        raise Rejected('cross-task record custody')
    if role in ('murdock', 'dennis'):
        if value.get('role') != role:
            raise Rejected('wrong independent reviewer role')
        capture = path.with_name(role + '.capture.json')
        event = json.loads(trusted_bytes(capture), object_pairs_hook=unique)
        if (hashlib.sha256(trusted_bytes(capture)).hexdigest() != value.get('capture_sha256') or
                event.get('source') != 'authenticated-session-export' or
                event.get('session_id') != value.get('original_session_id') or
                event.get('transcript_sha256') != value.get('transcript_sha256') or
                event.get('role') != role):
            raise Rejected('original authenticated workflow capture required')
    if role == 'owner' and value.get('scope') == 'merge':
        event_path = path.with_name('final-merge-owner-event.json')
        event = json.loads(trusted_bytes(event_path), object_pairs_hook=unique)
        fields = ('repository', 'commit', 'base', 'pr', 'report_sha256', 'review_sha256')
        if (hashlib.sha256(trusted_bytes(event_path)).hexdigest() != value.get('owner_event_sha256') or
                event.get('actor') != 'Elvis' or event.get('source') != 'authenticated-owner-message' or
                event.get('decision') != 'approve-exact-final-merge' or
                timestamp(event.get('recorded_at')) > timestamp(value.get('issued_at')) or
                event.get('recorded_at') != value.get('approved_at') or
                any(event.get(k) != value.get(k) for k in fields)):
            raise Rejected('separate actual exact final owner merge approval required')
    return SignedPayload(value, raw)  # Digest container only; no crypto assertion.


def timestamp(value):
    try:
        parsed = datetime.datetime.fromisoformat(value)
    except (TypeError, ValueError):
        raise Rejected('invalid timestamp')
    if parsed.tzinfo is None:
        raise Rejected('timezone required')
    return parsed


def validity(payload):
    issued = timestamp(payload.get('issued_at'))
    expires = (datetime.datetime.max.replace(tzinfo=datetime.timezone.utc)
               if payload.get('contract') == OWNER_REVIEWED and payload.get('expires_at') is None
               else timestamp(payload.get('expires_at')))
    if payload.get('contract') == OWNER_REVIEWED and payload.get('revoked') is True:
        raise Rejected('revoked owner-reviewed permission')
    now = datetime.datetime.now(datetime.timezone.utc)
    if not issued <= now < expires:
        raise Rejected('expired/future evidence')
    return issued, expires


def v2_authorization(approval):
    validity(approval)
    if (not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', str(approval.get('run_id', ''))) or
            not isinstance(approval.get('authorized_host'), dict) or
            set(approval['authorized_host']) != {'host_id', 'platform', 'boot_id'} or
            any(not isinstance(approval['authorized_host'][k], str) or not approval['authorized_host'][k]
                for k in ('platform', 'boot_id')) or
            ((not isinstance(approval['authorized_host']['host_id'], str) or not approval['authorized_host']['host_id']) and
             not (approval['authorized_host']['platform'] == 'darwin' and approval['authorized_host']['host_id'] is None))):
        raise Rejected('run/authorized host missing')
    for name in ('commit', 'base'):
        if not re.fullmatch('[0-9a-f]{40}', str(approval.get(name, ''))):
            raise Rejected('full head/base required')
    if approval.get('candidate') not in (None, approval['commit']):
        raise Rejected('unsupported candidate')


def match_bindings(payload, approval, authorization_hash):
    if approval.get('contract') == OWNER_REVIEWED and (
            payload.get('task_id') != approval.get('task_id') or
            payload.get('authenticity') != AUTHENTICITY):
        raise Rejected('cross-task/owner-reviewed contract mismatch')
    if (any(name not in payload or payload[name] != approval[name] for name in BINDINGS) or
            payload.get('authorization_sha256') != authorization_hash):
        raise Rejected('cross-run/source/pin/authorization binding mismatch')


def v2_completed(report, approval, authorization_hash):
    match_bindings(report, approval, authorization_hash)
    started, finished = timestamp(report['started_at']), timestamp(report['finished_at'])
    issued, expires = validity(approval)
    if not issued <= started <= finished <= expires:
        raise Rejected('authorization/execution chronology mismatch')
    if finished > datetime.datetime.now(datetime.timezone.utc):
        raise Rejected('future completed run')
    lease = report['lease']
    if any(lease.get(k) != v for k, v in approval['authorized_host'].items()):
        raise Rejected('actual reservation host differs from authorized host')
    admission = report.get('reservation_evidence', {})
    if (admission.get('binding') != {k:v for k,v in lease.items() if k != 'state'} or
            admission.get('state') != 'RESERVED' or
            not issued <= timestamp(admission.get('recorded_at')) <= finished):
        raise Rejected('actual reservation evidence missing')
    previous = started
    for row in report['tool_steps'] + report['steps']:
        begin, end = timestamp(row['started_at']), timestamp(row['finished_at'])
        if not previous <= begin <= end <= finished:
            raise Rejected('stage chronology mismatch')
        previous = end


def v2_review(role, review, review_path, report, approval, authorization_hash, policy, seen, expected_workflow):
    match_bindings(review, approval, authorization_hash)
    issued, _ = validity(review)
    if timestamp(report['finished_at']) > issued:
        raise Rejected('review ratification predates completed execution')
    # Both owner ratifications authenticate the same exact original workflow bytes.
    # No run-specific host trust file or trust.json mutation is required.
    workflow_path = Path(review_path).with_name('workflow.json')
    workflow_raw = read_payload(workflow_path)
    workflow_hash = hashlib.sha256(workflow_raw).hexdigest()
    if (review.get('workflow_sha256') != workflow_hash or
            (expected_workflow is not None and workflow_hash != expected_workflow)):
        raise Rejected('ratifications differ from original workflow bytes')
    workflow = json.loads(workflow_raw, object_pairs_hook=unique)
    match_bindings(workflow, approval, authorization_hash)
    if review.get('implementer_session_id') != workflow.get('implementer_session_id'):
        raise Rejected('ratified implementer session differs from workflow')
    entry = workflow.get('reviewers', {}).get(role, {})
    session = entry.get('original_session_id')
    model = entry.get('model')
    if (not isinstance(session, str) or not session or session in seen or
            session == workflow.get('implementer_session_id') or
            not isinstance(workflow.get('implementer_session_id'), str) or
            not workflow['implementer_session_id'] or not isinstance(model, str) or not model or
            workflow.get('run_id') != approval['run_id'] or
            workflow.get('report_sha256') != review.get('report_sha256') or
            review.get('original_session_id') != session or review.get('model') != model or
            review.get('role') != role or review.get('review_basis') != 'completed-run' or
            review.get('pending_findings') != [] or review.get('deferred_mandatory_acceptance') != [] or
            entry.get('verdict') != 'PASS' or entry.get('role') != role or
            entry.get('review_basis') != 'completed-run' or entry.get('pending_findings') != [] or
            entry.get('deferred_mandatory_acceptance') != []):
        raise Rejected('independent original-session completed-run PASS missing')
    if review.get('completed_at') != entry.get('completed_at'):
        raise Rejected('ratified original review time differs from workflow')
    completed = timestamp(entry.get('completed_at'))
    if not timestamp(report['finished_at']) <= completed <= issued:
        raise Rejected('original review chronology mismatch')
    transcript = Path(review_path).with_name(role + '.transcript')
    if (secure_digest(transcript) != review.get('transcript_sha256') or
            review['transcript_sha256'] != entry.get('transcript_sha256')):
        raise Rejected('exact original transcript bytes differ')
    if role == 'dennis':
        pr = review.get('pr')
        if (not isinstance(pr, dict) or set(pr) != {'repository', 'number', 'head', 'base'} or
                pr.get('repository') != approval['repository'] or
                type(pr.get('number')) is not int or pr['number'] <= 0 or
                pr.get('head') != approval['commit'] or pr.get('base') != approval['base'] or
                entry.get('pr') != pr):
            raise Rejected('Dennis actual PR identity/head/base missing')
    seen.add(session)
    return workflow_hash


def v2_merge(approval, result, execution, number):
    match_bindings(approval, execution, result['authorization_sha256'])
    issued, _ = validity(approval)
    if approval.get('contract') == OWNER_REVIEWED and (
            approval.get('scope') != 'merge' or
            timestamp(approval.get('approved_at')) < timestamp(result['review_ratified_at'])):
        raise Rejected('actual final owner merge approval must follow reviews')
    if (approval.get('pr') != number or approval.get('report_sha256') != result['report_sha256'] or
            issued < timestamp(result['review_ratified_at']) or
            approval.get('review_sha256') != result['review_sha256']):
        raise Rejected('merge authorization precedes/differs from final ratifications')


class Rejected(ValueError):
    pass


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(65536), b''):
            value.update(chunk)
    return value.hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Rejected('duplicate JSON key')
        result[key] = value
    return result


def load(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > LIMIT:
        raise Rejected('missing, unsafe or oversize evidence')
    return json.loads(path.read_text(), object_pairs_hook=unique)


def git(root, *args):
    return subprocess.check_output(['git', *args], cwd=root, text=True).strip()


def trust():
    # Fixed external location, never CLI-selectable/repository supplied.
    for path in (TRUST_ROOT, TRUST_ROOT / 'trust.json'):
        info = path.lstat()
        if path.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise Rejected('trust custody/permissions invalid')
    policy = load(TRUST_ROOT / 'trust.json')
    if is_owner_reviewed(policy):
        if 'identities' in policy:
            raise Rejected('mixed owner-reviewed/signature trust contracts')
        return policy
    info = (TRUST_ROOT / 'allowed_signers').lstat()
    if (TRUST_ROOT / 'allowed_signers').is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise Rejected('trust custody/permissions invalid')
    if policy.get('schema') not in (1, 2) or (policy.get('schema') == 2 and not is_v2(policy)):
        raise Rejected('unsupported trust policy')
    if policy['schema'] == 1 and 'contract' in policy:
        raise Rejected('mixed trust contracts')
    identities = policy.get('identities', {})
    roles = {'owner', 'runner'} if is_v2(policy) else {'owner', 'runner', 'murdock', 'dennis'}
    if set(identities) != roles or len(set(identities.values())) != len(roles):
        raise Rejected('distinct identity principals required for selected contract')
    keys = {}
    for line in (TRUST_ROOT / 'allowed_signers').read_text().splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        fields = line.split()
        if len(fields) != 3 or fields[0] not in identities.values() or fields[0] in keys:
            raise Rejected('allowed_signers requires one simple public key row per identity')
        keys[fields[0]] = base64.b64decode(fields[2], validate=True)
    if set(keys) != set(identities.values()) or len(set(keys.values())) != len(roles):
        raise Rejected('self review rejected: distinct signer keys required')
    return policy


class SignedPayload(dict):
    """Only verify() creates this value; digest belongs to the verified bytes."""
    def __init__(self, value, raw):
        super().__init__(value)
        self.sha256 = hashlib.sha256(raw).hexdigest()


def secure_digest(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise Rejected('unsafe transcript')
        value = hashlib.sha256()
        for chunk in iter(lambda: source.read(65536), b''):
            value.update(chunk)
        return value.hexdigest()


def read_payload(path):
    # Capture one bounded descriptor, never reopen after signature verification.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > LIMIT:
            raise Rejected('missing, unsafe or oversize signed payload')
        raw = source.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise Rejected('oversize signed payload')
        return raw


def verify(path, role, policy):
    if is_owner_reviewed(policy):
        return owner_reviewed_payload(path, role, policy)
    path = Path(path)
    principals = policy.get('identities', {})
    ratification = is_v2(policy) and role in ('murdock', 'dennis')
    identity = principals.get('owner' if ratification else role)
    namespace = 'owner-review-' + role if ratification else role
    if not identity or len(set(principals.values())) != len(principals):
        raise Rejected('missing/distinct review/owner/runner identities required')
    signature = path.with_name(path.name + '.sig')
    if signature.is_symlink() or not signature.is_file() or signature.stat().st_size > 65536:
        raise Rejected('detached signature missing')
    raw = read_payload(path)
    result = subprocess.run(['ssh-keygen', '-Y', 'verify', '-f', str(TRUST_ROOT / 'allowed_signers'),
                             '-I', identity, '-n', 'slateforge-local-ci-' + namespace,
                             '-s', str(signature)], input=raw, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=10)
    if result.returncode:
        raise Rejected('unverified ' + role + ' provenance')
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise Rejected('signed JSON object required')
    if (is_v2(policy) and value.get('contract') != V2) or (not is_v2(policy) and 'contract' in value):
        raise Rejected('mixed signed payload contracts')
    return SignedPayload(value, raw)


def exact_source(root, repository, commit):
    if not re.fullmatch('[0-9a-f]{40}', commit) or git(root, 'rev-parse', 'HEAD') != commit:
        raise Rejected('stale/current head mismatch')
    if git(root, 'status', '--porcelain'):
        raise Rejected('dirty source')
    remote = git(root, 'remote', 'get-url', 'origin')
    if remote not in ('https://github.com/' + repository + '.git',
                      'https://github.com/' + repository, 'git@github.com:' + repository + '.git'):
        raise Rejected('repository identity mismatch')


def manifest(root):
    path = root / 'local-ci.json'
    if path.is_file():
        spec = load(path)
    elif git(root, 'remote', 'get-url', 'origin') in (
            'git@github.com:EdeAbreu23/slateforge-config.git',
            'https://github.com/EdeAbreu23/slateforge-config.git'):
        path = root / 'scripts/validate-slateforge-config.sh'
        spec = {'schema': 1, 'repository': 'EdeAbreu23/slateforge-config',
                'steps': [{'name': 'config-gate', 'command': ['bash', 'scripts/validate-slateforge-config.sh']}],
                'cleanup': [], 'resource_lifecycle': 'process-groups-only'}
    else:
        raise Rejected('project manifest missing; unknown profile')
    lifecycle = spec.get('resource_lifecycle')
    if lifecycle not in ('process-groups-only', 'cleanup-and-verify'):
        raise Rejected('resource lifecycle not explicitly reviewed')
    if lifecycle == 'cleanup-and-verify' and (not spec.get('cleanup') or not spec.get('resource_verification')):
        raise Rejected('owned resource cleanup and verification commands required')
    if lifecycle == 'process-groups-only' and (spec.get('cleanup') or spec.get('resource_verification')):
        raise Rejected('persistent cleanup requires explicit verification lifecycle')
    names = set()
    for step in spec.get('steps', []) + spec.get('cleanup', []) + spec.get('resource_verification', []):
        name = step.get('name', '')
        if (not re.fullmatch('[A-Za-z0-9_-]{1,80}', name) or name.startswith('tool-') or name in names or
                not isinstance(step.get('command'), list) or not step['command'] or
                not all(isinstance(v, str) for v in step['command'])):
            raise Rejected('invalid/duplicate stage')
        names.add(name)
    if not names or spec.get('schema') != 1:
        raise Rejected('missing stages or unsupported manifest')
    return spec, digest(path)


def authorize(path, root, spec, runner_hash):
    policy = trust()
    approval = verify(path, 'owner', policy)
    required_scope = {'candidate', 'base', 'scope', 'stages', 'expires_at', 'tools', 'support_sha256', 'resource_sha256'}
    if is_owner_reviewed(policy):
        required_scope.remove('expires_at')
    if not required_scope.issubset(approval):
        raise Rejected('incomplete owner scope schema')
    if bound_reviews(policy):
        v2_authorization(approval)
    if is_owner_reviewed(policy):
        _, task = owner_task(policy, approval)
        if task.get('checkout') != str(root.resolve()):
            raise Rejected('owner task checkout mismatch')
    repository = spec['repository']
    head = git(root, 'rev-parse', 'HEAD')
    exact_source(root, repository, head)
    if is_owner_reviewed(policy):
        validity(approval)
    else:
        expires = datetime.datetime.fromisoformat(approval['expires_at'])
        if expires.tzinfo is None or expires <= datetime.datetime.now(datetime.timezone.utc):
            raise Rejected('expired/invalid owner approval')
    expected = {'repository': repository, 'commit': head,
                'manifest_sha256': manifest(root)[1], 'runner_sha256': runner_hash}
    if any(approval.get(k) != v for k, v in expected.items()):
        raise Rejected('owner approval scope does not match exact source/tools')
    project = policy.get('repositories', {}).get(repository, {})
    if runner_hash not in project.get('runner_sha256', []) or expected['manifest_sha256'] not in project.get('manifest_sha256', []):
        raise Rejected('runner/manifest not independently trusted')
    if approval.get('scope') != 'local-ci' or approval.get('stages') != [s['name'] for s in spec['steps'] + spec.get('cleanup', []) + spec.get('resource_verification', [])]:
        raise Rejected('exact stage execution not authorized')
    if approval.get('resource_sha256') != project.get('resource_sha256') or not project.get('resource_sha256'):
        raise Rejected('resource implementation not independently pinned')
    if approval.get('support_sha256') != project.get('support_sha256') or not project.get('support_sha256'):
        raise Rejected('support implementation not independently pinned')
    if set(project['support_sha256']) != {'local_ci_evidence.py', 'local-ci-accept.py', 'local-ci-merge.py'}:
        raise Rejected('exact helper/acceptance/merge support pins required')
    for name, expected_hash in project['support_sha256'].items():
        if Path(name).name != name or digest(root / 'scripts' / name) != expected_hash:
            raise Rejected('support asset provenance mismatch')
    if approval.get('tools') != project.get('tools') or not approval.get('tools'):
        raise Rejected('tool policy not authorized')
    return policy, approval


def accept(root, report_path, authorization_path, review_paths, candidate=None, base=None):
    spec, manifest_hash = manifest(root)
    policy = trust()
    report = verify(report_path, 'runner', policy)
    policy, approval = authorize(authorization_path, root, spec, report['validator_sha256'])
    head = git(root, 'rev-parse', 'HEAD')
    required = {'schema', 'repository', 'commit', 'final_commit', 'source_status', 'final_source_status',
                'started_at', 'finished_at', 'os', 'machine', 'python', 'status', 'steps', 'tools',
                'tool_steps', 'validator_sha256', 'manifest_sha256', 'authorization_sha256', 'lease',
                'candidate', 'base', 'checkout', 'resource_sha256'}
    if not required.issubset(report) or report['schema'] != 1:
        raise Rejected('incomplete report schema')
    if (report['source_status'] != '' or report['final_source_status'] != '' or
            report['checkout'] != str(root.resolve()) or
            report['resource_sha256'] != approval['resource_sha256']):
        raise Rejected('source/host/resource provenance missing')
    for key in ('os', 'machine', 'python'):
        if not isinstance(report[key], str) or not report[key]:
            raise Rejected('host/tool identity missing')
    if (report.get('repository') != spec['repository'] or report.get('commit') != head or
            report.get('final_commit') != head or report.get('source_status') or report.get('final_source_status') or
            report.get('status') not in ('PASS', 'PASS_WITH_ADVISORIES') or
            report.get('manifest_sha256') != manifest_hash or
            report.get('authorization_sha256') != approval.sha256):
        raise Rejected('nonpassing/stale/unsigned-scope report')
    if report.get('tools') != approval['tools'] or report.get('lease', {}).get('state') != 'RELEASED':
        raise Rejected('tool/lease completion not verified')
    if (report.get('candidate') != candidate or report.get('base') != base or
            approval.get('candidate') != candidate or approval.get('base') != base):
        raise Rejected('candidate/base mismatch')
    lease = report['lease']
    if not {'lease_id', 'owner', 'boot_id', 'platform', 'host_id', 'state'}.issubset(lease) or not re.fullmatch('[0-9a-f]{32}', lease['lease_id']):
        raise Rejected('incomplete lease identity')
    expected = [{'name': 'tool-' + str(index), 'command': tool['command'], 'expected_output': tool['expected_output']}
                for index, tool in enumerate(approval['tools'])] + spec['steps'] + spec.get('cleanup', []) + spec.get('resource_verification', [])
    records = report['tool_steps'] + report.get('steps', [])
    if len(records) != len(expected):
        raise Rejected('missing/extra stages')
    directory = Path(report_path).resolve().parent
    for step, record in zip(expected, records):
        allowed_status = ('PASS', 'ADVISORY_FAIL') if step.get('advisory') else ('PASS',)
        expected_command = [part.replace('${REPORT}', str(directory)) for part in step['command']]
        expected_cwd = str((root / step.get('cwd', '.')).resolve())
        required_stage = {'name', 'command', 'cwd', 'started_at', 'finished_at', 'status', 'exit_code', 'log_sha256', 'log_bytes', 'counts'}
        if not required_stage.issubset(record) or record['command'] != expected_command or record['cwd'] != expected_cwd:
            raise Rejected('incomplete/changed stage command provenance')
        if 'expected_output' in step and record.get('expected_output_matches') is not True:
            raise Rejected('tool version evidence missing')
        if (record.get('name') != step['name'] or record.get('status') not in allowed_status or
                (record.get('status') == 'PASS' and record.get('exit_code') != 0) or
                record.get('timed_out') or record.get('exit_code') is None):
            raise Rejected('unsuccessful required stage')
        log = directory / (step['name'] + '.log')
        if log.is_symlink() or log.resolve().parent != directory or digest(log) != record.get('log_sha256') or log.stat().st_size != record.get('log_bytes'):
            raise Rejected('artifact integrity mismatch')
    seen_sessions = set()
    workflow_hash = None
    reviews = {}
    if bound_reviews(policy):
        v2_completed(report, approval, approval.sha256)
    for role in ('murdock', 'dennis'):
        review = verify(review_paths[role], role, policy)
        if (review.get('repository') != spec['repository'] or review.get('commit') != head or
                review.get('verdict') != 'PASS' or review.get('report_sha256') != report.sha256):
            raise Rejected('independent exact-head review missing')
        reviews[role] = review
        if bound_reviews(policy):
            if is_owner_reviewed(policy):
                trusted_bytes(Path(review_paths[role]).with_name('workflow.json'))
                trusted_bytes(Path(review_paths[role]).with_name(role + '.transcript'))
            workflow_hash = v2_review(role, review, review_paths[role], report, approval, approval.sha256, policy, seen_sessions, workflow_hash)
    completion_names = {s['name'] for s in spec.get('cleanup', []) + spec.get('resource_verification', [])}
    if any(row['status'] != 'PASS' or row['exit_code'] != 0 for row in records if row['name'] in completion_names):
        raise Rejected('owned resource cleanup/verification did not pass')
    result = {'state': 'ACCEPTED', 'repository': spec['repository'], 'commit': head,
              'report_sha256': report.sha256, 'candidate': candidate, 'base': base}
    if bound_reviews(policy):
        result.update(contract=policy['contract'], run_id=approval['run_id'], authorization_sha256=approval.sha256,
                      review_sha256={role:value.sha256 for role,value in reviews.items()},
                      review_ratified_at='')
        result['review_ratified_at'] = max(timestamp(v['issued_at']) for v in reviews.values()).isoformat()
    if is_owner_reviewed(policy):
        result['authenticity'] = AUTHENTICITY
    return result
