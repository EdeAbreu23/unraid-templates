#!/usr/bin/env python3
"""Supported cooperative merge gate. Never creates checks or bypasses protections.

Actual merge additionally requires distinct current owner-signed merge approval.
Independent GitHub/API/manual callers remain outside this cooperative boundary.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
from local_ci_evidence import accept, digest, git, trust, verify, Rejected, bound_reviews, v2_merge, is_owner_reviewed, validity


def provider(repository, number):
    raw = subprocess.check_output(['gh', 'api', 'repos/' + repository + '/pulls/' + str(number)], text=True)
    info = json.loads(raw)
    if info.get('state') != 'open' or info.get('draft') or info.get('merged'):
        raise Rejected('PR is not an open nondraft candidate')
    return info


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'report', 'authorization', 'murdock', 'dennis'):
        p.add_argument('--' + name, required=True, type=Path)
    p.add_argument('--pr', required=True, type=int)
    p.add_argument('--merge-authorization', type=Path)
    args = p.parse_args()
    try:
        root = args.repo.resolve()
        # Parse only to find repository; no trust is granted before signatures.
        from local_ci_evidence import load
        report = load(args.report)
        repository = report['repository']
        before = provider(repository, args.pr)
        if before['head']['repo']['full_name'] != repository:
            raise Rejected('fork merge requires separately supported provenance')
        base = before['base']['sha']
        result = accept(root, args.report, args.authorization,
                        {'murdock': args.murdock, 'dennis': args.dennis}, None, base)
        policy = trust()
        if bound_reviews(policy):
            dennis = verify(args.dennis, 'dennis', policy)
            if (dennis.sha256 != result['review_sha256']['dennis'] or
                    dennis.get('pr') != {'repository': repository, 'number': args.pr, 'head': before['head']['sha'], 'base': base}):
                raise Rejected('Dennis reviewed a different actual PR')
        if before['head']['sha'] != result['commit']:
            raise Rejected('provider PR head differs from accepted source')
        if not args.merge_authorization:
            print(json.dumps(dict(result, merge='NOT_REQUESTED', provider_protection='UNKNOWN_UNLESS_PROVIDER_ENFORCES')))
            return 0
        approval = verify(args.merge_authorization, 'owner', policy)
        if bound_reviews(policy):
            execution = verify(args.authorization, 'owner', policy)
            if execution.sha256 != result['authorization_sha256']:
                raise Rejected('execution authorization changed after acceptance')
            v2_merge(approval, result, execution, args.pr)
        import datetime
        if is_owner_reviewed(policy):
            validity(approval)
        else:
            expires = datetime.datetime.fromisoformat(approval['expires_at'])
            if expires.tzinfo is None or expires <= datetime.datetime.now(datetime.timezone.utc):
                raise Rejected('merge approval expired')
        expected = {'scope': 'merge', 'repository': repository, 'pr': args.pr,
                    'commit': result['commit'], 'base': base, 'method': 'merge',
                    'report_sha256': result['report_sha256']}
        if any(approval.get(k) != v for k, v in expected.items()):
            raise Rejected('separate exact merge approval missing')
        again = provider(repository, args.pr)
        if again['head']['sha'] != result['commit'] or again['base']['sha'] != base:
            raise Rejected('provider candidate changed during gate')
        # Match-head is a provider precondition. Recheck base immediately before
        # invocation; GitHub provides no atomic base-SHA precondition, so this
        # supports exact PR-head evidence, not merge-candidate validation.
        subprocess.run(['gh', 'pr', 'merge', str(args.pr), '--repo', repository,
                        '--merge', '--match-head-commit', result['commit']], check=True)
        print(json.dumps(dict(result, merge='PROVIDER_REQUEST_COMPLETED',
                              base_constraint='rechecked; not atomic at provider')))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(json.dumps({'state': 'REJECTED', 'reason': str(exc)}))
        return 2


if __name__ == '__main__':
    sys.exit(main())
