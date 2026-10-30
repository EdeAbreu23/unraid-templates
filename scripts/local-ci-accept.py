#!/usr/bin/env python3
"""Read-only consumer of owner/runner/reviewer-signed exact-head Local CI evidence."""
import argparse
import json
from pathlib import Path
import sys
from local_ci_evidence import accept


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--authorization', required=True, type=Path)
    parser.add_argument('--murdock', required=True, type=Path)
    parser.add_argument('--dennis', required=True, type=Path)
    parser.add_argument('--candidate')
    parser.add_argument('--base')
    args = parser.parse_args()
    try:
        result = accept(args.repo.resolve(), args.report, args.authorization,
                        {'murdock': args.murdock, 'dennis': args.dennis}, args.candidate, args.base)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({'state': 'REJECTED', 'reason': str(exc)}))
        return 2


if __name__ == '__main__':
    sys.exit(main())
