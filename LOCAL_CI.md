# Codex-managed LOCAL CI

With explicit current owner authorization:

```sh
python3 scripts/local-ci.py --authorization 'Current owner approval and scope' --report-dir /private/new-evidence-directory
```

Pins Python3.9.6 and Bash3.2.57(1)-release on the approved local macOS arm64 environment. The former Ubuntu job had unpinned Bash/Python; Ubuntu execution remains unverified and is not implied by the local result. There are no project dependency installs or locks. The gate retains the complete existing `bash scripts/validate-templates.sh` unchanged: XML required metadata, image references, host-network/privilege/private-network/Docker-socket/secret-default restrictions, trusted-network warnings and diff checks. Existing mutable :latest warnings remain visible. Shell syntax and synthetic runner safety checks supplement the original gate.

The runner requires a clean exact commit, refuses private inputs, uses fresh HOME, writes commands/exits/toolchain/OS/static results and test summaries into a private external evidence directory, and continues independent checks after failures. Reports from another revision are not current proof. Murdock engineering and Dennis final PR reviews remain mandatory; record them separately against exact HEAD. No GitHub status is fabricated.

This only reads repository templates and images. It never contacts Unraid, imports a template, validates real private host configuration, starts containers, publishes images or deploys anything. Preserve workflow/tests. Retire the ordinary hosted Template Validation workflow only after local proof and reviews. All PRs remain unmerged pending separate owner authorization.
