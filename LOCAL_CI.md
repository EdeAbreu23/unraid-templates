# Codex-managed LOCAL CI

With explicit current owner authorization (replace TASK/base with the provisioned scope; reconcile memory/output estimates for the actual run):

```sh
python3 scripts/local-ci.py \
  --authorization "$HOME/.config/SlateForge/local-ci/owner-reviewed/TASK/run/authorization.json" \
  --report-dir "$HOME/.config/SlateForge/local-ci/owner-reviewed/TASK/run/new-report" \
  --resource-controls /Users/edeabreu/SlateForge/slateforge-config \
  --memory-gib 2 --output-gib 2 --base FULL_APPROVED_BASE_SHA
```

Pins Python3.9.6 and Bash3.2.57(1)-release on the approved local macOS arm64 environment. The former Ubuntu job had unpinned Bash/Python; Ubuntu execution remains unverified and is not implied by the local result. There are no project dependency installs or locks. The gate retains the complete existing `bash scripts/validate-templates.sh` unchanged: XML required metadata, image references, host-network/privilege/private-network/Docker-socket/secret-default restrictions, trusted-network warnings and diff checks. Existing mutable :latest warnings remain visible. Shell syntax and synthetic runner safety checks supplement the original gate.

The runner requires a clean exact commit, refuses private inputs, uses fresh HOME, writes commands/exits/toolchain/OS/static results and test summaries into a private external evidence directory, and continues independent checks after failures. Reports from another revision are not current proof. Murdock engineering and Dennis final PR reviews remain mandatory; record them separately against exact HEAD. No GitHub status is fabricated.

This only reads repository templates and images. It never contacts Unraid, imports a template, validates real private host configuration, starts containers, publishes images or deploys anything. Preserve workflow/tests. Retire the ordinary hosted Template Validation workflow only after local proof and reviews. All PRs remain unmerged pending separate owner authorization.

The whitespace gate checks the complete committed SHA-1 tree against Git’s empty tree, so it detects committed whitespace even with a clean working tree and no origin/main ref. The manifest records the canonical repository; authorization requires its exact credential-free origin URL. Invalid or missing origins fail before report creation without recording credential values. Synthetic guards cover a committed whitespace failure, missing/credential-bearing remotes and SIGTERM during startup, execution, teardown and bounded resource cleanup. Existing template assertions and mutable-tag warnings remain unchanged.

## Canonical authorization, admission and evidence

The four runner/acceptance assets are copied unchanged from reviewed shared main
`68aead0` (PR #408). `local-ci.json` identifies the exact GitHub repository and
explicitly declares `process-groups-only`: all listed commands are foreground
build, install, static or synthetic-test commands. None starts a daemon, service,
VM, container or escaped persistent workload. The runner stops only its owned
stage groups, heartbeats the actual reservation and requires verified group
completion before release. Unknown ownership retains recovery-required state.
Adding a persistent service requires reviewed cleanup and resource verification;
this declaration cannot authorize an existing service to be stopped.

The entry point requires a clean exact commit and exact credential-free origin,
private ignored-input refusal, independently pinned runner/manifest/support/tool
and nine controller hashes, and a genuine fresh host reservation through the
reviewed primary `slateforge-config` checkout. Check-only admission, a historical
receipt and synthetic reservations do not authorize or prove this execution.
Retain complete private report/log bytes and exact hashes, tool versions, stage
commands/exits and reported counts. Changed source/base/pins require matching
new authorization and evidence. No GitHub success status is fabricated.

Host policy is provisioned separately in the fixed private
`~/.config/SlateForge/local-ci` directory. The owner may explicitly select schema3
`owner-reviewed-v1` only after review/tests. In that mode the bounded task approval
and original authenticated Elvis approval capture, run authorization, reports and
independent review exports stay in private same-user custody beneath
`owner-reviewed/<task_id>/`. Reports must use a new canonical directory inside
that task. Use the literal authenticity label
`owner-reviewed; NOT cryptographically authenticated`; no synthetic signatures,
keys or manufactured owner/reviewer captures satisfy real acceptance.

Schema1/schema2 signed modes retain their distinct key, signature and custody
requirements and never fall back to schema3. For a selected signed mode, add
`--signing-key /private/externally-provisioned-runner-key` to the command above;
key provisioning is separate owner action. Schema3 rejects a signing-key option.
The authorization binds exact head, base, stage order, tools, support/controllers
and actual host. The bounded task grants no merge permission.

After the genuine completed run, independent Murdock and Dennis reviews must
bind that report, source, request, workflow and original authenticated transcript
bytes. `scripts/local-ci-accept.py` consumes the report, authorization and both
reviews with the exact base. `scripts/local-ci-merge.py` remains a cooperating
gate requiring separately captured final exact-revision Elvis merge approval;
provider protections and base-race limitations remain. Leave the PR unmerged.

`python3 -B scripts/test-local-ci.py` is the focused synthetic runner suite, only
under explicit task authorization and genuine outer host admission. It creates
private temporary HOME/trust, disposable Git fixtures, synthetic owner records
and fake controller modules; these never touch the real trust/store and confer
no production authority. It retains failure/dependency/advisory, private-input,
credential redaction, timeout, signal, descendant cleanup and tool-pin checks.
The canonical contract rejects dirty or invalid-origin fixtures before creating
a report; positive receipts come only from exact-origin clean fixtures.
