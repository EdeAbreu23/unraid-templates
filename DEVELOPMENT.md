# Development workflow

Codex implements changes and runs the relevant native tests under the owner’s task authorization. GitHub Codex Code Review reviews pull requests automatically; Elvis approves merges. Michael, Murdock and Dennis are available when needed, not mandatory CI infrastructure.

Custom SlateForge Local CI and GitHub Actions test CI are retired. Preserve native test suites, dependency locks, deployment and publishing capabilities, security checks, historical evidence, ownership receipts and private data boundaries. No merge or deployment is authorized by test results.

## Native commands

Run relevant commands from the indicated directory, using the pinned project toolchain and synthetic data. Dependency installation and platform checks are separate choices; this is not an automated pipeline.

- From `.`: `bash -n scripts/validate-templates.sh`
- From `.`: `bash scripts/validate-templates.sh`
- From `.`: `git diff --check 4b825dc642cb6eb9a060e54bf8d69288fbee4904 HEAD`
