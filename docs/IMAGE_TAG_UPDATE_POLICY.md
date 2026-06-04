# Image Tag And Update Policy

This repository publishes Unraid XML templates and public icon assets. It does
not publish app images and does not prove that an app release is production
ready.

## Current Policy

- Template `Repository` values may use `:latest` while app release tagging is
  still being standardized.
- `:latest` is a validation warning, not a failing condition.
- A template PR that changes image references must state whether it keeps
  `:latest`, pins a version tag, or pins a digest.
- Do not switch a template from one tag strategy to another without approval
  from the owning app repo.
- Do not publish, release, or announce templates from this repo without a
  separate release decision.

## Preferred Future Policy

When the app repos have stable release automation, prefer immutable or
versioned references for install templates:

- semantic version tags, such as `1.2.3`, when app images are released that way;
- date/build tags, such as `2026.06.04`, when that is the app's release model;
- digest pins only when operators have an update process that can refresh them
  intentionally.

Keep mutable tags documented as update-risk warnings until an app-specific
release policy is approved.

## Validation Boundary

`bash scripts/validate-templates.sh` checks XML structure, required fields,
public icon references, unsafe defaults, private-network defaults, Docker socket
mounts, and secret-like defaults. It reports mutable `:latest` tags as warnings.

Passing validation does not mean:

- the template was imported into Unraid;
- the container started successfully;
- the WebUI opened;
- app health checks passed;
- any app runtime behavior passed.

Unraid runtime evidence must come from the manual checklist in
[Manual Unraid Smoke Checklist](UNRAID_SMOKE_CHECKLIST.md).
