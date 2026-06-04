# unraid-templates

Public Unraid template and asset repository for self-hosted apps maintained by Elvis De Abreu.

This repo exists so Unraid can fetch public assets such as Docker icons and, later, install templates without exposing the private source repositories for the apps themselves.

## Status

Docs baseline ready. This repo is a public template and asset support repo only; it is not an application runtime.

## Repository ownership

Belongs here:

- Public Unraid XML templates.
- Public app icons and asset README files.
- Template validation notes and public install metadata.

Does not belong here:

- Product implementation docs for private app repos.
- Private deployment values, private app URLs, secrets, tokens, or local `.env` contents.
- Runtime evidence for the applications themselves.

## Validation

Use the local validator plus `git diff --check`. Do not deploy, import into Unraid, or publish as part of template validation.

```bash
bash scripts/validate-templates.sh
```

The validator parses every XML template, checks required metadata fields, confirms template icon URLs point at tracked files under `images/`, rejects privileged or host-network defaults, and rejects secret-like defaults that are not blank or placeholder-only. Mutable image tags are reported as warnings because update policy is still a release decision for each app.

See [Image Tag And Update Policy](docs/IMAGE_TAG_UPDATE_POLICY.md) for the
current tag policy. `:latest` remains a warning, not a failure, until an app
owner approves a stricter release/update policy.

Manual Unraid import/render checks must use
[Manual Unraid Smoke Checklist](docs/UNRAID_SMOKE_CHECKLIST.md). Do not claim
Unraid runtime PASS without real approved import/render evidence.

## Documentation map

- [Docs](docs/README.md)
- [Image Tag And Update Policy](docs/IMAGE_TAG_UPDATE_POLICY.md)
- [Manual Unraid Smoke Checklist](docs/UNRAID_SMOKE_CHECKLIST.md)
- [Images](images/README.md)
- [Templates](templates/README.md)

## Planned apps

| App | Public icon path | Template path |
| --- | --- | --- |
| SlateLedger | `images/slateledger-icon.png` | `templates/slateledger.xml` |
| SlateWatch | `images/slatewatch-icon.png` | `templates/slatewatch.xml` |
| OpsSlate | `images/opsslate-icon.png` | `templates/opsslate.xml` |

## Current structure

```text
images/
  slateledger-icon.png
  slatewatch-icon.png
  opsslate-icon.png

templates/
  slateledger.xml
  slatewatch.xml
  opsslate.xml
scripts/
  validate-templates.sh
```
