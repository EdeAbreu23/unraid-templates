# Templates

Public Unraid XML templates for self-hosted applications.

## Current templates

- opsslate.xml
- slateledger.xml
- slatewatch.xml

## Template contract

Every template must include these fields:

- `Name`
- `Repository`
- `Registry`
- `Network`
- `Shell`
- `Privileged`
- `Support`
- `Project`
- `Overview`
- `Category`
- `WebUI`
- `Icon`

Templates must use bridge networking by default, set `Privileged` to `false`, avoid Docker socket mounts, and keep secret-like values blank or placeholder-only. Public templates must not contain private LAN URLs, real host paths beyond generic Unraid appdata examples, tokens, API keys, or real passwords.

Image tag policy lives in
[Image Tag And Update Policy](../docs/IMAGE_TAG_UPDATE_POLICY.md). Mutable
`:latest` image references are allowed for now and remain validator warnings,
not failures, until an app-specific release/update policy is approved.

Run validation before opening or updating a PR:

```bash
bash scripts/validate-templates.sh
```
