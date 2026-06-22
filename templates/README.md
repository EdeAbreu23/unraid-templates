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

## Trusted-network applications

OpsSlate and SlateWatch expose control operations and do not currently provide
app-native authentication. Their template overviews must prominently state
that they are trusted-network applications and must never be exposed directly
to the public internet.

Before installing either application, require one or more of these access
boundaries:

- trusted-LAN-only access with no router port forwarding;
- VPN or Tailscale access;
- host firewall or VLAN allowlists; or
- an authenticated reverse proxy or identity-aware access proxy.

Publishing a container port is not authentication. Unraid WebUI visibility,
hidden application buttons, and application rate limits are not authorization
controls.

Image tag policy lives in
[Image Tag And Update Policy](../docs/IMAGE_TAG_UPDATE_POLICY.md). Mutable
`:latest` image references are allowed for now and remain validator warnings,
not failures, until an app-specific release/update policy is approved.

Run validation before opening or updating a PR:

```bash
bash scripts/validate-templates.sh
```
