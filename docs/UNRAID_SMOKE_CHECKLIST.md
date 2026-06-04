# Manual Unraid Smoke Checklist

Use this checklist only when a real Unraid import/render smoke test is approved.
Keep all concrete deployment values outside git.

## Preconditions

- The target Unraid system is approved for non-production smoke testing.
- The template branch or raw template URL under test is identified.
- Required app-owned deployment prerequisites are satisfied outside this repo.
- No real passwords, API keys, tokens, private LAN values, internal hostnames,
  cookies, or connection strings will be copied into commits, PRs, chat,
  screenshots, or shared logs.

## Checklist

1. Record the repo, commit SHA, template path, and test date.
2. Import or preview the template in Unraid.
3. Confirm the template name, repository image reference, category, WebUI field,
   icon, support URL, and project URL render as expected.
4. Confirm bridge networking and `Privileged=false` remain the default.
5. Confirm required variables are visible and secret-like variables are masked
   or blank/placeholder-only.
6. Confirm no template field displays real private LAN values, passwords,
   tokens, private URLs, or local `.env` values.
7. If container creation is in scope, use only approved placeholder or
   non-production values supplied outside git.
8. If app startup is in scope, record only status codes, sanitized health shape,
   and whether the WebUI opened. Do not record full logs if they contain private
   values.

## Evidence Template

```text
Unraid Template Smoke Verdict:
PASS, PARTIAL, BLOCKED, or FAIL

Repository:
Commit:
Template:
Unraid target label:
Date:

Validated:
- XML/template import or preview:
- Icon rendered:
- Repository image reference:
- Network/privileged defaults:
- Secret-like fields masked or placeholder-only:
- WebUI field rendered:
- Optional container create:
- Optional app health/WebUI:

Blocked:
- <missing app image, prerequisite, approved test host, or non-production config>

Risk:
- <runtime behavior, app deployment, or update policy not proven>

Evidence handling:
- No real passwords, tokens, connection strings, private LAN values, cookies, or
  private URLs were copied into git, PRs, chat, screenshots, or shared logs.
```

Do not call the result `Runtime PASS` unless a real approved Unraid run was
performed and the evidence above is filled with redacted, non-secret results.
