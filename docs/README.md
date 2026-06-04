# unraid-templates Documentation

This folder can hold durable documentation for the public Unraid template and asset repository.

## What Belongs Here

- Public Unraid template documentation.
- Public icon and template validation notes.
- Docs about how this repository references public app assets.

## What Does Not Belong Here

- Product implementation docs for OpsSlate, SlateWatch, SlateLedger, LeagueSlate, Amor y Poesia, or the personal website.
- Private deployment values, private app URLs, secrets, tokens, or local `.env` contents.
- Source code or runtime docs for the private application repositories.

## Validation

Use local XML/image inspection and `git diff --check`. Do not publish or deploy from documentation cleanup work.

Policy references:

- [Image Tag And Update Policy](IMAGE_TAG_UPDATE_POLICY.md)
- [Manual Unraid Smoke Checklist](UNRAID_SMOKE_CHECKLIST.md)

Static validation and XML inspection are not Unraid runtime PASS. Runtime PASS
requires a real approved import/render run with redacted evidence.

## Current Status

Docs baseline ready.
