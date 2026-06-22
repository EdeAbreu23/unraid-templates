#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 <<'PY'
from pathlib import Path
from urllib.parse import urlparse
import re
import sys
import xml.etree.ElementTree as ET

required_tags = [
    "Name",
    "Repository",
    "Registry",
    "Network",
    "Shell",
    "Privileged",
    "Support",
    "Project",
    "Overview",
    "Category",
    "WebUI",
    "Icon",
]

secret_terms = re.compile(
    r"(password|passwd|token|secret|api[_ -]?key|private[_ -]?key|service[_ -]?role)",
    re.IGNORECASE,
)
placeholder_terms = re.compile(
    r"(^$|placeholder|change[_-]?me|your_|<.*>|\\[.*\\])",
    re.IGNORECASE,
)
private_network = re.compile(r"(192\.168\.|10\.\d{1,3}\.|172\.(1[6-9]|2\d|3[01])\.)")
trusted_network_warning_terms = {
    "OpsSlate": (
        "requires app-native administrator authentication",
        "basic credentials require https",
        "never expose this port directly to the public internet",
        "trusted lan",
        "vpn",
        "firewall allowlist",
        "authenticated reverse proxy",
    ),
    "SlateWatch": (
        "no app-native authentication",
        "never expose this port directly to the public internet",
        "trusted lan",
        "vpn",
        "firewall allowlist",
        "authenticated reverse proxy",
    ),
}

errors: list[str] = []
warnings: list[str] = []

template_paths = sorted(Path("templates").glob("*.xml"))
if not template_paths:
    errors.append("No templates/*.xml files found.")

for path in template_paths:
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        errors.append(f"{path}: XML parse failed: {exc}")
        continue

    for tag in required_tags:
        text = (root.findtext(tag) or "").strip()
        if not text and tag not in {"MyIP"}:
            errors.append(f"{path}: missing required <{tag}> value")

    if (root.findtext("Network") or "").strip().lower() == "host":
        errors.append(f"{path}: host networking is not allowed by default")

    if (root.findtext("Privileged") or "").strip().lower() != "false":
        errors.append(f"{path}: <Privileged> must be explicitly false")

    repository = (root.findtext("Repository") or "").strip()
    if repository.endswith(":latest"):
        warnings.append(f"{path}: repository uses mutable :latest tag; document update risk before release use")

    icon = (root.findtext("Icon") or "").strip()
    icon_name = Path(urlparse(icon).path).name
    if not icon_name:
        errors.append(f"{path}: icon URL does not include a filename")
    elif not Path("images", icon_name).is_file():
        errors.append(f"{path}: icon URL references missing images/{icon_name}")

    app_name = (root.findtext("Name") or "").strip()
    overview = (root.findtext("Overview") or "").strip().lower()
    if app_name in trusted_network_warning_terms:
        for warning_term in trusted_network_warning_terms[app_name]:
            if warning_term not in overview:
                errors.append(
                    f"{path}: {app_name} overview must include trusted-network warning term {warning_term!r}"
                )

    for config in root.findall("Config"):
        name = config.attrib.get("Name", "")
        target = config.attrib.get("Target", "")
        default = config.attrib.get("Default", "")
        value = (config.text or "").strip()
        combined_label = f"{name} {target}"

        if private_network.search(default) or private_network.search(value):
            errors.append(f"{path}: {name or target} contains a private network default")

        if "/var/run/docker.sock" in default or "/var/run/docker.sock" in value:
            errors.append(f"{path}: {name or target} mounts Docker socket by default")

        if secret_terms.search(combined_label):
            for field_name, field_value in (("Default", default), ("value", value)):
                if field_value and not placeholder_terms.search(field_value):
                    errors.append(
                        f"{path}: {name or target} has secret-like {field_name} content; leave it blank or placeholder-only"
                    )

if warnings:
    print("Template validation warnings:")
    for warning in warnings:
        print(f"  - {warning}")

if errors:
    print("Template validation failed:")
    for error in errors:
        print(f"  - {error}")
    sys.exit(1)

print(f"Template validation passed for {len(template_paths)} template(s).")
PY

if git rev-parse --verify origin/main >/dev/null 2>&1; then
    git diff --check origin/main...HEAD
fi
git diff --check
git diff --cached --check
