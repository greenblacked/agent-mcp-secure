#!/usr/bin/env python3
"""
Scan MCP server launch configurations for high-risk patterns.

Looks at command lines or structured configs for:
- Unpinned package launchers
- Overly broad filesystem roots
- Sensitive environment variables passed in cleartext
"""

import json
import re
import sys
from pathlib import Path

UNPINNED = [
    r"npx\s+[^\s]+@latest",
    r"uvx\s+[^\s]+(?:\s|$)",
    r"docker\s+run\s+[^\s]+:latest",
]

# Matched against the lowercased command line. Each root must be the whole
# argument, so a scoped path such as "--root /data/documents" is not flagged.
BROAD_ROOTS = [
    r"--root(?:\s+|=)/(?=\s|$)",
    r"--root(?:\s+|=)~/?(?=\s|$)",
    r"--root(?:\s+|=)\$home/?(?=\s|$)",
    r"filesystem\S*\s+/(?=\s|$)",
]

SENSITIVE_ENV = [
    r"AWS_SECRET_ACCESS_KEY",
    r"GITHUB_TOKEN",
    r"OPENAI_API_KEY",
    r"ANTHROPIC_API_KEY",
]


def check_launch(config: dict | str) -> list:
    findings = []
    if isinstance(config, str):
        text = config
    else:
        # Scan the launch command as it would run, plus the raw config for env keys.
        argv = [config.get("command", ""), *config.get("args", [])]
        text = " ".join(str(part) for part in argv) + "\n" + json.dumps(config)
    lower = text.lower()

    for pat in UNPINNED:
        if re.search(pat, lower):
            findings.append({"severity": "medium", "type": "unpinned_launcher", "pattern": pat})

    for pat in BROAD_ROOTS:
        if re.search(pat, lower):
            findings.append({"severity": "high", "type": "broad_filesystem_root", "pattern": pat})

    for pat in SENSITIVE_ENV:
        if re.search(pat, text):
            findings.append({"severity": "high", "type": "sensitive_env_in_config", "pattern": pat})

    return findings


def main():
    if len(sys.argv) < 2:
        print("Usage: scan_config.py <config.json|command-line>", file=sys.stderr)
        sys.exit(1)

    path = Path(sys.argv[1])
    if path.exists():
        data = json.loads(path.read_text())
    else:
        data = sys.argv[1]

    findings = check_launch(data)
    if not findings:
        print("No high-signal findings.")
        return

    print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()
