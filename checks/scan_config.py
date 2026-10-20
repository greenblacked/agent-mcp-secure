#!/usr/bin/env python3
"""
Scan MCP server launch configurations for high-risk patterns.

Looks at command lines or structured configs for:
- Unpinned package launchers
- Overly broad filesystem roots
- Sensitive environment variables passed in cleartext

Exit codes: 0 no findings at or above --fail-on, 1 findings, 2 usage or input error.
"""

import argparse
import json
import re
import sys
from pathlib import Path

from scan import FAIL_ON_CHOICES, exit_code, load_json

UNPINNED = [
    r"npx\s+[^\s]+@latest",
    r"uvx\s+[^\s]+(?:\s|$)",
    r"docker\s+run\s+[^\s]+:latest",
]

# Matched against the flattened command line; a root must be the whole argument,
# so "--root /data/documents" is not flagged.
BROAD_ROOTS = [
    r"--root[\s=]+(?:/|~/?|\$home)(?:\s|$)",
    r"filesystem\S*(?:\s+\S+)*\s+(?:/|~/?|\$home)(?:\s|$)",
]

SENSITIVE_ENV = [
    r"AWS_SECRET_ACCESS_KEY",
    r"GITHUB_TOKEN",
    r"OPENAI_API_KEY",
    r"ANTHROPIC_API_KEY",
]


def command_line(config: dict | str) -> str:
    """Flatten a launch config into a single command line."""
    if isinstance(config, str):
        return config
    args = config.get("args") or []
    if not isinstance(args, list):
        args = [args]
    return " ".join(str(part) for part in [config.get("command", ""), *args])


def check_launch(config: dict | str) -> list:
    findings = []
    text = config if isinstance(config, str) else json.dumps(config)
    lower = command_line(config).lower()

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


def report_config(data, fail_on: str) -> int:
    findings = check_launch(data)
    if not findings:
        print("No high-signal findings.")
        return 0
    print(json.dumps(findings, indent=2))
    return exit_code(findings, fail_on)


def main():
    parser = argparse.ArgumentParser(description="Scan an MCP server launch config for high-risk patterns.")
    parser.add_argument("target", help="JSON config file, or a command line to scan as-is")
    parser.add_argument("--fail-on", choices=FAIL_ON_CHOICES, default="medium", help="lowest severity that fails")
    args = parser.parse_args()

    path = Path(args.target)
    data = load_json(path) if path.exists() else args.target
    sys.exit(report_config(data, args.fail_on))


if __name__ == "__main__":
    main()
