#!/usr/bin/env python3
"""
Simple static checks for MCP tool definitions.

Scans JSON tool definitions for high-signal risk patterns.
"""

import json
import re
import sys
from pathlib import Path

STEERING_PATTERNS = [
    r"ignore previous",
    r"ignore all previous",
    r"before using this tool",
    r"first call",
    r"you must",
    r"override",
    r"system prompt",
]

SENSITIVE_PATHS = [
    r"~/.ssh",
    r"~/.aws",
    r"\.env",
    r"credentials",
    r"id_rsa",
    r"secret",
    r"token",
]

BROAD_CAPABILITIES = [
    r"shell",
    r"execute command",
    r"run arbitrary",
    r"filesystem.*\/",
    r"admin",
]

UNPINNED_PACKAGES = [
    r"npx\s+[^\s]+@latest",
    r"uvx\s+[^\s]+(?:\s|$)",
    r"docker\s+run\s+[^\s]+:latest",
]

OPEN_URL_PATTERNS = [
    r"fetch any url",
    r"call the provided endpoint",
    r"request the given url",
    r"arbitrary url",
    r"webhook url",
]

BROAD_FS_ROOTS = [
    r"rooted at /",
    r"root.*\$home",
    r"filesystem.*home",
    r"access to the entire filesystem",
]


def check_description(desc: str) -> list:
    findings = []
    lower = desc.lower()

    for pat in STEERING_PATTERNS:
        if re.search(pat, lower):
            findings.append({"severity": "high", "type": "steering_language", "pattern": pat})

    for pat in SENSITIVE_PATHS:
        if re.search(pat, lower):
            findings.append(
                {
                    "severity": "high",
                    "type": "sensitive_path_reference",
                    "pattern": pat,
                }
            )

    for pat in BROAD_CAPABILITIES:
        if re.search(pat, lower):
            findings.append({"severity": "medium", "type": "broad_capability", "pattern": pat})

    for pat in UNPINNED_PACKAGES:
        if re.search(pat, lower):
            findings.append({"severity": "medium", "type": "unpinned_package", "pattern": pat})

    for pat in OPEN_URL_PATTERNS:
        if re.search(pat, lower):
            findings.append({"severity": "high", "type": "open_url_argument", "pattern": pat})

    for pat in BROAD_FS_ROOTS:
        if re.search(pat, lower):
            findings.append({"severity": "medium", "type": "broad_filesystem_root", "pattern": pat})

    # Simple obfuscation signal
    if re.search(r"[A-Za-z0-9+/]{40,}={0,2}", desc):
        findings.append({"severity": "medium", "type": "possible_encoded_content"})

    return findings


def scan_tools(tools: list) -> list:
    results = []
    for tool in tools:
        name = tool.get("name", "unknown")
        desc = tool.get("description", "")
        findings = check_description(desc)
        if findings:
            results.append({"tool": name, "findings": findings})
    return results


def main():
    if len(sys.argv) < 2:
        print("Usage: scan.py <tools.json>", file=sys.stderr)
        sys.exit(1)

    path = Path(sys.argv[1])
    data = json.loads(path.read_text())
    tools = data if isinstance(data, list) else data.get("tools", [])
    results = scan_tools(tools)

    if not results:
        print("No high-signal findings.")
        return

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
