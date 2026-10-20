#!/usr/bin/env python3
"""
Simple static checks for MCP tool definitions.

Scans JSON tool definitions for high-signal risk patterns.

Exit codes: 0 no findings at or above --fail-on, 1 findings, 2 usage or input error.
"""

import argparse
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
    r"from any url",
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

ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")

RISKY_PARAM_NAMES = {
    "url",
    "endpoint",
    "webhook",
    "host",
    "path",
    "filepath",
    "file_path",
}


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

    if re.search(r"[A-Za-z0-9+/]{40,}={0,2}", desc):
        findings.append({"severity": "medium", "type": "possible_encoded_content"})

    # Zero-width characters (common obfuscation)
    if ZERO_WIDTH.search(desc):
        findings.append({"severity": "medium", "type": "zero_width_characters"})

    # High ratio of non-ASCII (possible obfuscation or unexpected content)
    if desc:
        non_ascii = sum(1 for c in desc if ord(c) > 127)
        if non_ascii / len(desc) > 0.3:
            findings.append({"severity": "low", "type": "high_non_ascii_ratio"})

    return findings


def check_schema(schema: dict) -> list:
    """Look for free-form string parameters that commonly enable SSRF or path issues."""
    findings = []
    if not isinstance(schema, dict):
        return findings

    properties = schema.get("properties") or {}
    if not isinstance(properties, dict):
        return findings

    for name, prop in properties.items():
        if not isinstance(prop, dict):
            continue
        if prop.get("type") != "string":
            continue
        lower_name = name.lower()
        if lower_name in RISKY_PARAM_NAMES and "enum" not in prop and "pattern" not in prop:
            findings.append(
                {
                    "severity": "medium",
                    "type": "unconstrained_risky_parameter",
                    "parameter": name,
                }
            )
    return findings


def scan_tools(tools: list) -> list:
    results = []
    for tool in tools:
        name = tool.get("name", "unknown")
        desc = tool.get("description", "")
        findings = check_description(desc)

        schema = tool.get("inputSchema") or tool.get("input_schema") or {}
        findings.extend(check_schema(schema))

        if findings:
            results.append({"tool": name, "findings": findings})
    return results


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}
FAIL_ON_CHOICES = ["low", "medium", "high", "none"]


def exit_code(findings: list, fail_on: str) -> int:
    """Return 1 if any finding is at or above the fail_on severity, else 0."""
    if fail_on == "none":
        return 0
    threshold = SEVERITY_RANK[fail_on]
    return int(any(SEVERITY_RANK.get(f.get("severity"), 0) >= threshold for f in findings))


def load_json(path: Path):
    """Load a JSON file, exiting with code 2 on a missing or malformed file."""
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        print(f"File not found: {path}", file=sys.stderr)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Cannot read {path}: {exc}", file=sys.stderr)
    sys.exit(2)


def tools_from(data) -> list:
    return data if isinstance(data, list) else data.get("tools", [])


def report_tools(data, fail_on: str) -> int:
    results = scan_tools(tools_from(data))
    if not results:
        print("No high-signal findings.")
        return 0
    print(json.dumps(results, indent=2))
    return exit_code([f for r in results for f in r["findings"]], fail_on)


def main():
    parser = argparse.ArgumentParser(description="Scan MCP tool definitions for high-signal risk patterns.")
    parser.add_argument("file", type=Path, help="JSON file with a list of tools or a {'tools': [...]} object")
    parser.add_argument("--fail-on", choices=FAIL_ON_CHOICES, default="medium", help="lowest severity that fails")
    args = parser.parse_args()
    sys.exit(report_tools(load_json(args.file), args.fail_on))


if __name__ == "__main__":
    main()
