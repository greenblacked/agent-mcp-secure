#!/usr/bin/env python3
"""
Unified CLI for agent-mcp-secure checks.

Usage:
  python3 cli.py tools <file.json>
  python3 cli.py config <file.json>
"""

import sys
from pathlib import Path

from scan import scan_tools
from scan_config import check_launch
import json


def main():
    if len(sys.argv) < 3:
        print("Usage: cli.py <tools|config> <file.json>", file=sys.stderr)
        sys.exit(1)

    mode = sys.argv[1]
    path = Path(sys.argv[2])
    if not path.exists():
        print(f"File not found: {path}", file=sys.stderr)
        sys.exit(1)

    data = json.loads(path.read_text())

    if mode == "tools":
        tools = data if isinstance(data, list) else data.get("tools", [])
        results = scan_tools(tools)
        if not results:
            print("No high-signal findings.")
        else:
            print(json.dumps(results, indent=2))
    elif mode == "config":
        findings = check_launch(data)
        if not findings:
            print("No high-signal findings.")
        else:
            print(json.dumps(findings, indent=2))
    else:
        print("Unknown mode. Use 'tools' or 'config'.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
