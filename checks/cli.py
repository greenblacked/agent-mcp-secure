#!/usr/bin/env python3
"""
Unified CLI for agent-mcp-secure checks.

Usage:
  python3 cli.py tools <file.json> [--fail-on low|medium|high|none]
  python3 cli.py config <file.json> [--fail-on low|medium|high|none]

Exit codes: 0 no findings at or above --fail-on, 1 findings, 2 usage or input error.
"""

import argparse
import sys
from pathlib import Path

from scan import FAIL_ON_CHOICES, load_json, report_tools
from scan_config import report_config


def main():
    parser = argparse.ArgumentParser(description="agent-mcp-secure static checks")
    parser.add_argument("mode", choices=["tools", "config"], help="what the file contains")
    parser.add_argument("file", type=Path, help="JSON file to scan")
    parser.add_argument("--fail-on", choices=FAIL_ON_CHOICES, default="medium", help="lowest severity that fails")
    args = parser.parse_args()

    data = load_json(args.file)
    report = report_tools if args.mode == "tools" else report_config
    sys.exit(report(data, args.fail_on))


if __name__ == "__main__":
    main()
