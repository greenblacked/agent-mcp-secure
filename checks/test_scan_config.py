#!/usr/bin/env python3
"""Tests for MCP launch configuration scanner."""

import json
import unittest
from pathlib import Path

from scan_config import check_launch


class TestLaunchConfig(unittest.TestCase):
    def test_risky_example(self):
        path = Path(__file__).parent / "examples" / "risky-launch.json"
        config = json.loads(path.read_text())
        findings = check_launch(config)
        types = {f["type"] for f in findings}
        self.assertIn("unpinned_launcher", types)
        self.assertIn("broad_filesystem_root", types)
        self.assertIn("sensitive_env_in_config", types)

    def test_each_type_reported_once(self):
        path = Path(__file__).parent / "examples" / "risky-launch.json"
        findings = check_launch(json.loads(path.read_text()))
        types = [f["type"] for f in findings]
        self.assertEqual(len(types), len(set(types)))
        roots = next(f for f in findings if f["type"] == "broad_filesystem_root")
        self.assertEqual(len(roots["patterns"]), 2)

    def test_clean(self):
        config = {
            "command": "python3",
            "args": ["server.py", "--root", "/data/documents"],
            "env": {"NODE_ENV": "production"},
        }
        self.assertEqual(check_launch(config), [])

    def test_broad_root_variants(self):
        for cmd in ["server --root /", "server --root=~/", "server --root $HOME", "npx server-filesystem@1.2.3 /"]:
            types = {f["type"] for f in check_launch(cmd)}
            self.assertIn("broad_filesystem_root", types, cmd)

    def test_scoped_root_string(self):
        self.assertEqual(check_launch("python3 server.py --root /data/documents"), [])


if __name__ == "__main__":
    unittest.main()
