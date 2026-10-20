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

    def test_clean(self):
        config = {
            "command": "python3",
            "args": ["server.py", "--root", "/data/documents"],
            "env": {"NODE_ENV": "production"},
        }
        self.assertEqual(check_launch(config), [])

    def test_broad_roots_in_args(self):
        for root in ["/", "~", "~/", "$HOME"]:
            with self.subTest(root=root):
                config = {"command": "python3", "args": ["server.py", "--root", root]}
                types = {f["type"] for f in check_launch(config)}
                self.assertIn("broad_filesystem_root", types)

    def test_broad_root_in_command_line(self):
        types = {f["type"] for f in check_launch("python3 server.py --root=/")}
        self.assertIn("broad_filesystem_root", types)

    def test_scoped_root_command_line_is_clean(self):
        self.assertEqual(check_launch("python3 server.py --root /data/documents"), [])


if __name__ == "__main__":
    unittest.main()
