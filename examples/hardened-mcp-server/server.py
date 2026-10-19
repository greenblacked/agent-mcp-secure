#!/usr/bin/env python3
"""
Minimal hardened MCP server example.

Demonstrates:
- Narrow tool purpose (document reader only)
- Path restriction to an explicit root
- Argument validation
- No shell interpolation
- Clear rejection of out-of-scope requests
"""

import json
from pathlib import Path

ALLOWED_ROOT = Path("/data/documents").resolve()


def validate_path(user_path: str) -> Path:
    """Resolve path and ensure it stays inside ALLOWED_ROOT."""
    if not user_path or ".." in user_path:
        raise ValueError("Invalid path")

    candidate = (ALLOWED_ROOT / user_path).resolve()
    try:
        candidate.relative_to(ALLOWED_ROOT)
    except ValueError:
        raise PermissionError("Path outside allowed root") from None

    if not candidate.is_file():
        raise FileNotFoundError("Document not found")

    return candidate


def read_document(path: str) -> dict:
    """Tool implementation: read a document under the allowed root."""
    try:
        resolved = validate_path(path)
        content = resolved.read_text(encoding="utf-8", errors="replace")
        # Limit size to reduce abuse
        if len(content) > 100_000:
            content = content[:100_000] + "\n...[truncated]"
        return {
            "status": "ok",
            "path": str(resolved.relative_to(ALLOWED_ROOT)),
            "content": content,
        }
    except (ValueError, PermissionError, FileNotFoundError) as e:
        return {"status": "error", "message": str(e)}


def main():
    """Simple stdin/stdout MCP-style loop for demonstration."""
    print("Hardened document reader ready. Allowed root:", ALLOWED_ROOT, flush=True)
    for line in iter(input, ""):
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            if req.get("tool") == "read_document":
                result = read_document(req.get("path", ""))
                print(json.dumps(result), flush=True)
            else:
                print(json.dumps({"status": "error", "message": "Unknown tool"}), flush=True)
        except json.JSONDecodeError:
            print(json.dumps({"status": "error", "message": "Invalid JSON"}), flush=True)


if __name__ == "__main__":
    # Ensure the allowed root exists for local testing
    ALLOWED_ROOT.mkdir(parents=True, exist_ok=True)
    main()
