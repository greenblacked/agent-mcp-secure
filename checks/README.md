# Static Checks

High-signal patterns to look for in MCP tool definitions and agent configurations.

These are intentionally simple and focused on issues that have led to real impact. They are not a complete scanner.

## Runnable checker

```bash
python3 checks/scan.py checks/examples/vulnerable-tools.json
```

Run the unit tests:

```bash
cd checks && python3 -m unittest test_scan.py -v
```

## Patterns covered

- Steering language (“ignore previous”, “before using this tool”, etc.)
- References to sensitive paths (`~/.ssh`, credentials, `.env`)
- Broad capabilities (shell, arbitrary execution)
- Unpinned package launchers (`npx ...@latest`, `uvx`, `docker :latest`)
- Open URL / SSRF-style arguments
- Broad filesystem roots (`/`, `$HOME`)
- Possible encoded content

See [rules.md](rules.md) for the full list and planned extensions.

## GitHub Action

A reusable composite action is available at `.github/actions/scan-tools`.

Example usage in a workflow:

```yaml
- uses: actions/checkout@v4
- uses: ./.github/actions/scan-tools
  with:
    path: path/to/tools.json
```
