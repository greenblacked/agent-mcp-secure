# Check Rules

## Implemented

### Steering language
Instructions that attempt to override prior context or force specific actions before/after tool use.

### Sensitive path references
Mentions of `~/.ssh`, credentials, `.env`, tokens, etc.

### Broad capabilities
Unrestricted shell, arbitrary command execution, admin-level access.

### Unpinned package launchers
- `npx @scope/tool@latest`
- `uvx tool` (no version)
- `docker run image:latest`

### Open URL / SSRF-style arguments
Descriptions that accept or fetch arbitrary URLs or endpoints without an allow-list.

### Broad filesystem roots
Tools rooted at `/`, `$HOME`, or described as having full filesystem access.

### Possible encoded content
Long base64-like strings in descriptions.

### Schema-level risky parameters
Free-form string parameters named `url`, `endpoint`, `webhook`, `host`, `path`, `filepath` without an `enum` or `pattern` constraint.

### Launch configuration scanning
`checks/scan_config.py` flags:
- Unpinned package launchers in MCP server commands
- Broad filesystem roots in arguments (`--root /`, `$HOME`)
- Sensitive environment variables present in config

## Planned

- High ratio of non-ASCII or zero-width characters
- Nested encoding
