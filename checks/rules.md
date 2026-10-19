# Additional Check Rules

These rules extend the high-signal patterns already implemented in the scanners.

## Unpinned package launchers

Flag MCP server launch commands that use floating versions:

- `npx @scope/tool@latest`
- `uvx tool` (no version pin)
- `docker run image:latest`

**Why**: Supply-chain and reproducibility risk. Prefer pinned versions or digests.

## SSRF / open URL arguments

Flag tools whose schemas accept free-form URLs or hostnames that the server will request:

- Parameter named `url`, `endpoint`, `host`, `webhook` without an allow-list
- Description mentioning "fetch any URL" or "call the provided endpoint"

**Why**: Enables server-side request forgery and data exfiltration via tool arguments.

## Overly broad filesystem roots

Flag configuration that roots a filesystem tool at `/`, `$HOME`, or the user profile.

**Why**: Increases the impact of path-related injections.

## Encoded or obfuscated descriptions

Already partially covered. Also watch for:

- High ratio of non-ASCII or zero-width characters
- Nested base64
- Instructions hidden in HTML comments or JSON string escapes

These rules can be added to the Python and Rust scanners incrementally.
