# Hardened MCP Server Example

Minimal Python example that demonstrates practical controls for an MCP-style tool.

## What it shows

- A single narrow tool (`read_document`) instead of a general-purpose file or shell tool
- Path restriction: requests outside `/data/documents` are rejected
- Basic argument validation (no `..`, must resolve inside the root)
- Size limiting on returned content
- Clear error responses that do not leak internal details
- No shell command interpolation

## Run locally

```bash
cd examples/hardened-mcp-server
python3 server.py
```

Then send JSON lines on stdin:

```json
{"tool": "read_document", "path": "report.txt"}
```

Requests with `../` or paths that resolve outside the root are rejected.

## Contrast with insecure patterns

An insecure version would typically:

- Accept arbitrary paths or shell commands
- Interpolate model-controlled input into `subprocess` or `os.system`
- Root the file tool at `/` or the user home directory
- Include steering language in the tool description

This example keeps the tool deliberately limited so that even a fully steered model cannot escape the allowed directory or execute commands.

## Next steps for a real MCP server

In a production MCP server you would additionally:

- Use the official MCP SDK and proper tool schema
- Enforce schemas at the protocol level
- Add authentication if the server is remote
- Log rejected requests for monitoring
