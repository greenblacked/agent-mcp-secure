# Hardened MCP Server Example

Minimal reference for an MCP server that demonstrates basic controls.

## Characteristics of a hardened server

- Tools have narrow, well-defined purposes
- Arguments are validated against strict schemas
- No shell interpolation of user/model-controlled input
- File access is restricted to an explicit root
- Sensitive operations require additional authorization or are absent
- Tool descriptions contain no steering language
- Errors do not leak internal paths or secrets

## Status

This directory is a placeholder for a concrete example implementation (Python or TypeScript). The initial version will include:

- A simple document-reader tool with path restriction
- Schema validation
- Clear rejection of out-of-scope requests

Contributions of minimal, well-commented examples are welcome.
