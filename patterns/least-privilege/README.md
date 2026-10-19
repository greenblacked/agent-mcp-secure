# Least-Privilege Tool Pattern

## Goal

Reduce the blast radius of a successful prompt injection by limiting what any single tool (or the agent as a whole) can do.

## Approach

Prefer narrow, purpose-built tools over general-purpose ones.

### Instead of

- A shell tool that can run arbitrary commands
- A file system tool rooted at `/` or the user’s home directory
- A cloud tool with project-level admin permissions

### Prefer

- A tool that can only read specific document types from a known directory
- A tool that can only query a single database table or API endpoint
- A tool that can only create a ticket or send a message to a fixed channel

## Implementation notes

- Enforce the restriction in the tool implementation or a wrapper, not only in the prompt.
- Validate arguments against an allow-list (allowed paths, allowed hosts, allowed command names).
- Return clear errors when the agent requests something outside the allowed set.
- Log rejected requests for monitoring.

## Example (conceptual)

```python
ALLOWED_ROOT = "/data/documents"

def read_document(path: str) -> str:
    resolved = os.path.realpath(path)
    if not resolved.startswith(ALLOWED_ROOT):
        raise PermissionError("Path outside allowed root")
    # ... read and return content
```

This pattern does not stop all attacks, but it makes many high-impact actions impossible even if the model is fully controlled.
