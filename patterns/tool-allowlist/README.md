# Tool Allow-List Proxy Pattern

## Goal

Enforce a strict set of permitted tools and arguments at a proxy or orchestration layer, independent of the model.

## Approach

Sit a thin proxy between the agent and the MCP servers. The proxy:

1. Maintains an allow-list of tool names and permitted argument patterns.
2. Rejects any tool call not on the list.
3. Validates arguments against schemas or regular expressions before forwarding.
4. Logs every decision (allowed or denied).

## Example policy (conceptual)

```yaml
allowed_tools:
  - name: read_document
    arg_patterns:
      path: "^[a-zA-Z0-9_./-]+$"
  - name: search_knowledge_base
    arg_patterns:
      query: ".{1,200}"
denied_by_default: true
```

## Why it helps

Even if the model is fully steered by injected content, it can only invoke tools and arguments that the proxy has explicitly permitted. This is a strong complement to least-privilege tool design.
