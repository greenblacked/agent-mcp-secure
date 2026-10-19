# Human Approval Pattern

## Goal

Prevent automated execution of high-impact actions when the agent may have been influenced by untrusted content.

## Approach

Classify actions by impact:

- **Low impact** (read public data, summarize, search) — can execute automatically
- **High impact** (write files, send email, call paid APIs, modify cloud resources, access secrets) — require explicit human approval

The agent can propose the action. A human or an approval workflow must confirm it before the tool executes.

## Implementation notes

- Make the approval decision outside the model (in the tool wrapper, MCP proxy, or orchestration layer).
- Present the proposed action clearly (tool name, arguments, expected effect).
- Log both the proposal and the approval decision.
- Consider time-limited or scoped approvals for repeated legitimate workflows.

## Example flow

1. Agent decides to call `delete_user_data` with specific arguments.
2. Wrapper intercepts the call and returns a pending approval token instead of executing.
3. User (or automated policy for low-risk cases) approves or denies.
4. Only on approval does the actual tool run.

This breaks the direct path from injected instruction to harmful side effect.
