# Detections

Detection content for identifying potential agent or MCP abuse.

## Contents

- `sigma/agent-credential-access.yml` — Sigma rule for credential path access after untrusted content processing (Linux process creation). Adapt log source to your environment.
- `queries/cloud-audit-tool-abuse.sql` — Example BigQuery-style query for cloud audit logs showing secret access by principals that recently read objects.

## Usage notes

These are starting points. They require:

- Logs that capture tool calls or process command lines
- Mapping of agent/MCP principals
- Tuning to reduce false positives in your environment

Map findings back to the controls in `docs/controls.md` for remediation guidance.
