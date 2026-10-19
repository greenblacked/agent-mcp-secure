# agent-mcp-secure

Practical security controls for AI agents and MCP (Model Context Protocol) servers.

This repository provides opinionated, production-oriented checks, patterns, and examples to reduce the real cyber risk of AI agents: indirect prompt injection that leads to tool abuse, excessive agency, credential leakage, and insecure MCP tool definitions.

It focuses on system-level controls rather than relying solely on model behavior.

## Problem

AI agents that can call tools (especially via MCP) create a new attack surface:

- Untrusted content (documents, tool responses, web pages, tool descriptions) can contain instructions the model treats as authoritative.
- Agents often run with more privilege than necessary.
- Many MCP servers have weak validation on tool arguments or overly broad capabilities.
- A successful injection can result in data exfiltration, unwanted actions, or credential access — not just bad text.

Existing tools are strong on red-teaming and generic guardrails. This repo aims to provide concrete, copy-pasteable defensive controls and checks that platform and security teams can adopt.

## What this repository contains

- **checks/** — Python static checks for MCP tool definitions (runnable scanner included).
- **rust/** — Rust implementation of the same high-signal checks (library + CLI).
- **patterns/** — Practical control patterns (least privilege, human approval, output sanitization).
- **detections/** — Detection content for agent abuse (queries and rules).
- **examples/** — Hardened reference implementations.
- **docs/** — Threat model and control rationale.
- **worker/** — Cloudflare Worker demo endpoint for the checks.

## Quick start

Python:

```bash
python3 checks/scan.py checks/examples/vulnerable-tools.json
python3 checks/scan.py checks/examples/safe-tools.json
```

Rust:

```bash
cd rust
cargo run -- ../checks/examples/vulnerable-tools.json
cargo test
```

## CI

On every push and pull request to `main`:

- **Python**: ruff lint + format check, functional assertions on vulnerable/safe examples, syntax check of the hardened server.
- **Rust**: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, release build.

## Threat model (summary)

**In scope**
- Indirect and direct prompt injection that influences tool selection or arguments.
- Overly broad or dangerous tool capabilities.
- Tool descriptions that attempt to steer the agent.
- Missing authorization boundaries between the model and tool execution.

**Out of scope (for now)**
- Model training data poisoning.
- Full adversarial robustness of the underlying LLM.
- Network-level attacks against the MCP transport itself.

Full details: [docs/threat-model.md](docs/threat-model.md)

## Mapping

Primary alignment:

- OWASP LLM Top 10 2026 — LLM01 Prompt Injection, LLM03 Excessive Agency, LLM10 Improper Output Handling
- Practical agent/MCP risk patterns observed in 2025–2026 incidents

## Contributing

Contributions are welcome. Please open an issue or pull request. Focus on practical, high-signal controls with clear rationale.

## License

Apache-2.0. See [LICENSE](LICENSE).

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities in this project.
