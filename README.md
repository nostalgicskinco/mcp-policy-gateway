# mcp-policy-gateway

**MCP policy gateway / reverse proxy** — enforce authn/z, rate limits, tool allowlists, and audit logging for Model Context Protocol servers.

Sits between agents and MCP servers to enforce least privilege. JSON-RPC aware: intercepts `tools/call` requests, evaluates them against declarative policies, rate-limits per agent/tool, and logs every decision.

> Part of the **GenAI Infrastructure Standard** — a composable suite of open-source tools for enterprise-grade GenAI observability, security, and governance.
>
> | Layer | Component | Repo |
> |-------|-----------|------|
> | Privacy | Prompt Vault Processor | [prompt-vault-processor](https://github.com/nostalgicskinco/prompt-vault-processor) |
> | Normalization | Semantic Normalizer | [genai-semantic-normalizer](https://github.com/nostalgicskinco/genai-semantic-normalizer) |
> | Metrics | Cost & SLO Pack | [genai-cost-slo](https://github.com/nostalgicskinco/genai-cost-slo) |
> | Replay | Agent VCR | [agent-vcr](https://github.com/nostalgicskinco/agent-vcr) |
> | Testing | Regression Harness | [trace-regression-harness](https://github.com/nostalgicskinco/trace-regression-harness) |
> | Security | MCP Scanner | [mcp-security-scanner](https://github.com/nostalgicskinco/mcp-security-scanner) |
> | **Gateway** | **MCP Policy Gateway** | **this repo** |
> | Safety | GenAI Safe Processor | [otel-processor-genai](https://github.com/nostalgicskinco/opentelemetry-collector-processor-genai) |

## Problem

MCP servers expose tools to agents with no built-in access control. OWASP flags "Insecure Plugin Design" and "Excessive Agency" as top LLM risks. You need:

- **Tool allowlists** — only approved tools per agent
- **Argument validation** — block path traversal, SQL injection patterns
- **Rate limiting** — per-agent, per-tool token-bucket limits
- **Audit trail** — structured JSON logs for every tool call decision

## Quick Start

```bash
# Build the gateway
go build -o mcpgw ./cmd/mcpgw

# Run with a policy file
./mcpgw -upstream http://localhost:3000/mcp -policy gateway-policy.json -listen :8080
```

## Policy Files

```json
{
  "name": "production",
  "default_action": "deny",
  "rules": [
    {"id": "R1", "action": "allow", "tools": ["read_file", "list_files"]},
    {"id": "R2", "action": "audit", "tools": ["write_*"]},
    {"id": "R3", "action": "deny", "tools": ["delete_*", "exec_sql"]},
    {"id": "R4", "action": "deny", "tools": ["read_file"], "arg_deny": {"path": ".."}}
  ]
}
```

## Features

| Feature | Description |
|---------|-------------|
| Tool allowlists | Allow/deny/audit by tool name with wildcards |
| Agent filtering | Restrict tools per agent ID |
| Argument validation | Block dangerous argument patterns |
| Rate limiting | Per-agent/tool token-bucket limiter |
| Audit logging | Structured JSON event log for SIEM integration |
| JSON-RPC passthrough | Non-tool-call methods forwarded transparently |

## Architecture

```
Agent → mcpgw (policy + rate limit + audit) → MCP Server
```

The gateway intercepts `tools/call` JSON-RPC requests, evaluates them, and either forwards to the upstream MCP server or returns a JSON-RPC error.

## License

AGPL-3.0-or-later — see [LICENSE](LICENSE). Commercial licenses available — see [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md).
