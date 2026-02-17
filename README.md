# MCP Policy Gateway

**A firewall for AI agent tool access.** Intercepts MCP tool calls, checks them against the Policy Engine, and enforces allow/deny/escalate decisions with full audit logging.

## API

| Endpoint | Method | Description |
|---|---|---|
| `/v1/intercept` | POST | Check a tool call against policies |
| `/v1/rules` | POST | Add a local override rule |
| `/v1/rules/{tool}` | DELETE | Remove a local rule |
| `/v1/stats` | GET | Gateway statistics |
| `/v1/audit` | GET | Audit log of all decisions |
| `/v1/health` | GET | Health check |

## How It Works

1. Agent requests tool call → Gateway intercepts
2. Gateway checks local rules first, then Policy Engine
3. Returns ALLOW/DENY/ESCALATE/LOG decision
4. All decisions are audit-logged

## Part of the AIR Platform

[AIR Blackbox Gateway](https://github.com/nostalgicskinco/air-blackbox-gateway) ecosystem.

## License

Apache-2.0
