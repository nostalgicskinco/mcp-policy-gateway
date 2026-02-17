"""Tool call interceptor — the core gateway logic."""
from __future__ import annotations
import time
import uuid
from typing import Any
import httpx
from pkg.models.gateway import (
    AuditEntry, Decision, GatewayConfig, GatewayStats, ToolDecision, ToolRequest,
)

class ToolInterceptor:
    def __init__(self, config: GatewayConfig | None = None) -> None:
        self.config = config or GatewayConfig()
        self.stats = GatewayStats()
        self.audit_log: list[AuditEntry] = []
        self._local_rules: dict[str, Decision] = {}

    async def intercept(self, request: ToolRequest) -> ToolDecision:
        start = time.monotonic()
        if not request.request_id:
            request.request_id = f"req-{uuid.uuid4().hex[:12]}"

        # Check local overrides first
        if request.tool_name in self._local_rules:
            decision = self._make_decision(request, self._local_rules[request.tool_name], "local_rule")
        else:
            # Check policy engine
            decision = await self._check_policy(request)

        elapsed = (time.monotonic() - start) * 1000
        self._record(request, decision, elapsed)
        return decision

    def add_local_rule(self, tool_name: str, decision: Decision) -> None:
        self._local_rules[tool_name] = decision

    def remove_local_rule(self, tool_name: str) -> None:
        self._local_rules.pop(tool_name, None)

    def get_stats(self) -> GatewayStats:
        return self.stats

    def get_audit_log(self, limit: int = 100) -> list[AuditEntry]:
        return self.audit_log[-limit:]

    async def _check_policy(self, request: ToolRequest) -> ToolDecision:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(
                    f"{self.config.policy_engine_url}/v1/evaluate",
                    json={
                        "agent_id": request.agent_id,
                        "action": request.tool_name,
                        "context": {**request.context, "tool_input": request.tool_input},
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    action = data.get("action", "deny")
                    decision_map = {"allow": Decision.ALLOW, "deny": Decision.DENY, "escalate": Decision.ESCALATE, "log": Decision.LOG}
                    return self._make_decision(request, decision_map.get(action, Decision.DENY), data.get("reason", "policy_engine"), data.get("policy_id"))
        except httpx.HTTPError:
            pass
        return self._make_decision(request, self.config.default_decision, "policy_engine_unreachable")

    def _make_decision(self, request: ToolRequest, decision: Decision, reason: str, policy_id: str | None = None) -> ToolDecision:
        return ToolDecision(request_id=request.request_id, decision=decision, tool_name=request.tool_name, agent_id=request.agent_id, reason=reason, policy_id=policy_id)

    def _record(self, request: ToolRequest, decision: ToolDecision, duration_ms: float) -> None:
        self.stats.total_requests += 1
        if decision.decision == Decision.ALLOW: self.stats.allowed += 1
        elif decision.decision == Decision.DENY: self.stats.denied += 1
        elif decision.decision == Decision.ESCALATE: self.stats.escalated += 1
        elif decision.decision == Decision.LOG: self.stats.logged += 1
        self.audit_log.append(AuditEntry(request=request, decision=decision, duration_ms=duration_ms))
