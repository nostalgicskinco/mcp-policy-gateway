"""Tests for gateway models."""
from pkg.models.gateway import Decision, GatewayStats, ToolRequest

class TestModels:
    def test_tool_request(self):
        r = ToolRequest(agent_id="a", tool_name="search")
        assert r.agent_id == "a"

    def test_gateway_stats(self):
        s = GatewayStats()
        assert s.total_requests == 0

    def test_decision_enum(self):
        assert Decision.ALLOW.value == "allow"
        assert Decision.DENY.value == "deny"
        assert Decision.ESCALATE.value == "escalate"
        assert Decision.LOG.value == "log"

    def test_tool_request_with_input(self):
        r = ToolRequest(agent_id="agent-1", tool_name="execute", tool_input={"cmd": "ls"})
        assert r.tool_input["cmd"] == "ls"
