"""Tests for tool interceptor."""
import pytest
from pkg.models.gateway import Decision, ToolRequest

class TestInterceptor:
    @pytest.mark.asyncio
    async def test_local_rule_allow(self, interceptor, sample_request):
        interceptor.add_local_rule("search", Decision.ALLOW)
        decision = await interceptor.intercept(sample_request)
        assert decision.decision == Decision.ALLOW

    @pytest.mark.asyncio
    async def test_local_rule_deny(self, interceptor):
        interceptor.add_local_rule("dangerous_tool", Decision.DENY)
        req = ToolRequest(agent_id="agent", tool_name="dangerous_tool")
        decision = await interceptor.intercept(req)
        assert decision.decision == Decision.DENY

    @pytest.mark.asyncio
    async def test_default_deny_when_policy_unreachable(self, interceptor, sample_request):
        decision = await interceptor.intercept(sample_request)
        assert decision.decision == Decision.DENY
        assert "unreachable" in decision.reason

    @pytest.mark.asyncio
    async def test_stats_tracking(self, interceptor, sample_request):
        interceptor.add_local_rule("search", Decision.ALLOW)
        await interceptor.intercept(sample_request)
        stats = interceptor.get_stats()
        assert stats.total_requests == 1
        assert stats.allowed == 1

    @pytest.mark.asyncio
    async def test_audit_log(self, interceptor, sample_request):
        interceptor.add_local_rule("search", Decision.ALLOW)
        await interceptor.intercept(sample_request)
        log = interceptor.get_audit_log()
        assert len(log) == 1

    @pytest.mark.asyncio
    async def test_remove_rule(self, interceptor, sample_request):
        interceptor.add_local_rule("search", Decision.ALLOW)
        interceptor.remove_local_rule("search")
        decision = await interceptor.intercept(sample_request)
        assert decision.decision == Decision.DENY
