"""Test configuration and fixtures."""
import pytest
from pkg.models.gateway import GatewayConfig, ToolRequest, Decision
from pkg.proxy.interceptor import ToolInterceptor

@pytest.fixture
def interceptor():
    config = GatewayConfig(policy_engine_url="http://localhost:9999", default_decision=Decision.DENY)
    return ToolInterceptor(config=config)

@pytest.fixture
def sample_request():
    return ToolRequest(agent_id="test-agent", tool_name="search", tool_input={"q": "test"})
