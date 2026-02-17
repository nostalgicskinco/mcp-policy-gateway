"""Tests for FastAPI routes."""
from fastapi.testclient import TestClient
from app.server import app

client = TestClient(app)

class TestAPI:
    def test_health(self):
        resp = client.get("/v1/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_stats(self):
        resp = client.get("/v1/stats")
        assert resp.status_code == 200
        assert "total_requests" in resp.json()

    def test_add_rule(self):
        resp = client.post("/v1/rules", json={"tool_name": "test_tool", "decision": "allow"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "rule_added"

    def test_intercept(self):
        client.post("/v1/rules", json={"tool_name": "api_search", "decision": "allow"})
        resp = client.post("/v1/intercept", json={"agent_id": "test", "tool_name": "api_search"})
        assert resp.status_code == 200
        assert resp.json()["decision"] == "allow"

    def test_audit(self):
        resp = client.get("/v1/audit")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_remove_rule(self):
        client.post("/v1/rules", json={"tool_name": "temp_tool", "decision": "allow"})
        resp = client.delete("/v1/rules/temp_tool")
        assert resp.status_code == 200
        assert resp.json()["status"] == "rule_removed"
