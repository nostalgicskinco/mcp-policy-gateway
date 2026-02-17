"""Policy engine client."""
from __future__ import annotations
import httpx

class PolicyClient:
    def __init__(self, base_url: str = "http://localhost:8200") -> None:
        self.base_url = base_url.rstrip("/")

    async def check(self, agent_id: str, tool_name: str, context: dict | None = None) -> dict:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(f"{self.base_url}/v1/evaluate", json={"agent_id": agent_id, "action": tool_name, "context": context or {}})
            resp.raise_for_status()
            return resp.json()

    async def health(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(f"{self.base_url}/v1/health")
                return resp.status_code == 200
        except httpx.HTTPError:
            return False
