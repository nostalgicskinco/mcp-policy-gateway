"""FastAPI routes for MCP policy gateway."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException
from pkg.models.gateway import Decision, GatewayConfig, ToolRequest
from pkg.proxy.interceptor import ToolInterceptor

router = APIRouter()
interceptor = ToolInterceptor()

@router.get("/v1/health")
async def health():
    return {"status": "ok", "service": "mcp-policy-gateway"}

@router.post("/v1/intercept")
async def intercept_tool_call(request: ToolRequest):
    decision = await interceptor.intercept(request)
    return decision.model_dump(mode="json")

@router.get("/v1/stats")
async def get_stats():
    return interceptor.get_stats().model_dump()

@router.get("/v1/audit")
async def get_audit(limit: int = 100):
    entries = interceptor.get_audit_log(limit=limit)
    return [e.model_dump(mode="json") for e in entries]

@router.post("/v1/rules")
async def add_rule(body: dict):
    tool = body.get("tool_name", "")
    decision = body.get("decision", "deny")
    if not tool:
        raise HTTPException(400, "tool_name required")
    interceptor.add_local_rule(tool, Decision(decision))
    return {"status": "rule_added", "tool_name": tool, "decision": decision}

@router.delete("/v1/rules/{tool_name}")
async def remove_rule(tool_name: str):
    interceptor.remove_local_rule(tool_name)
    return {"status": "rule_removed", "tool_name": tool_name}
