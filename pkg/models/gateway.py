"""Gateway models for MCP tool policy enforcement."""
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field

class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"
    LOG = "log"

class ToolRequest(BaseModel):
    request_id: str = ""
    agent_id: str
    tool_name: str
    tool_input: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class ToolDecision(BaseModel):
    request_id: str
    decision: Decision
    tool_name: str
    agent_id: str
    reason: str = ""
    policy_id: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class GatewayConfig(BaseModel):
    policy_engine_url: str = "http://localhost:8200"
    default_decision: Decision = Decision.DENY
    log_all: bool = True
    escalation_webhook: str | None = None

class AuditEntry(BaseModel):
    request: ToolRequest
    decision: ToolDecision
    duration_ms: float = 0.0

class GatewayStats(BaseModel):
    total_requests: int = 0
    allowed: int = 0
    denied: int = 0
    escalated: int = 0
    logged: int = 0
