// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package proxy implements the MCP policy gateway — a reverse proxy that
// intercepts JSON-RPC tool calls, evaluates them against policies and
// rate limits, and forwards allowed calls to upstream MCP servers.
package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/nostalgicskinco/mcp-policy-gateway/pkg/audit"
	"github.com/nostalgicskinco/mcp-policy-gateway/pkg/policy"
	"github.com/nostalgicskinco/mcp-policy-gateway/pkg/ratelimit"
)

// Config holds gateway configuration.
type Config struct {
	ListenAddr    string           `json:"listen_addr"`
	UpstreamURL   string           `json:"upstream_url"`
	PolicyFiles   []string         `json:"policy_files,omitempty"`
	RateLimit     ratelimit.Config `json:"rate_limit"`
	AuditLogPath  string           `json:"audit_log_path,omitempty"`
}

// Gateway is the MCP policy gateway.
type Gateway struct {
	config   Config
	engine   *policy.Engine
	limiter  *ratelimit.Limiter
	auditor  *audit.Logger
	upstream string
}

// jsonRPCRequest is a minimal JSON-RPC 2.0 request.
type jsonRPCRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	Method  string         `json:"method"`
	ID      any            `json:"id,omitempty"`
	Params  map[string]any `json:"params,omitempty"`
}

// jsonRPCError is a JSON-RPC 2.0 error response.
type jsonRPCError struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id,omitempty"`
	Error   struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// New creates a new gateway instance.
func New(cfg Config, engine *policy.Engine, limiter *ratelimit.Limiter, auditor *audit.Logger) *Gateway {
	return &Gateway{
		config:   cfg,
		engine:   engine,
		limiter:  limiter,
		auditor:  auditor,
		upstream: cfg.UpstreamURL,
	}
}

// ServeHTTP implements http.Handler for the gateway.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	var req jsonRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON-RPC", http.StatusBadRequest)
		return
	}

	// Only intercept tools/call requests
	if req.Method != "tools/call" {
		g.forward(w, r, body)
		return
	}

	toolName, _ := req.Params["name"].(string)
	agentID := r.Header.Get("X-Agent-ID")
	args, _ := req.Params["arguments"].(map[string]any)

	// Rate limit check
	limitKey := fmt.Sprintf("%s:%s", agentID, toolName)
	if g.limiter != nil && !g.limiter.Allow(limitKey) {
		if g.auditor != nil {
			g.auditor.LogToolCall(audit.EventRateLimited, toolName, agentID, "", "deny", "rate limited")
		}
		writeJSONRPCError(w, req.ID, -32000, "rate limited")
		return
	}

	// Policy check
	tc := policy.ToolCall{
		ToolName:  toolName,
		AgentID:   agentID,
		Arguments: args,
	}
	decision := g.engine.Evaluate(tc)

	switch decision.Action {
	case policy.ActionDeny:
		if g.auditor != nil {
			g.auditor.LogToolCall(audit.EventToolCallDenied, toolName, agentID, decision.RuleID, "deny", decision.Reason)
		}
		writeJSONRPCError(w, req.ID, -32001, "tool call denied: "+decision.Reason)
		return

	case policy.ActionAudit:
		if g.auditor != nil {
			g.auditor.LogToolCall(audit.EventToolCallAudited, toolName, agentID, decision.RuleID, "audit", "allowed with audit")
		}

	case policy.ActionAllow:
		if g.auditor != nil {
			g.auditor.LogToolCall(audit.EventToolCallAllowed, toolName, agentID, decision.RuleID, "allow", "")
		}
	}

	g.forward(w, r, body)
}

func (g *Gateway) forward(w http.ResponseWriter, _ *http.Request, body []byte) {
	if g.upstream == "" {
		writeJSONRPCError(w, nil, -32002, "no upstream configured")
		return
	}

	resp, err := http.Post(g.upstream, "application/json", strings.NewReader(string(body)))
	if err != nil {
		writeJSONRPCError(w, nil, -32003, "upstream error: "+err.Error())
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func writeJSONRPCError(w http.ResponseWriter, id any, code int, msg string) {
	resp := jsonRPCError{JSONRPC: "2.0", ID: id}
	resp.Error.Code = code
	resp.Error.Message = msg
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // JSON-RPC errors use 200
	json.NewEncoder(w).Encode(resp)
}
