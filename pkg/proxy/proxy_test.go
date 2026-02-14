// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nostalgicskinco/mcp-policy-gateway/pkg/audit"
	"github.com/nostalgicskinco/mcp-policy-gateway/pkg/policy"
	"github.com/nostalgicskinco/mcp-policy-gateway/pkg/ratelimit"
)

func newTestGateway(policyJSON string) (*Gateway, *httptest.Server) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]any{"content": "ok"},
		})
	}))

	engine := policy.NewEngine()
	if policyJSON != "" {
		engine.LoadJSON([]byte(policyJSON))
	}

	limiter := ratelimit.New(ratelimit.Config{
		RequestsPerSecond: 100,
		BurstSize:         100,
	})

	auditor := audit.NewLogger(&bytes.Buffer{})

	gw := New(Config{
		UpstreamURL: upstream.URL,
	}, engine, limiter, auditor)

	return gw, upstream
}

func TestAllowedToolCall(t *testing.T) {
	gw, upstream := newTestGateway(`{
		"name": "test",
		"default_action": "deny",
		"rules": [{"id": "R1", "action": "allow", "tools": ["read_file"]}]
	}`)
	defer upstream.Close()

	body := `{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"read_file","arguments":{"path":"/tmp/test"}}}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	gw.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if _, ok := resp["result"]; !ok {
		t.Fatal("expected result from upstream")
	}
}

func TestDeniedToolCall(t *testing.T) {
	gw, upstream := newTestGateway(`{
		"name": "test",
		"default_action": "deny",
		"rules": [{"id": "R1", "action": "allow", "tools": ["read_file"]}]
	}`)
	defer upstream.Close()

	body := `{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"exec_sql","arguments":{}}}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	gw.ServeHTTP(w, req)

	var resp jsonRPCError
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error.Code != -32001 {
		t.Fatalf("expected error code -32001, got %d", resp.Error.Code)
	}
}

func TestNonToolCallPassthrough(t *testing.T) {
	gw, upstream := newTestGateway(`{"name":"test","default_action":"deny","rules":[]}`)
	defer upstream.Close()

	body := `{"jsonrpc":"2.0","method":"resources/list","id":1}`
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	gw.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200 for non-tool-call passthrough, got %d", w.Code)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	gw, upstream := newTestGateway("")
	defer upstream.Close()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	gw.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}
