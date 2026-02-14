// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"testing"
)

func TestAllowByToolName(t *testing.T) {
	engine := NewEngine()
	engine.LoadJSON([]byte(`{
		"name": "test",
		"default_action": "deny",
		"rules": [
			{"id": "R1", "action": "allow", "tools": ["read_file", "list_files"]}
		]
	}`))

	d := engine.Evaluate(ToolCall{ToolName: "read_file"})
	if d.Action != ActionAllow {
		t.Fatalf("expected allow, got %s", d.Action)
	}

	d2 := engine.Evaluate(ToolCall{ToolName: "exec_sql"})
	if d2.Action != ActionDeny {
		t.Fatalf("expected deny for exec_sql, got %s", d2.Action)
	}
}

func TestWildcardTool(t *testing.T) {
	engine := NewEngine()
	engine.LoadJSON([]byte(`{
		"name": "test",
		"default_action": "deny",
		"rules": [
			{"id": "R1", "action": "allow", "tools": ["read_*"]}
		]
	}`))

	d := engine.Evaluate(ToolCall{ToolName: "read_file"})
	if d.Action != ActionAllow {
		t.Fatalf("expected allow for read_file with read_*, got %s", d.Action)
	}

	d2 := engine.Evaluate(ToolCall{ToolName: "write_file"})
	if d2.Action != ActionDeny {
		t.Fatalf("expected deny for write_file, got %s", d2.Action)
	}
}

func TestAgentFilter(t *testing.T) {
	engine := NewEngine()
	engine.LoadJSON([]byte(`{
		"name": "test",
		"default_action": "deny",
		"rules": [
			{"id": "R1", "action": "allow", "tools": ["*"], "agents": ["trusted-agent"]}
		]
	}`))

	d := engine.Evaluate(ToolCall{ToolName: "any_tool", AgentID: "trusted-agent"})
	if d.Action != ActionAllow {
		t.Fatalf("expected allow for trusted agent, got %s", d.Action)
	}

	d2 := engine.Evaluate(ToolCall{ToolName: "any_tool", AgentID: "rogue-agent"})
	if d2.Action != ActionDeny {
		t.Fatalf("expected deny for rogue agent, got %s", d2.Action)
	}
}

func TestArgDeny(t *testing.T) {
	engine := NewEngine()
	engine.LoadJSON([]byte(`{
		"name": "test",
		"default_action": "allow",
		"rules": [
			{"id": "R1", "action": "deny", "description": "no path traversal", "tools": ["read_file"], "arg_deny": {"path": ".."}}
		]
	}`))

	d := engine.Evaluate(ToolCall{
		ToolName:  "read_file",
		Arguments: map[string]any{"path": "/etc/../shadow"},
	})
	if d.Action != ActionDeny {
		t.Fatalf("expected deny for path traversal, got %s", d.Action)
	}

	d2 := engine.Evaluate(ToolCall{
		ToolName:  "read_file",
		Arguments: map[string]any{"path": "/home/user/file.txt"},
	})
	if d2.Action != ActionAllow {
		t.Fatalf("expected allow for safe path, got %s", d2.Action)
	}
}

func TestAuditAction(t *testing.T) {
	engine := NewEngine()
	engine.LoadJSON([]byte(`{
		"name": "test",
		"default_action": "deny",
		"rules": [
			{"id": "R1", "action": "audit", "tools": ["web_search"]}
		]
	}`))

	d := engine.Evaluate(ToolCall{ToolName: "web_search"})
	if d.Action != ActionAudit {
		t.Fatalf("expected audit, got %s", d.Action)
	}
}

func TestDefaultDeny(t *testing.T) {
	engine := NewEngine()
	engine.LoadJSON([]byte(`{
		"name": "test",
		"default_action": "deny",
		"rules": []
	}`))

	d := engine.Evaluate(ToolCall{ToolName: "anything"})
	if d.Action != ActionDeny {
		t.Fatalf("expected default deny, got %s", d.Action)
	}
}

func TestDefaultAllow(t *testing.T) {
	engine := NewEngine()
	engine.LoadJSON([]byte(`{
		"name": "test",
		"default_action": "allow",
		"rules": []
	}`))

	d := engine.Evaluate(ToolCall{ToolName: "anything"})
	if d.Action != ActionAllow {
		t.Fatalf("expected default allow, got %s", d.Action)
	}
}

func TestNoPoliciesLoaded(t *testing.T) {
	engine := NewEngine()
	d := engine.Evaluate(ToolCall{ToolName: "anything"})
	if d.Action != ActionDeny {
		t.Fatalf("expected deny with no policies, got %s", d.Action)
	}
}
