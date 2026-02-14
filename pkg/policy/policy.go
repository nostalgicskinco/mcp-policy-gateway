// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package policy defines tool-call policies for the MCP gateway.
// Policies determine which tools agents are allowed to call,
// with what arguments, and under what conditions.
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Action is what the gateway does when a rule matches.
type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
	ActionAudit Action = "audit" // allow but log as suspicious
)

// Rule is a single policy rule evaluated against tool-call requests.
type Rule struct {
	ID          string            `json:"id"`
	Description string            `json:"description,omitempty"`
	Action      Action            `json:"action"`
	Tools       []string          `json:"tools,omitempty"`       // tool name patterns (* = wildcard)
	Agents      []string          `json:"agents,omitempty"`      // agent ID patterns
	ArgDeny     map[string]string `json:"arg_deny,omitempty"`    // deny if arg key contains value
	MaxArgs     int               `json:"max_args,omitempty"`    // max number of arguments
}

// PolicyFile is a collection of named rules loaded from config.
type PolicyFile struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	DefaultAction Action `json:"default_action"`
	Rules       []Rule `json:"rules"`
}

// Decision is the result of evaluating a tool call against policies.
type Decision struct {
	Action    Action `json:"action"`
	RuleID    string `json:"ruleId,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// ToolCall represents an incoming tool-call request from an agent.
type ToolCall struct {
	ToolName  string         `json:"tool_name"`
	AgentID   string         `json:"agent_id,omitempty"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

// Engine evaluates tool calls against loaded policies.
type Engine struct {
	policies []PolicyFile
}

// NewEngine creates a new policy engine.
func NewEngine() *Engine {
	return &Engine{}
}

// LoadFile loads a policy file and adds it to the engine.
func (e *Engine) LoadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read policy file: %w", err)
	}
	return e.LoadJSON(data)
}

// LoadJSON parses policy JSON and adds it to the engine.
func (e *Engine) LoadJSON(data []byte) error {
	var pf PolicyFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return fmt.Errorf("parse policy JSON: %w", err)
	}
	if pf.DefaultAction == "" {
		pf.DefaultAction = ActionDeny
	}
	e.policies = append(e.policies, pf)
	return nil
}

// Evaluate checks a tool call against all loaded policies.
// First matching rule wins. If no rule matches, default action applies.
func (e *Engine) Evaluate(tc ToolCall) Decision {
	for _, pf := range e.policies {
		for _, rule := range pf.Rules {
			if matchesRule(rule, tc) {
				d := Decision{Action: rule.Action, RuleID: rule.ID}
				if rule.Action == ActionDeny {
					d.Reason = rule.Description
					if d.Reason == "" {
						d.Reason = "denied by rule " + rule.ID
					}
				}
				return d
			}
		}
		// No rule matched in this policy — use its default.
		return Decision{
			Action: pf.DefaultAction,
			Reason: "no matching rule; default " + string(pf.DefaultAction),
		}
	}
	return Decision{Action: ActionDeny, Reason: "no policies loaded"}
}

func matchesRule(rule Rule, tc ToolCall) bool {
	// Check tool name
	if len(rule.Tools) > 0 && !matchesAny(rule.Tools, tc.ToolName) {
		return false
	}

	// Check agent ID
	if len(rule.Agents) > 0 && !matchesAny(rule.Agents, tc.AgentID) {
		return false
	}

	// Check denied argument patterns
	for key, pattern := range rule.ArgDeny {
		if val, ok := tc.Arguments[key]; ok {
			if strVal, ok := val.(string); ok {
				if strings.Contains(strings.ToLower(strVal), strings.ToLower(pattern)) {
					return true // arg matches deny pattern → rule fires
				}
			}
		}
	}

	// If we have arg_deny rules but none matched, this rule doesn't match
	if len(rule.ArgDeny) > 0 {
		return false
	}

	// Check max args
	if rule.MaxArgs > 0 && len(tc.Arguments) > rule.MaxArgs {
		return true
	}

	return true
}

func matchesAny(patterns []string, value string) bool {
	for _, p := range patterns {
		if p == "*" {
			return true
		}
		if p == value {
			return true
		}
		// Simple prefix wildcard: "read_*" matches "read_file"
		if strings.HasSuffix(p, "*") {
			prefix := strings.TrimSuffix(p, "*")
			if strings.HasPrefix(value, prefix) {
				return true
			}
		}
	}
	return false
}
