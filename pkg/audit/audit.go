// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package audit records structured audit events for MCP tool calls
// in a format compatible with OTel log exporters and SIEM systems.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// EventType classifies audit events.
type EventType string

const (
	EventToolCallAllowed  EventType = "tool_call.allowed"
	EventToolCallDenied   EventType = "tool_call.denied"
	EventToolCallAudited  EventType = "tool_call.audited"
	EventRateLimited      EventType = "tool_call.rate_limited"
	EventToolCallError    EventType = "tool_call.error"
	EventToolCallComplete EventType = "tool_call.complete"
)

// Event is a single audit log entry.
type Event struct {
	Timestamp   time.Time      `json:"timestamp"`
	EventType   EventType      `json:"event_type"`
	AgentID     string         `json:"agent_id,omitempty"`
	ToolName    string         `json:"tool_name"`
	RuleID      string         `json:"rule_id,omitempty"`
	Action      string         `json:"action,omitempty"`
	Reason      string         `json:"reason,omitempty"`
	DurationMs  float64        `json:"duration_ms,omitempty"`
	Error       string         `json:"error,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// Logger writes audit events to an output sink.
type Logger struct {
	mu     sync.Mutex
	writer io.Writer
	enc    *json.Encoder
}

// NewLogger creates an audit logger writing to the given writer.
func NewLogger(w io.Writer) *Logger {
	return &Logger{
		writer: w,
		enc:    json.NewEncoder(w),
	}
}

// NewFileLogger creates an audit logger writing to a file.
func NewFileLogger(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return NewLogger(f), nil
}

// Log writes an audit event.
func (l *Logger) Log(e Event) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.enc.Encode(e)
}

// LogToolCall is a convenience method for logging tool call decisions.
func (l *Logger) LogToolCall(eventType EventType, toolName, agentID, ruleID, action, reason string) error {
	return l.Log(Event{
		EventType: eventType,
		AgentID:   agentID,
		ToolName:  toolName,
		RuleID:    ruleID,
		Action:    action,
		Reason:    reason,
	})
}
