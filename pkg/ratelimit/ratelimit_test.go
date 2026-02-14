// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: AGPL-3.0-or-later

package ratelimit

import (
	"testing"
)

func TestAllowWithinBurst(t *testing.T) {
	l := New(Config{RequestsPerSecond: 10, BurstSize: 5})
	for i := 0; i < 5; i++ {
		if !l.Allow("key1") {
			t.Fatalf("request %d should be allowed within burst", i)
		}
	}
}

func TestDenyOverBurst(t *testing.T) {
	l := New(Config{RequestsPerSecond: 10, BurstSize: 3})
	for i := 0; i < 3; i++ {
		l.Allow("key1")
	}
	if l.Allow("key1") {
		t.Fatal("request over burst should be denied")
	}
}

func TestSeparateKeys(t *testing.T) {
	l := New(Config{RequestsPerSecond: 10, BurstSize: 2})
	l.Allow("key1")
	l.Allow("key1")
	// key1 exhausted
	if l.Allow("key1") {
		t.Fatal("key1 should be exhausted")
	}
	// key2 should still work
	if !l.Allow("key2") {
		t.Fatal("key2 should be allowed")
	}
}

func TestReset(t *testing.T) {
	l := New(Config{RequestsPerSecond: 10, BurstSize: 1})
	l.Allow("key1")
	if l.Allow("key1") {
		t.Fatal("should be denied after burst")
	}
	l.Reset()
	if !l.Allow("key1") {
		t.Fatal("should be allowed after reset")
	}
}
