// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ratelimit implements a token-bucket rate limiter for MCP tool calls.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter is a per-key token-bucket rate limiter.
type Limiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64       // tokens per second
	capacity int           // max burst
	cleanup  time.Duration // how long to keep idle buckets
}

type bucket struct {
	tokens   float64
	lastTime time.Time
}

// Config holds rate limiter configuration.
type Config struct {
	RequestsPerSecond float64       `json:"requests_per_second"`
	BurstSize         int           `json:"burst_size"`
	CleanupInterval   time.Duration `json:"cleanup_interval,omitempty"`
}

// New creates a new rate limiter.
func New(cfg Config) *Limiter {
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = 5 * time.Minute
	}
	return &Limiter{
		buckets:  make(map[string]*bucket),
		rate:     cfg.RequestsPerSecond,
		capacity: cfg.BurstSize,
		cleanup:  cfg.CleanupInterval,
	}
}

// Allow checks if a request for the given key is allowed.
// Returns true if allowed, false if rate-limited.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(l.capacity), lastTime: now}
		l.buckets[key] = b
	}

	// Refill tokens
	elapsed := now.Sub(b.lastTime).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > float64(l.capacity) {
		b.tokens = float64(l.capacity)
	}
	b.lastTime = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// Reset clears all rate limit state.
func (l *Limiter) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buckets = make(map[string]*bucket)
}

// Cleanup removes idle buckets older than cleanup interval.
func (l *Limiter) Cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := time.Now().Add(-l.cleanup)
	for key, b := range l.buckets {
		if b.lastTime.Before(cutoff) {
			delete(l.buckets, key)
		}
	}
}
