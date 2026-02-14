// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command mcpgw runs the MCP policy gateway reverse proxy.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/nostalgicskinco/mcp-policy-gateway/pkg/audit"
	"github.com/nostalgicskinco/mcp-policy-gateway/pkg/policy"
	"github.com/nostalgicskinco/mcp-policy-gateway/pkg/proxy"
	"github.com/nostalgicskinco/mcp-policy-gateway/pkg/ratelimit"
)

func main() {
	listen := flag.String("listen", ":8080", "Listen address")
	upstream := flag.String("upstream", "", "Upstream MCP server URL")
	policyFile := flag.String("policy", "", "Path to policy JSON file")
	auditLog := flag.String("audit-log", "", "Path to audit log file (JSON lines)")
	rps := flag.Float64("rps", 10, "Requests per second rate limit")
	burst := flag.Int("burst", 20, "Rate limit burst size")
	flag.Parse()

	if *upstream == "" {
		fmt.Fprintf(os.Stderr, "Usage: mcpgw -upstream <url> [-policy <file>] [-listen :8080]\n")
		os.Exit(1)
	}

	engine := policy.NewEngine()
	if *policyFile != "" {
		if err := engine.LoadFile(*policyFile); err != nil {
			log.Fatalf("load policy: %v", err)
		}
	}

	limiter := ratelimit.New(ratelimit.Config{
		RequestsPerSecond: *rps,
		BurstSize:         *burst,
	})

	var auditor *audit.Logger
	if *auditLog != "" {
		var err error
		auditor, err = audit.NewFileLogger(*auditLog)
		if err != nil {
			log.Fatalf("open audit log: %v", err)
		}
	} else {
		auditor = audit.NewLogger(os.Stdout)
	}

	gw := proxy.New(proxy.Config{
		ListenAddr:  *listen,
		UpstreamURL: *upstream,
	}, engine, limiter, auditor)

	log.Printf("MCP Policy Gateway listening on %s → %s", *listen, *upstream)
	if err := http.ListenAndServe(*listen, gw); err != nil {
		log.Fatal(err)
	}
}
