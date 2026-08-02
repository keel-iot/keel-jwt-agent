package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Fatalf("invalid %s: %v", key, err)
	}
	return d
}

// clientSecret reads the OAuth2 client secret from a file
// (JWT_CLIENT_SECRET_FILE, preferred — avoids leaving it in the process
// environment/shell history) or falls back to JWT_CLIENT_SECRET directly.
func clientSecret() string {
	if path := os.Getenv("JWT_CLIENT_SECRET_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("read JWT_CLIENT_SECRET_FILE: %v", err)
		}
		return trimNewline(string(data))
	}
	return os.Getenv("JWT_CLIENT_SECRET")
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

func configFromEnv() config {
	tokenURL := os.Getenv("JWT_TOKEN_URL")
	if tokenURL == "" {
		log.Fatal("JWT_TOKEN_URL is required")
	}
	clientID := os.Getenv("JWT_CLIENT_ID")
	if clientID == "" {
		log.Fatal("JWT_CLIENT_ID is required")
	}
	return config{
		TokenURL:      tokenURL,
		ClientID:      clientID,
		ClientSecret:  clientSecret(),
		Scope:         os.Getenv("JWT_SCOPE"),
		TokenPath:     env("TOKEN_PATH", "/etc/keel/jwt-agent/token.jwt"),
		RefreshWindow: envDuration("REFRESH_WINDOW", 2*time.Minute),
		CheckInterval: envDuration("CHECK_INTERVAL", 30*time.Second),
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `keel-jwt-agent: OAuth2 client-credentials JWT client for keel-mqtt-gateway

Usage:
  keel-jwt-agent fetch    fetch a token now, then exit
  keel-jwt-agent status   print the current token's time-to-expiry
  keel-jwt-agent run      fetch if needed, then refresh unattended forever

This is the "basic" auth tier for tenants without Clavex Device PKI — no
certificate rotation, no revocation beyond the token's own short TTL. For
full mTLS rotation/revocation, use keel-cert-manager instead.

Configuration is via environment variables — see README.md.`)
}

func main() {
	if len(os.Args) != 2 {
		usage()
		os.Exit(2)
	}

	cfg := configFromEnv()
	ctx := context.Background()

	switch os.Args[1] {
	case "fetch":
		if _, err := refresh(ctx, cfg); err != nil {
			log.Fatalf("fetch: %v", err)
		}
		log.Printf("fetched token for client %s", cfg.ClientID)

	case "status":
		ttl, err := tokenTimeToExpiry(cfg.TokenPath)
		if err != nil {
			log.Fatalf("status: %v", err)
		}
		fmt.Printf("token for %s expires in %s\n", cfg.ClientID, ttl.Round(time.Second))

	case "run":
		ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := run(ctx, cfg, log.Printf); err != nil {
			log.Fatalf("run: %v", err)
		}

	default:
		usage()
		os.Exit(2)
	}
}
