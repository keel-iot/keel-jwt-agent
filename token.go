// Package main implements keel-jwt-agent: a standalone OAuth2
// client-credentials token client for authenticating a device to
// keel-mqtt-gateway via its JWT/JWKS auth path (internal/auth/jwks_cache.go),
// for tenants that have no Clavex Device PKI and therefore no real
// certificate rotation/revocation — see keel-cert-manager for that tier.
//
// It does exactly one thing: keep a JWT valid on disk, fetching one via the
// standard OAuth2 client-credentials grant (RFC 6749 §4.4) against any
// OIDC-compliant token endpoint, and refreshing it before it expires.
// Anything that connects to keel-mqtt-gateway reads the file this tool
// maintains; it has no opinion on what consumes it.
//
// This is a strictly weaker security tier than keel-cert-manager: there is
// no revocation mechanism beyond the token's own (short) TTL, and no
// per-device certificate identity — only whatever claims the issuer puts in
// the JWT. It exists for tenants using a generic OAuth2/OIDC IdP instead of
// Clavex, which cannot do true rotation-with-revocation.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// config configures the OAuth2 client-credentials token client.
type config struct {
	TokenURL      string // OAuth2 token endpoint (client_credentials grant)
	ClientID      string
	ClientSecret  string
	Scope         string        // optional, space-separated
	TokenPath     string        // where the current JWT (access token) is written
	RefreshWindow time.Duration // refresh once time-to-expiry drops below this
	CheckInterval time.Duration // how often the run loop checks time-to-expiry
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"` // seconds, per RFC 6749 §5.1; optional
	TokenType   string `json:"token_type"`
}

// writeFileAtomic writes data to path via a temp file + rename in the same
// directory, so a concurrent reader (or a crash mid-write) never observes a
// truncated token file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once renamed away

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// fetchToken performs the OAuth2 client-credentials grant against
// cfg.TokenURL and returns the raw response.
func fetchToken(ctx context.Context, cfg config) (*tokenResponse, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
	}
	if cfg.Scope != "" {
		form.Set("scope", cfg.Scope)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	httpResp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token: server returned %d", httpResp.StatusCode)
	}

	var resp tokenResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if resp.AccessToken == "" {
		return nil, fmt.Errorf("token response has no access_token")
	}
	return &resp, nil
}

// refresh fetches a fresh token and writes it to cfg.TokenPath.
func refresh(ctx context.Context, cfg config) (*tokenResponse, error) {
	resp, err := fetchToken(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(cfg.TokenPath, []byte(resp.AccessToken), 0o600); err != nil {
		return nil, fmt.Errorf("write token: %w", err)
	}
	return resp, nil
}

// jwtExpiry decodes (without verifying — this client only needs to read its
// own just-issued claims) the "exp" claim from a JWT's payload segment and
// returns how long until it expires.
func jwtExpiry(token string) (time.Time, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return time.Time{}, fmt.Errorf("not a JWT: expected 3 dot-separated segments, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, fmt.Errorf("decode payload: %w", err)
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, fmt.Errorf("parse claims: %w", err)
	}
	if claims.Exp == 0 {
		return time.Time{}, fmt.Errorf("token has no exp claim")
	}
	return time.Unix(claims.Exp, 0), nil
}

// tokenTimeToExpiry reads the JWT at path and returns how long until it
// expires.
func tokenTimeToExpiry(path string) (time.Duration, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	exp, err := jwtExpiry(string(data))
	if err != nil {
		return 0, err
	}
	return time.Until(exp), nil
}

// run fetches a token immediately (if none exists yet) and then loops
// forever, refreshing it whenever its time-to-expiry drops below
// cfg.RefreshWindow. Intended to run as a long-lived sidecar/daemon
// alongside whatever process actually uses the token file for its own
// connection to keel-mqtt-gateway.
func run(ctx context.Context, cfg config, logf func(string, ...any)) error {
	if _, err := os.Stat(cfg.TokenPath); err != nil {
		if _, err := refresh(ctx, cfg); err != nil {
			return fmt.Errorf("initial fetch failed: %w", err)
		}
		logf("fetched token for client %s", cfg.ClientID)
	}

	ticker := time.NewTicker(cfg.CheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			ttl, err := tokenTimeToExpiry(cfg.TokenPath)
			if err != nil {
				logf("check expiry: %v", err)
				continue
			}
			if ttl > cfg.RefreshWindow {
				continue
			}
			if _, err := refresh(ctx, cfg); err != nil {
				logf("refresh failed (retrying in %s): %v", cfg.CheckInterval, err)
				continue
			}
			logf("refreshed token for client %s", cfg.ClientID)
		}
	}
}
