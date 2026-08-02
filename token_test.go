package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testJWT(t *testing.T, exp time.Time) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, err := json.Marshal(map[string]any{"exp": exp.Unix(), "sub": "device-1"})
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	return header + "." + body + ".sig"
}

func TestWriteFileAtomicCreatesAndOverwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "file.jwt")

	if err := writeFileAtomic(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "first" {
		t.Fatalf("content = %q, want %q", got, "first")
	}

	if err := writeFileAtomic(path, []byte("second"), 0o600); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	got, _ = os.ReadFile(path)
	if string(got) != "second" {
		t.Fatalf("content = %q, want %q", got, "second")
	}

	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 file in dir, got %d: %v", len(entries), entries)
	}
}

func TestJWTExpiry(t *testing.T) {
	want := time.Now().Add(1 * time.Hour).Truncate(time.Second)
	token := testJWT(t, want)

	got, err := jwtExpiry(token)
	if err != nil {
		t.Fatalf("jwtExpiry: %v", err)
	}
	if !got.Equal(want) {
		t.Fatalf("exp = %v, want %v", got, want)
	}
}

func TestJWTExpiryMalformed(t *testing.T) {
	if _, err := jwtExpiry("not-a-jwt"); err == nil {
		t.Fatal("expected error for malformed token")
	}
}

func TestJWTExpiryNoExpClaim(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"device-1"}`))
	if _, err := jwtExpiry(header + "." + payload + ".sig"); err == nil {
		t.Fatal("expected error for missing exp claim")
	}
}

func TestTokenTimeToExpiry(t *testing.T) {
	want := time.Now().Add(30 * time.Minute)
	token := testJWT(t, want)

	dir := t.TempDir()
	path := filepath.Join(dir, "token.jwt")
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	ttl, err := tokenTimeToExpiry(path)
	if err != nil {
		t.Fatalf("tokenTimeToExpiry: %v", err)
	}
	if ttl <= 0 || ttl > 30*time.Minute {
		t.Fatalf("ttl = %v, want in (0, 30m]", ttl)
	}
}

func TestTokenTimeToExpiryMissingFile(t *testing.T) {
	if _, err := tokenTimeToExpiry("/nonexistent/path.jwt"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestFetchTokenAndRefresh(t *testing.T) {
	exp := time.Now().Add(1 * time.Hour)
	wantToken := testJWT(t, exp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if got := r.Form.Get("grant_type"); got != "client_credentials" {
			t.Fatalf("grant_type = %q, want client_credentials", got)
		}
		if got := r.Form.Get("client_id"); got != "client-1" {
			t.Fatalf("client_id = %q, want client-1", got)
		}
		if got := r.Form.Get("client_secret"); got != "secret-1" {
			t.Fatalf("client_secret = %q, want secret-1", got)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResponse{
			AccessToken: wantToken,
			ExpiresIn:   3600,
			TokenType:   "Bearer",
		})
	}))
	defer srv.Close()

	cfg := config{
		TokenURL:     srv.URL,
		ClientID:     "client-1",
		ClientSecret: "secret-1",
		TokenPath:    filepath.Join(t.TempDir(), "token.jwt"),
	}

	resp, err := refresh(context.Background(), cfg)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if resp.AccessToken != wantToken {
		t.Fatalf("access token mismatch")
	}

	got, err := os.ReadFile(cfg.TokenPath)
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	if string(got) != wantToken {
		t.Fatalf("token file content mismatch")
	}
}

func TestFetchTokenServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	cfg := config{TokenURL: srv.URL, ClientID: "client-1", ClientSecret: "wrong"}
	if _, err := fetchToken(context.Background(), cfg); err == nil {
		t.Fatal("expected error for 401 response")
	}
}

func TestRunFetchesThenRefreshesOnExpiry(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token.jwt")

	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		exp := time.Now().Add(500 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResponse{AccessToken: testJWT(t, exp)})
	}))
	defer srv.Close()

	cfg := config{
		TokenURL:      srv.URL,
		ClientID:      "client-1",
		ClientSecret:  "secret-1",
		TokenPath:     tokenPath,
		RefreshWindow: 400 * time.Millisecond,
		CheckInterval: 100 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()

	if err := run(ctx, cfg, func(string, ...any) {}); err != nil && err != context.DeadlineExceeded {
		t.Fatalf("run: %v", err)
	}
	if calls < 2 {
		t.Fatalf("expected at least 2 fetches (initial + refresh), got %d", calls)
	}
}
