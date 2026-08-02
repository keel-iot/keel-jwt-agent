# keel-jwt-agent

Standalone OAuth2 client-credentials token client, used to authenticate a
device to [`keel-mqtt-gateway`](../keel-mqtt-cluster) via its JWT/JWKS auth
path (`internal/auth/jwks_cache.go`), for tenants that have no Clavex Device
PKI and therefore no real certificate rotation/revocation.

It does exactly one thing: keep a JWT valid on disk, fetching one via the
standard OAuth2 client-credentials grant (RFC 6749 §4.4) against any
OIDC-compliant token endpoint, and refreshing it before it expires. Anything
that connects to `keel-mqtt-gateway` reads the file this tool maintains; it
has no opinion on what consumes it.

This is the **"basic" auth tier**: strictly weaker than
[`keel-cert-manager`](../keel-cert-manager)'s mTLS tier — there is no
revocation mechanism beyond the token's own (short) TTL, and no per-device
certificate identity, only whatever claims the issuer puts in the JWT. It
exists for tenants using a generic OAuth2/OIDC IdP instead of Clavex, which
cannot do true rotation-with-revocation. This tradeoff should be communicated
explicitly to tenants who pick this tier, not presented as equivalent to the
mTLS one.

## Usage

```
keel-jwt-agent fetch    fetch a token now, then exit
keel-jwt-agent status   print the current token's time-to-expiry
keel-jwt-agent run      fetch if needed, then refresh unattended forever
```

Run as a long-lived sidecar/daemon (systemd service, K8s sidecar container)
alongside whatever process actually uses the token file for its own
connection to `keel-mqtt-gateway`.

## Configuration

All configuration is via environment variables:

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `JWT_TOKEN_URL` | yes | — | OAuth2 token endpoint (client_credentials grant) |
| `JWT_CLIENT_ID` | yes | — | OAuth2 client id |
| `JWT_CLIENT_SECRET_FILE` | one of these two | — | path to the client secret (preferred — avoids leaving it in the process environment/shell history) |
| `JWT_CLIENT_SECRET` | | — | client secret, inline (fallback if no `_FILE` var set) |
| `JWT_SCOPE` | no | — | OAuth2 scope, space-separated |
| `TOKEN_PATH` | no | `/etc/keel/jwt-agent/token.jwt` | where the current JWT is written (mode `0600`) |
| `REFRESH_WINDOW` | no | `2m` | refresh once time-to-expiry drops below this |
| `CHECK_INTERVAL` | no | `30s` | how often `run` checks time-to-expiry |

## Build

```
go build ./...
go test ./...
```
