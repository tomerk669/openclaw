# OpenClaw Gateway: Public Deployment Security Audit

OpenClaw's web interface is designed for local use and is "not hardened for public exposure."
This document records the findings of a security audit performed to harden the gateway
for deployment on a hosted environment with the UI console exposed publicly.

---

## Summary

| # | Issue | Severity | Status |
|---|-------|----------|--------|
| 1 | No rate limiting on authentication | CRITICAL | Fixed |
| 2 | WebSocket connection flood protection | HIGH | Fixed |
| 3 | Control UI served without authentication | HIGH | Fixed |
| 4 | Passwords stored in plaintext | MEDIUM | Fixed |
| 5 | No password strength enforcement | MEDIUM | Fixed |
| 6 | Hook token non-constant-time comparison | MEDIUM | Fixed |
| 7 | Dangerous auth bypass flags need friction | MEDIUM | Fixed |
| 8 | No CORS on HTTP API endpoints | MEDIUM | Fixed |
| 9 | No TLS enforcement warning | MEDIUM | Fixed |
| 10 | Auth failure information leakage | LOW | Fixed |

---

## Finding 1: No Rate Limiting on Authentication (CRITICAL)

**Description:**
The gateway accepted unlimited authentication attempts from any IP address with no
throttling or lockout mechanism. An attacker could brute-force gateway tokens or
passwords without restriction.

**Remediation:**
- Added `AuthRateLimiter` class (`src/gateway/rate-limit.ts`) with per-IP tracking
- Defaults: 5 failed attempts per 15-minute window, exponential lockout (1s to 5min)
- Integrated into `authorizeGatewayConnect()` for all auth paths (WS, HTTP APIs)
- Local/loopback connections bypass rate limiting
- HTTP endpoints return 429 Too Many Requests with Retry-After header when rate-limited
- Periodic cleanup every 5 minutes prevents memory leaks

**Files:**
- `src/gateway/rate-limit.ts` (new)
- `src/gateway/rate-limit.test.ts` (new)
- `src/gateway/auth.ts` (modified)
- `src/gateway/server-constants.ts` (modified)
- `src/gateway/openai-http.ts` (modified)
- `src/gateway/tools-invoke-http.ts` (modified)
- `src/gateway/openresponses-http.ts` (modified)
- `src/gateway/http-common.ts` (modified)

---

## Finding 2: WebSocket Connection Flood Protection (HIGH)

**Description:**
A single IP could open unlimited pending WebSocket connections, exhausting server
resources (file descriptors, memory) without ever authenticating.

**Remediation:**
- Added `PendingWsTracker` class (`src/gateway/ws-connection-limit.ts`)
- Default limit: 5 pending connections per IP
- Tracks connection count per remote IP; rejects with 429 when exceeded
- Slot released when socket closes (regardless of auth outcome)
- Integrated into `attachGatewayUpgradeHandler()` upgrade path

**Files:**
- `src/gateway/ws-connection-limit.ts` (new)
- `src/gateway/ws-connection-limit.test.ts` (new)
- `src/gateway/server-http.ts` (modified)
- `src/gateway/server-constants.ts` (modified)

---

## Finding 3: Control UI Served Without Authentication (HIGH)

**Description:**
The Control UI (HTML/JS/CSS assets and avatar endpoints) was served to any requester
without authentication when accessed from a non-loopback address. An attacker with
network access could load the full UI.

**Remediation:**
- Added bearer token authentication gate before serving Control UI for non-loopback requests
- Loopback (local) requests continue to bypass auth for developer convenience
- Uses the same `authorizeGatewayConnect()` + `getBearerToken()` pattern as canvas auth

**Files:**
- `src/gateway/server-http.ts` (modified)

---

## Finding 4: Passwords Stored in Plaintext (MEDIUM)

**Description:**
Gateway passwords configured via `gateway.auth.password` were stored and compared
as plaintext. If the config file was compromised, the password was immediately usable.

**Remediation:**
- Added `password-hash.ts` with scrypt-based hashing (Node.js `crypto.scrypt`, zero new deps)
- Hash format: `scrypt:<salt-hex>:<key-hex>` (64-byte key, 32-byte salt, N=16384)
- `authorizeGatewayConnect()` detects the `scrypt:` prefix and uses `verifyPassword()`
- Backward-compatible: plaintext passwords continue to work (with audit warning)
- Hashed passwords verified using `timingSafeEqual` for the key comparison
- Audit finding enhanced to distinguish hashed vs plaintext passwords

**Files:**
- `src/gateway/password-hash.ts` (new)
- `src/gateway/password-hash.test.ts` (new)
- `src/gateway/auth.ts` (modified)
- `src/security/audit-extra.ts` (modified)

---

## Finding 5: No Password Strength Enforcement (MEDIUM)

**Description:**
No validation was performed on password strength. Users could configure single-character
passwords for a publicly-exposed gateway.

**Remediation:**
- Added `checkPasswordStrength()` (`src/gateway/password-strength.ts`)
- Checks: minimum 8 chars (required), 12 chars (recommended), mixed case, digits, symbols
- Scoring: 0-5 scale; weak passwords produce audit warnings
- Non-blocking: weak passwords produce a warning, not a startup error
- New audit finding: `gateway.password_weak`

**Files:**
- `src/gateway/password-strength.ts` (new)
- `src/gateway/password-strength.test.ts` (new)
- `src/security/audit.ts` (modified)

---

## Finding 6: Hook Token Non-Constant-Time Comparison (MEDIUM)

**Description:**
The hooks HTTP handler compared the hook token using JavaScript's `!==` operator
(`token !== hooksConfig.token`), which is vulnerable to timing side-channel attacks.
An attacker could potentially determine the token character-by-character by measuring
response times.

**Remediation:**
- Exported existing `safeEqual()` from `src/gateway/auth.ts` (uses `crypto.timingSafeEqual`)
- Replaced `token !== hooksConfig.token` with `!safeEqual(token, hooksConfig.token)` in hooks handler

**Files:**
- `src/gateway/auth.ts` (modified: export `safeEqual`)
- `src/gateway/server-http.ts` (modified: use `safeEqual` for hook token)

---

## Finding 7: Dangerous Auth Bypass Flags Need Friction (MEDIUM)

**Description:**
The config flags `dangerouslyDisableDeviceAuth` and `allowInsecureAuth` could be
enabled with just a config file change. There was no additional confirmation step,
making it easy to accidentally leave these enabled in production.

**Remediation:**
- `dangerouslyDisableDeviceAuth=true` now requires `OPENCLAW_DANGEROUSLY_DISABLE_DEVICE_AUTH=1` env var
- `allowInsecureAuth=true` now requires `OPENCLAW_ALLOW_INSECURE_AUTH=1` env var
- Gateway throws on startup if the config flag is set without the env var
- Both log prominent `[SECURITY WARNING]` at startup even when the env var is present
- Audit remediation text updated to mention the env-var requirement

**Files:**
- `src/gateway/server-runtime-config.ts` (modified)
- `src/security/audit.ts` (modified)

---

## Finding 8: No CORS on HTTP API Endpoints (MEDIUM)

**Description:**
HTTP API endpoints (`/v1/chat/completions`, `/v1/responses`, `/tools/invoke`) did not
set CORS headers. While browsers enforce same-origin policy, the lack of explicit CORS
headers meant no controlled cross-origin access was possible for legitimate use cases,
and no explicit denial was in place.

**Remediation:**
- Added CORS utilities (`src/gateway/cors.ts`): `applyCorsHeaders()` and `handlePreflight()`
- Restrictive default: if no `allowedOrigins` configured, no CORS headers are set
- Reuses `gateway.controlUi.allowedOrigins` from existing config
- OPTIONS preflight handled early in `handleRequest()` before routing
- CORS headers applied after successful auth on each API endpoint

**Files:**
- `src/gateway/cors.ts` (new)
- `src/gateway/cors.test.ts` (new)
- `src/gateway/server-http.ts` (modified)
- `src/gateway/openai-http.ts` (modified)
- `src/gateway/tools-invoke-http.ts` (modified)
- `src/gateway/openresponses-http.ts` (modified)

---

## Finding 9: No TLS Enforcement Warning (MEDIUM)

**Description:**
When the gateway was bound to a non-loopback address without TLS and without Tailscale,
there was no warning that traffic (including auth credentials) was transmitted in cleartext.

**Remediation:**
- New audit finding: `gateway.no_tls_non_loopback` (severity: warn)
- Startup `console.warn` with actionable message
- Non-blocking: warning only (user may be behind a TLS-terminating proxy)
- Suggests `gateway.tls.enabled=true` or Tailscale Serve

**Files:**
- `src/security/audit.ts` (modified)
- `src/gateway/server-runtime-config.ts` (modified)

---

## Finding 10: Auth Failure Information Leakage (LOW)

**Description:**
When authentication failed, the error message included detailed hints about the auth
mode (token vs password), what was missing, and how to fix it. While helpful for
local debugging, this leaked configuration details to remote attackers.

**Remediation:**
- Added `isLocal` parameter to `formatGatewayAuthFailureMessage()`
- Remote clients (`isLocal=false`) receive a generic `"unauthorized"` message
- Local clients continue to receive detailed messages for debugging
- Server-side logging always includes the full reason regardless

**Files:**
- `src/gateway/server/ws-connection/message-handler.ts` (modified)

---

## Verification Checklist

1. Run existing tests: `pnpm test` to confirm no regressions
2. Run security audit: `openclaw security audit --deep` to verify new findings appear
3. Manual testing:
   - Start gateway with `bind=lan`, verify rate limiting triggers after 5 failed WS connects
   - Verify Control UI returns 401 without bearer token from non-loopback
   - Verify hooks use constant-time comparison (code review)
   - Verify hashed passwords work: hash a password, set it in config, authenticate
4. New unit tests pass: `pnpm test -- --testPathPattern="rate-limit|ws-connection-limit|password-strength|password-hash|cors"`
