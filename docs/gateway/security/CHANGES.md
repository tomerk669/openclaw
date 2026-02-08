# Security Hardening Changes — Context & Rationale

## Why These Changes Exist

OpenClaw is designed for local use and explicitly states its web interface is "not hardened for public exposure." These changes address 10 vulnerabilities identified during a security audit to make the gateway safe for deployment on a hosted environment with the UI console exposed publicly.

The core problem: when OpenClaw's gateway is bound to a non-loopback address (e.g., `bind=lan`), several assumptions that hold for localhost break down — there's no brute-force protection, no connection flooding defense, and the Control UI serves assets to anyone who can reach the port.

---

## Change-by-Change Rationale

### 1. Auth Rate Limiting (`rate-limit.ts`)

**Problem:** An attacker with network access could try unlimited passwords/tokens per second. A 6-character token could be brute-forced in minutes.

**Approach:** Per-IP sliding window (5 attempts / 15 min) with exponential lockout (1s → 5 min). The limiter is an in-memory `Map` — no new dependencies. Loopback connections are exempt so local development isn't affected. HTTP endpoints return 429 with `Retry-After`. The singleton pattern with `resetAuthRateLimiter()` keeps tests isolated.

**Why not Redis/external store?** OpenClaw is a single-process app. In-memory is simpler, faster, and sufficient. If the process restarts, rate-limit state resetting is acceptable.

### 2. WebSocket Flood Protection (`ws-connection-limit.ts`)

**Problem:** Each pending WebSocket connection consumes a file descriptor and memory. An attacker could open thousands of connections without authenticating, exhausting server resources (classic slowloris-style attack).

**Approach:** Track pending (pre-auth) connections per remote IP. Default limit: 5 concurrent pending connections. The slot is acquired in the `upgrade` handler and released on socket close. Rejected with 429 at the raw socket level before the WebSocket handshake even begins.

**Why per-IP, not global?** A global limit would let one attacker block all legitimate users. Per-IP limits contain the blast radius.

### 3. Control UI Auth Gate (`server-http.ts`)

**Problem:** The Control UI HTML/JS/CSS was served to any requester without authentication. On a public deployment, anyone could load the full dashboard interface. While they couldn't _use_ it without auth, serving the UI leaks information about the deployment and increases attack surface.

**Approach:** Before serving Control UI assets for non-loopback requests, require a bearer token (same pattern already used for canvas auth). Loopback requests bypass auth — consistent with the existing `isLocalDirectRequest()` convention used everywhere else.

### 4. Password Hashing (`password-hash.ts`)

**Problem:** Passwords in `gateway.auth.password` were stored and compared as plaintext. If the config file leaked (backup, version control, shared machine), the password was immediately usable.

**Approach:** scrypt-based hashing using only Node.js `crypto` (zero new dependencies). Hash format: `scrypt:<salt-hex>:<key-hex>`. The auth flow detects the `scrypt:` prefix and switches to `verifyPassword()` (which uses `timingSafeEqual` internally). Plaintext passwords continue to work for backward compatibility — the audit warns about them. This is opt-in: users hash passwords themselves and paste the hash into config.

**Why scrypt over bcrypt/argon2?** scrypt is built into Node.js `crypto`. No native addon compilation, no new dependency. For a gateway password (not millions of user accounts), scrypt with N=16384 is more than adequate.

### 5. Password Strength Checks (`password-strength.ts`)

**Problem:** Users could set `password: "a"` and expose their gateway publicly. No feedback loop existed to warn about weak passwords.

**Approach:** Simple scoring: length (8 required, 12 recommended), mixed case, digits, symbols. Score 0–5. Produces audit warnings for weak passwords. Non-blocking — weak passwords work but generate warnings. This is a guardrail, not a gate.

### 6. Hook Token Timing Fix (`auth.ts`, `server-http.ts`)

**Problem:** Hook token comparison used `token !== hooksConfig.token` — JavaScript string comparison that short-circuits on the first differing character. An attacker could determine the token character-by-character by measuring response times (timing side-channel).

**Approach:** One-line fix. The codebase already had `safeEqual()` (wrapping `crypto.timingSafeEqual`) for gateway auth. It just wasn't exported or used for hooks. Export it, import it, swap the comparison. The existing `safeEqual` already handles length-mismatch safely (compares full buffer regardless).

### 7. Dangerous Flag Friction (`server-runtime-config.ts`)

**Problem:** `dangerouslyDisableDeviceAuth` and `allowInsecureAuth` could be enabled with a single config file edit. Easy to set during debugging, easy to forget to unset. No runtime confirmation.

**Approach:** Require a matching environment variable (`OPENCLAW_DANGEROUSLY_DISABLE_DEVICE_AUTH=1` / `OPENCLAW_ALLOW_INSECURE_AUTH=1`). Gateway throws on startup if the config flag is set without the env var. Even with the env var, a prominent `[SECURITY WARNING]` is logged. This creates two-factor confirmation: config file _and_ environment.

**Why not remove the flags entirely?** They serve legitimate break-glass purposes. The goal is friction, not elimination.

### 8. CORS Protection (`cors.ts`)

**Problem:** HTTP API endpoints had no CORS headers at all. While browsers enforce same-origin policy by default, the absence of explicit CORS headers meant: (a) no controlled cross-origin access for legitimate use cases, and (b) no explicit server-side denial posture.

**Approach:** Restrictive default — if no `allowedOrigins` configured, no `Access-Control-Allow-Origin` header is set (blocks all cross-origin requests). Reuses the existing `gateway.controlUi.allowedOrigins` config. OPTIONS preflight handled early in the request pipeline before routing. CORS headers applied after successful auth on each API endpoint (so preflight works, but actual requests still require auth).

### 9. TLS Warning (`audit.ts`, `server-runtime-config.ts`)

**Problem:** When binding to a non-loopback address without TLS and without Tailscale, auth credentials travel in cleartext. No warning existed.

**Approach:** Audit finding (`gateway.no_tls_non_loopback`, severity: warn) plus a startup `console.warn`. Non-blocking because the user may have a TLS-terminating reverse proxy in front. The message suggests `gateway.tls.enabled=true` or Tailscale Serve as remediation.

### 10. Auth Failure Info Leakage (`message-handler.ts`)

**Problem:** Failed auth responses included detailed messages like "gateway token mismatch (set gateway.remote.token to match gateway.auth.token)" — telling an attacker exactly what auth mode is configured and how to fix their attempt.

**Approach:** Added `isLocal` parameter to `formatGatewayAuthFailureMessage()`. Remote clients get a generic `"unauthorized"`. Local clients keep the detailed messages (essential for debugging). The server-side log always records the full reason regardless — the information isn't lost, just not sent over the wire to attackers.

---

## Design Principles Applied

1. **No new dependencies.** Everything uses Node.js built-ins (`crypto.scrypt`, `crypto.timingSafeEqual`, `Map`, `setInterval`).

2. **Backward compatible.** Plaintext passwords still work. No config format changes required. Existing deployments continue to function — they just get audit warnings.

3. **Local development unaffected.** All protections exempt loopback connections. Rate limiting, Control UI auth gates, info leakage restrictions — none apply to localhost.

4. **Defense in depth.** Multiple layers: rate limiting + flood protection + auth + CORS + TLS warnings. No single fix is the complete solution.

5. **Fail closed, warn open.** Dangerous flags require explicit env-var confirmation (fail closed). Weak passwords and missing TLS produce warnings (warn open). The distinction: flags that _disable_ security fail closed; _weak_ security settings warn.

---

## Verification Steps

After installing Node.js and dependencies:

```bash
# Type check
pnpm tsc --noEmit

# Run all tests
pnpm test

# Run only the new tests
pnpm test -- --testPathPattern="rate-limit|ws-connection-limit|password-strength|password-hash|cors"

# Run security audit to see new findings
openclaw security audit --deep
```

### Manual smoke tests

1. **Rate limiting:** Start with `bind=lan`, fail auth 5 times from a remote IP, verify 6th attempt gets rate_limited/429
2. **Control UI auth:** From a remote IP, `curl http://<host>:<port>/` without auth — should get 401
3. **WS flood:** Open 6 WebSocket connections from the same IP without authenticating — 6th should get 429
4. **Password hashing:** Generate a hash, set it in config, verify auth works:
   ```js
   // In Node REPL:
   const { hashPassword } = await import("./src/gateway/password-hash.js");
   console.log(await hashPassword("my-password"));
   // Paste output into gateway.auth.password config
   ```
5. **Dangerous flags:** Set `dangerouslyDisableDeviceAuth=true` without the env var — gateway should refuse to start
