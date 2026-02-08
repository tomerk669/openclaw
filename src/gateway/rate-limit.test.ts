import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuthRateLimiter, resetAuthRateLimiter } from "./rate-limit.js";

describe("AuthRateLimiter", () => {
  let limiter: AuthRateLimiter;

  beforeEach(() => {
    limiter = new AuthRateLimiter({
      maxAttempts: 3,
      windowMs: 60_000,
      lockoutInitialMs: 100,
      lockoutMaxMs: 5_000,
      cleanupIntervalMs: 60_000,
    });
  });

  afterEach(() => {
    limiter.destroy();
    resetAuthRateLimiter();
  });

  it("allows requests with no prior failures", () => {
    const result = limiter.check("1.2.3.4");
    expect(result.allowed).toBe(true);
  });

  it("allows requests below the threshold", () => {
    limiter.recordFailure("1.2.3.4");
    limiter.recordFailure("1.2.3.4");
    const result = limiter.check("1.2.3.4");
    expect(result.allowed).toBe(true);
  });

  it("blocks after reaching the threshold", () => {
    for (let i = 0; i < 3; i++) {
      limiter.recordFailure("1.2.3.4");
    }
    const result = limiter.check("1.2.3.4");
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.retryAfterMs).toBeGreaterThan(0);
    }
  });

  it("does not affect other IPs", () => {
    for (let i = 0; i < 5; i++) {
      limiter.recordFailure("1.2.3.4");
    }
    const result = limiter.check("5.6.7.8");
    expect(result.allowed).toBe(true);
  });

  it("clears entries on success", () => {
    limiter.recordFailure("1.2.3.4");
    limiter.recordFailure("1.2.3.4");
    limiter.recordSuccess("1.2.3.4");
    expect(limiter.size).toBe(0);
    const result = limiter.check("1.2.3.4");
    expect(result.allowed).toBe(true);
  });

  it("increases lockout duration with continued failures", () => {
    // First lockout
    for (let i = 0; i < 3; i++) {
      limiter.recordFailure("1.2.3.4");
    }
    const r1 = limiter.check("1.2.3.4");
    expect(r1.allowed).toBe(false);
    const retryAfter1 = !r1.allowed ? r1.retryAfterMs : 0;

    // More failures = longer lockout
    limiter.recordFailure("1.2.3.4");
    const r2 = limiter.check("1.2.3.4");
    expect(r2.allowed).toBe(false);
    const retryAfter2 = !r2.allowed ? r2.retryAfterMs : 0;

    expect(retryAfter2).toBeGreaterThanOrEqual(retryAfter1);
  });

  it("tracks size correctly", () => {
    expect(limiter.size).toBe(0);
    limiter.recordFailure("1.1.1.1");
    limiter.recordFailure("2.2.2.2");
    expect(limiter.size).toBe(2);
    limiter.recordSuccess("1.1.1.1");
    expect(limiter.size).toBe(1);
  });
});
