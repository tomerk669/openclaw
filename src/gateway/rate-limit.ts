import {
  AUTH_RATE_LIMIT_MAX_ATTEMPTS,
  AUTH_RATE_LIMIT_WINDOW_MS,
  AUTH_RATE_LIMIT_LOCKOUT_INITIAL_MS,
  AUTH_RATE_LIMIT_LOCKOUT_MAX_MS,
  AUTH_RATE_LIMIT_CLEANUP_INTERVAL_MS,
} from "./server-constants.js";

type RateLimitEntry = {
  failedAttempts: number;
  firstFailAt: number;
  lockedUntilMs: number;
};

export type RateLimitCheckResult =
  | { allowed: true }
  | { allowed: false; retryAfterMs: number };

export class AuthRateLimiter {
  private entries = new Map<string, RateLimitEntry>();
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  private maxAttempts: number;
  private windowMs: number;
  private lockoutInitialMs: number;
  private lockoutMaxMs: number;

  constructor(opts?: {
    maxAttempts?: number;
    windowMs?: number;
    lockoutInitialMs?: number;
    lockoutMaxMs?: number;
    cleanupIntervalMs?: number;
  }) {
    this.maxAttempts = opts?.maxAttempts ?? AUTH_RATE_LIMIT_MAX_ATTEMPTS;
    this.windowMs = opts?.windowMs ?? AUTH_RATE_LIMIT_WINDOW_MS;
    this.lockoutInitialMs = opts?.lockoutInitialMs ?? AUTH_RATE_LIMIT_LOCKOUT_INITIAL_MS;
    this.lockoutMaxMs = opts?.lockoutMaxMs ?? AUTH_RATE_LIMIT_LOCKOUT_MAX_MS;

    const cleanupMs = opts?.cleanupIntervalMs ?? AUTH_RATE_LIMIT_CLEANUP_INTERVAL_MS;
    this.cleanupTimer = setInterval(() => this.cleanup(), cleanupMs);
    if (this.cleanupTimer.unref) {
      this.cleanupTimer.unref();
    }
  }

  check(ip: string): RateLimitCheckResult {
    const entry = this.entries.get(ip);
    if (!entry) {
      return { allowed: true };
    }

    const now = Date.now();

    // Check if currently locked out
    if (entry.lockedUntilMs > now) {
      return { allowed: false, retryAfterMs: entry.lockedUntilMs - now };
    }

    // Check if the window has expired
    if (now - entry.firstFailAt > this.windowMs) {
      this.entries.delete(ip);
      return { allowed: true };
    }

    return { allowed: true };
  }

  recordFailure(ip: string): void {
    const now = Date.now();
    const entry = this.entries.get(ip);

    if (!entry || now - entry.firstFailAt > this.windowMs) {
      this.entries.set(ip, {
        failedAttempts: 1,
        firstFailAt: now,
        lockedUntilMs: 0,
      });
      return;
    }

    entry.failedAttempts += 1;

    if (entry.failedAttempts >= this.maxAttempts) {
      // Exponential lockout: 1s, 2s, 4s, ... up to lockoutMaxMs
      const lockoutExponent = entry.failedAttempts - this.maxAttempts;
      const lockoutMs = Math.min(
        this.lockoutMaxMs,
        this.lockoutInitialMs * 2 ** lockoutExponent,
      );
      entry.lockedUntilMs = now + lockoutMs;
    }
  }

  recordSuccess(ip: string): void {
    this.entries.delete(ip);
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [ip, entry] of this.entries) {
      // Remove entries where the window has expired and lockout has passed
      if (now - entry.firstFailAt > this.windowMs && entry.lockedUntilMs <= now) {
        this.entries.delete(ip);
      }
    }
  }

  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.entries.clear();
  }

  /** @internal for testing */
  get size(): number {
    return this.entries.size;
  }
}

let singleton: AuthRateLimiter | null = null;

export function getAuthRateLimiter(): AuthRateLimiter {
  if (!singleton) {
    singleton = new AuthRateLimiter();
  }
  return singleton;
}

export function resetAuthRateLimiter(): void {
  if (singleton) {
    singleton.destroy();
    singleton = null;
  }
}
