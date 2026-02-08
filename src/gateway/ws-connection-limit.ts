import { MAX_PENDING_WS_PER_IP } from "./server-constants.js";

/**
 * Tracks pending (not-yet-authenticated) WebSocket connections per IP.
 * Prevents a single IP from exhausting server resources with many concurrent connections.
 */
export class PendingWsTracker {
  private counts = new Map<string, number>();
  private maxPerIp: number;

  constructor(maxPerIp?: number) {
    this.maxPerIp = maxPerIp ?? MAX_PENDING_WS_PER_IP;
  }

  /**
   * Try to acquire a connection slot for the given IP.
   * Returns true if allowed, false if the IP has too many pending connections.
   */
  acquire(ip: string): boolean {
    const current = this.counts.get(ip) ?? 0;
    if (current >= this.maxPerIp) {
      return false;
    }
    this.counts.set(ip, current + 1);
    return true;
  }

  /**
   * Release a connection slot for the given IP.
   */
  release(ip: string): void {
    const current = this.counts.get(ip) ?? 0;
    if (current <= 1) {
      this.counts.delete(ip);
    } else {
      this.counts.set(ip, current - 1);
    }
  }

  /** @internal for testing */
  get size(): number {
    return this.counts.size;
  }

  /** @internal for testing */
  getCount(ip: string): number {
    return this.counts.get(ip) ?? 0;
  }
}

let singleton: PendingWsTracker | null = null;

export function getPendingWsTracker(): PendingWsTracker {
  if (!singleton) {
    singleton = new PendingWsTracker();
  }
  return singleton;
}

export function resetPendingWsTracker(): void {
  singleton = null;
}
