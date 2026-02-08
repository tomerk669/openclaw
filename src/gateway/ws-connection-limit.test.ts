import { describe, expect, it } from "vitest";
import { PendingWsTracker } from "./ws-connection-limit.js";

describe("PendingWsTracker", () => {
  it("allows connections below the limit", () => {
    const tracker = new PendingWsTracker(3);
    expect(tracker.acquire("1.2.3.4")).toBe(true);
    expect(tracker.acquire("1.2.3.4")).toBe(true);
    expect(tracker.acquire("1.2.3.4")).toBe(true);
  });

  it("rejects connections at the limit", () => {
    const tracker = new PendingWsTracker(2);
    expect(tracker.acquire("1.2.3.4")).toBe(true);
    expect(tracker.acquire("1.2.3.4")).toBe(true);
    expect(tracker.acquire("1.2.3.4")).toBe(false);
  });

  it("does not affect other IPs", () => {
    const tracker = new PendingWsTracker(1);
    expect(tracker.acquire("1.2.3.4")).toBe(true);
    expect(tracker.acquire("1.2.3.4")).toBe(false);
    expect(tracker.acquire("5.6.7.8")).toBe(true);
  });

  it("allows new connections after release", () => {
    const tracker = new PendingWsTracker(1);
    expect(tracker.acquire("1.2.3.4")).toBe(true);
    expect(tracker.acquire("1.2.3.4")).toBe(false);
    tracker.release("1.2.3.4");
    expect(tracker.acquire("1.2.3.4")).toBe(true);
  });

  it("cleans up map entry when count drops to zero", () => {
    const tracker = new PendingWsTracker(5);
    tracker.acquire("1.2.3.4");
    expect(tracker.size).toBe(1);
    tracker.release("1.2.3.4");
    expect(tracker.size).toBe(0);
  });

  it("handles release on unknown IP gracefully", () => {
    const tracker = new PendingWsTracker(5);
    tracker.release("unknown");
    expect(tracker.size).toBe(0);
  });

  it("tracks counts correctly", () => {
    const tracker = new PendingWsTracker(5);
    tracker.acquire("1.2.3.4");
    tracker.acquire("1.2.3.4");
    expect(tracker.getCount("1.2.3.4")).toBe(2);
    tracker.release("1.2.3.4");
    expect(tracker.getCount("1.2.3.4")).toBe(1);
  });
});
