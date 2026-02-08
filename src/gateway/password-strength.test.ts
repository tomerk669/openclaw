import { describe, expect, it } from "vitest";
import { checkPasswordStrength } from "./password-strength.js";

describe("checkPasswordStrength", () => {
  it("rejects passwords shorter than 8 characters", () => {
    const result = checkPasswordStrength("short");
    expect(result.ok).toBe(false);
    expect(result.reasons.some((r) => r.includes("too short"))).toBe(true);
  });

  it("accepts passwords with 8+ characters", () => {
    const result = checkPasswordStrength("abcdefgh");
    expect(result.ok).toBe(true);
  });

  it("recommends 12+ characters", () => {
    const result = checkPasswordStrength("abcdefgh");
    expect(result.reasons.some((r) => r.includes("12"))).toBe(true);
  });

  it("gives higher score for 12+ chars", () => {
    const short = checkPasswordStrength("abcdefgh");
    const long = checkPasswordStrength("abcdefghijkl");
    expect(long.score).toBeGreaterThan(short.score);
  });

  it("detects missing mixed case", () => {
    const result = checkPasswordStrength("alllowercase");
    expect(result.reasons.some((r) => r.includes("mixed case"))).toBe(true);
  });

  it("credits mixed case", () => {
    const lower = checkPasswordStrength("alllowercase");
    const mixed = checkPasswordStrength("MixedCaseNow");
    expect(mixed.score).toBeGreaterThan(lower.score);
  });

  it("detects missing digits", () => {
    const result = checkPasswordStrength("NoDigitsHere!");
    expect(result.reasons.some((r) => r.includes("digits"))).toBe(true);
  });

  it("detects missing special characters", () => {
    const result = checkPasswordStrength("NoSpecial123");
    expect(result.reasons.some((r) => r.includes("special"))).toBe(true);
  });

  it("gives max score for strong password", () => {
    const result = checkPasswordStrength("Str0ng!Pass#12");
    expect(result.ok).toBe(true);
    expect(result.score).toBe(5);
    expect(result.reasons).toHaveLength(0);
  });
});
