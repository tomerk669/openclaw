import { describe, expect, it } from "vitest";
import { hashPassword, isHashedPassword, verifyPassword } from "./password-hash.js";

describe("password-hash", () => {
  describe("isHashedPassword", () => {
    it("returns true for scrypt-prefixed strings", () => {
      expect(isHashedPassword("scrypt:abc:def")).toBe(true);
    });

    it("returns false for plaintext", () => {
      expect(isHashedPassword("myplainpassword")).toBe(false);
    });

    it("returns false for empty string", () => {
      expect(isHashedPassword("")).toBe(false);
    });
  });

  describe("hashPassword", () => {
    it("returns a scrypt-prefixed hash", async () => {
      const hash = await hashPassword("test-password");
      expect(hash.startsWith("scrypt:")).toBe(true);
      const parts = hash.split(":");
      expect(parts).toHaveLength(3);
      // salt and key should be hex strings
      expect(parts[1]).toMatch(/^[0-9a-f]+$/);
      expect(parts[2]).toMatch(/^[0-9a-f]+$/);
    });

    it("produces different hashes for the same password (random salt)", async () => {
      const hash1 = await hashPassword("same-password");
      const hash2 = await hashPassword("same-password");
      expect(hash1).not.toBe(hash2);
    });
  });

  describe("verifyPassword", () => {
    it("verifies a correct password", async () => {
      const hash = await hashPassword("correct-password");
      const result = await verifyPassword("correct-password", hash);
      expect(result).toBe(true);
    });

    it("rejects an incorrect password", async () => {
      const hash = await hashPassword("correct-password");
      const result = await verifyPassword("wrong-password", hash);
      expect(result).toBe(false);
    });

    it("returns false for non-hashed stored value", async () => {
      const result = await verifyPassword("password", "plaintext-value");
      expect(result).toBe(false);
    });

    it("returns false for malformed hash", async () => {
      const result = await verifyPassword("password", "scrypt:badhex");
      expect(result).toBe(false);
    });

    it("returns false for wrong key length", async () => {
      const result = await verifyPassword("password", "scrypt:aa:bb");
      expect(result).toBe(false);
    });
  });
});
