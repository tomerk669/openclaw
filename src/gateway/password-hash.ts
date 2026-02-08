import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";

const SCRYPT_KEYLEN = 64;
const SCRYPT_COST = 16384; // N
const SCRYPT_BLOCK_SIZE = 8; // r
const SCRYPT_PARALLELISM = 1; // p
const SALT_BYTES = 32;
const PREFIX = "scrypt:";

/**
 * Check whether a stored password value is a hashed password (vs plaintext).
 */
export function isHashedPassword(value: string): boolean {
  return value.startsWith(PREFIX);
}

/**
 * Hash a password using scrypt. Returns a string like `scrypt:<salt-hex>:<key-hex>`.
 */
export function hashPassword(password: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const salt = randomBytes(SALT_BYTES);
    scrypt(
      password,
      salt,
      SCRYPT_KEYLEN,
      { N: SCRYPT_COST, r: SCRYPT_BLOCK_SIZE, p: SCRYPT_PARALLELISM },
      (err, derivedKey) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(`${PREFIX}${salt.toString("hex")}:${derivedKey.toString("hex")}`);
      },
    );
  });
}

/**
 * Verify a plaintext password against a stored hash.
 * Uses `timingSafeEqual` for the key comparison.
 */
export function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  return new Promise((resolve, reject) => {
    if (!isHashedPassword(storedHash)) {
      resolve(false);
      return;
    }

    const withoutPrefix = storedHash.slice(PREFIX.length);
    const colonIndex = withoutPrefix.indexOf(":");
    if (colonIndex === -1) {
      resolve(false);
      return;
    }

    const saltHex = withoutPrefix.slice(0, colonIndex);
    const keyHex = withoutPrefix.slice(colonIndex + 1);

    let salt: Buffer;
    let storedKey: Buffer;
    try {
      salt = Buffer.from(saltHex, "hex");
      storedKey = Buffer.from(keyHex, "hex");
    } catch {
      resolve(false);
      return;
    }

    if (storedKey.length !== SCRYPT_KEYLEN) {
      resolve(false);
      return;
    }

    scrypt(
      password,
      salt,
      SCRYPT_KEYLEN,
      { N: SCRYPT_COST, r: SCRYPT_BLOCK_SIZE, p: SCRYPT_PARALLELISM },
      (err, derivedKey) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(timingSafeEqual(derivedKey, storedKey));
      },
    );
  });
}
