import { describe, expect, it } from "vitest";
import { applyCorsHeaders, handlePreflight } from "./cors.js";
import type { IncomingMessage, ServerResponse } from "node:http";

function mockReq(method: string, origin?: string): IncomingMessage {
  return {
    method,
    headers: origin ? { origin } : {},
  } as unknown as IncomingMessage;
}

function mockRes(): ServerResponse & { _headers: Record<string, string>; _statusCode: number } {
  const headers: Record<string, string> = {};
  return {
    _headers: headers,
    _statusCode: 200,
    setHeader(name: string, value: string) {
      headers[name.toLowerCase()] = value;
    },
    get statusCode() {
      return this._statusCode;
    },
    set statusCode(code: number) {
      this._statusCode = code;
    },
    end() {},
  } as unknown as ServerResponse & { _headers: Record<string, string>; _statusCode: number };
}

describe("applyCorsHeaders", () => {
  it("sets no headers when no origin in request", () => {
    const req = mockReq("GET");
    const res = mockRes();
    applyCorsHeaders(res, req, { allowedOrigins: ["http://example.com"] });
    expect(res._headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("sets no headers when no allowedOrigins configured", () => {
    const req = mockReq("GET", "http://example.com");
    const res = mockRes();
    applyCorsHeaders(res, req);
    expect(res._headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("sets no headers when origin is not in allowlist", () => {
    const req = mockReq("GET", "http://evil.com");
    const res = mockRes();
    applyCorsHeaders(res, req, { allowedOrigins: ["http://example.com"] });
    expect(res._headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("sets headers when origin is in allowlist", () => {
    const req = mockReq("GET", "http://example.com");
    const res = mockRes();
    applyCorsHeaders(res, req, { allowedOrigins: ["http://example.com"] });
    expect(res._headers["access-control-allow-origin"]).toBe("http://example.com");
    expect(res._headers["vary"]).toBe("Origin");
  });

  it("is case-insensitive for origin matching", () => {
    const req = mockReq("GET", "HTTP://Example.COM");
    const res = mockRes();
    applyCorsHeaders(res, req, { allowedOrigins: ["http://example.com"] });
    expect(res._headers["access-control-allow-origin"]).toBe("HTTP://Example.COM");
  });
});

describe("handlePreflight", () => {
  it("returns false for non-OPTIONS methods", () => {
    const req = mockReq("GET", "http://example.com");
    const res = mockRes();
    expect(handlePreflight(req, res, { allowedOrigins: ["http://example.com"] })).toBe(false);
  });

  it("returns false for OPTIONS without origin", () => {
    const req = mockReq("OPTIONS");
    const res = mockRes();
    expect(handlePreflight(req, res)).toBe(false);
  });

  it("returns false for OPTIONS with unlisted origin", () => {
    const req = mockReq("OPTIONS", "http://evil.com");
    const res = mockRes();
    expect(handlePreflight(req, res, { allowedOrigins: ["http://example.com"] })).toBe(false);
  });

  it("handles OPTIONS with allowed origin", () => {
    const req = mockReq("OPTIONS", "http://example.com");
    const res = mockRes();
    const handled = handlePreflight(req, res, { allowedOrigins: ["http://example.com"] });
    expect(handled).toBe(true);
    expect(res._statusCode).toBe(204);
    expect(res._headers["access-control-allow-origin"]).toBe("http://example.com");
  });
});
