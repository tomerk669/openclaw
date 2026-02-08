import type { IncomingMessage, ServerResponse } from "node:http";

export type CorsConfig = {
  allowedOrigins?: string[];
};

function getOrigin(req: IncomingMessage): string | undefined {
  const raw = req.headers.origin;
  if (typeof raw === "string" && raw.trim()) {
    return raw.trim();
  }
  return undefined;
}

function isOriginAllowed(origin: string, allowedOrigins: string[]): boolean {
  if (allowedOrigins.length === 0) {
    return false;
  }
  const normalized = origin.toLowerCase();
  return allowedOrigins.some(
    (allowed) => allowed.trim().toLowerCase() === normalized,
  );
}

/**
 * Apply CORS headers to a response if the request origin is in the allowlist.
 * If no allowedOrigins are configured, no CORS headers are set (blocks all cross-origin).
 */
export function applyCorsHeaders(
  res: ServerResponse,
  req: IncomingMessage,
  config?: CorsConfig,
): void {
  const origin = getOrigin(req);
  if (!origin) {
    return;
  }
  const allowedOrigins = config?.allowedOrigins ?? [];
  if (!isOriginAllowed(origin, allowedOrigins)) {
    return;
  }
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type, X-OpenClaw-Token");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Max-Age", "86400");
}

/**
 * Handle an OPTIONS preflight request. Returns true if the request was handled.
 */
export function handlePreflight(
  req: IncomingMessage,
  res: ServerResponse,
  config?: CorsConfig,
): boolean {
  if (req.method !== "OPTIONS") {
    return false;
  }
  const origin = getOrigin(req);
  if (!origin) {
    return false;
  }
  const allowedOrigins = config?.allowedOrigins ?? [];
  if (!isOriginAllowed(origin, allowedOrigins)) {
    return false;
  }
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type, X-OpenClaw-Token");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Max-Age", "86400");
  res.statusCode = 204;
  res.end();
  return true;
}
