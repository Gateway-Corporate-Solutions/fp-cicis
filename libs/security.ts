const encoder = new TextEncoder();

export const SESSION_COOKIE_NAME = "fp_cicis_session";
export const MAX_MESSAGE_BYTES = 256 * 1024;
export const MAX_PAYLOAD_DEPTH = 12;
export const MAX_OBJECT_KEYS = 256;
export const MAX_ARRAY_LENGTH = 128;
export const MAX_STRING_LENGTH = 2048;

export interface WebSocketSession {
  id: string;
  token: string;
  expiresAt: number;
}

export interface FingerprintEnvelope {
  type: "data";
  data: Record<string, unknown>;
}

export interface ParseClientMessageSuccess {
  ok: true;
  value: FingerprintEnvelope;
}

export interface ParseClientMessageFailure {
  ok: false;
  closeCode: number;
  clientMessage: string;
}

export type ParseClientMessageResult = ParseClientMessageSuccess | ParseClientMessageFailure;

export function buildSecurityHeaders(): Record<string, string> {
  return {
    "Content-Security-Policy": [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self' https: data:",
      "connect-src 'self' ws: wss:",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "object-src 'none'",
    ].join("; "),
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  };
}

export function applySecurityHeaders(headers: Headers, isSecureRequest: boolean): void {
  for (const [name, value] of Object.entries(buildSecurityHeaders())) {
    headers.set(name, value);
  }

  if (isSecureRequest) {
    headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
}

export function injectSessionToken(template: string, token: string): string {
  return template.replaceAll("__WS_SESSION_TOKEN__", token);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function measureUtf8Size(value: string): number {
  return encoder.encode(value).byteLength;
}

function isSerializablePayloadValue(value: unknown, depth = 0): boolean {
  if (depth > MAX_PAYLOAD_DEPTH) {
    return false;
  }

  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "number"
  ) {
    return Number.isFinite(value as number) || typeof value !== "number";
  }

  if (typeof value === "string") {
    return measureUtf8Size(value) <= MAX_STRING_LENGTH;
  }

  if (Array.isArray(value)) {
    return value.length <= MAX_ARRAY_LENGTH && value.every((entry) => isSerializablePayloadValue(entry, depth + 1));
  }

  if (isPlainObject(value)) {
    const keys = Object.keys(value);
    return keys.length <= MAX_OBJECT_KEYS && keys.every((key) => {
      if (measureUtf8Size(key) > MAX_STRING_LENGTH) {
        return false;
      }
      return isSerializablePayloadValue(value[key], depth + 1);
    });
  }

  return false;
}

export function parseClientMessage(rawMessage: unknown): ParseClientMessageResult {
  if (typeof rawMessage !== "string") {
    return {
      ok: false,
      closeCode: 1003,
      clientMessage: "Invalid websocket frame type.",
    };
  }

  if (measureUtf8Size(rawMessage) > MAX_MESSAGE_BYTES) {
    return {
      ok: false,
      closeCode: 1009,
      clientMessage: "Request payload is too large.",
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawMessage);
  } catch {
    return {
      ok: false,
      closeCode: 1003,
      clientMessage: "Invalid JSON payload.",
    };
  }

  if (!isPlainObject(parsed) || parsed.type !== "data" || !isPlainObject(parsed.data)) {
    return {
      ok: false,
      closeCode: 1008,
      clientMessage: "Unsupported websocket payload.",
    };
  }

  if (!isSerializablePayloadValue(parsed.data)) {
    return {
      ok: false,
      closeCode: 1008,
      clientMessage: "Fingerprint payload failed validation.",
    };
  }

  return {
    ok: true,
    value: {
      type: "data",
      data: parsed.data,
    },
  };
}

export function sanitizeUserId(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }

  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > 128) {
    return undefined;
  }

  return /^[A-Za-z0-9_.:@-]+$/.test(trimmed) ? trimmed : undefined;
}

export function parseConfiguredOrigins(value?: string | null): string[] {
  return (value ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function firstForwardedValue(value: string | null): string | null {
  if (!value) {
    return null;
  }

  const [firstEntry] = value.split(",");
  const normalized = firstEntry?.trim();
  return normalized ? normalized : null;
}

export function resolveExternalOrigin(
  requestUrl: URL,
  headers: Headers,
  configuredOrigin?: string | null,
): string {
  if (configuredOrigin) {
    return configuredOrigin;
  }

  const forwardedProto = firstForwardedValue(headers.get("x-forwarded-proto"));
  const forwardedHost = firstForwardedValue(headers.get("x-forwarded-host"));
  const host = forwardedHost ?? headers.get("host") ?? requestUrl.host;
  const protocol = forwardedProto ?? requestUrl.protocol.replace(/:$/, "");

  return `${protocol}://${host}`;
}

export function isExternalOriginSecure(origin: string): boolean {
  try {
    return new URL(origin).protocol === "https:";
  } catch {
    return false;
  }
}

export function isOriginAllowed(originHeader: string | null, requestOrigin: string, configuredOrigins: string[]): boolean {
  if (!originHeader) {
    return false;
  }

  try {
    const normalizedOrigin = new URL(originHeader).origin;
    const allowedOrigins = new Set<string>([requestOrigin, ...configuredOrigins]);
    return allowedOrigins.has(normalizedOrigin);
  } catch {
    return false;
  }
}

export function parseTrustedProxyIps(value?: string | null): Set<string> {
  return new Set(
    (value ?? "")
      .split(",")
      .map((entry) => entry.trim())
      .filter(Boolean),
  );
}

function isIPv4(value: string): boolean {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((part) => /^\d+$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function isIPv6(value: string): boolean {
  return /^[0-9a-fA-F:]+$/.test(value) && value.includes(":");
}

export function isIpAddress(value: string): boolean {
  return isIPv4(value) || isIPv6(value);
}

export function resolveClientIp(requestIp: string, forwardedIp: string | null, trustedProxyIps: Set<string>): string {
  if (!trustedProxyIps.has(requestIp)) {
    return requestIp;
  }

  const candidate = forwardedIp?.trim() ?? "";
  return isIpAddress(candidate) ? candidate : requestIp;
}

export class SessionStore {
  #sessions = new Map<string, WebSocketSession>();
  #ttlMs: number;
  #now: () => number;

  constructor(ttlMs = 10 * 60 * 1000, now = () => Date.now()) {
    this.#ttlMs = ttlMs;
    this.#now = now;
  }

  createSession(): WebSocketSession {
    this.cleanupExpiredSessions();
    const id = crypto.randomUUID();
    const token = Array.from(crypto.getRandomValues(new Uint8Array(24)))
      .map((value) => value.toString(16).padStart(2, "0"))
      .join("");
    const session = {
      id,
      token,
      expiresAt: this.#now() + this.#ttlMs,
    };
    this.#sessions.set(id, session);
    return session;
  }

  validateSession(sessionId: string | undefined, token: string | null): boolean {
    this.cleanupExpiredSessions();
    if (!sessionId || !token) {
      return false;
    }

    const session = this.#sessions.get(sessionId);
    return session !== undefined && session.token === token;
  }

  cleanupExpiredSessions(): void {
    const now = this.#now();
    for (const [id, session] of this.#sessions.entries()) {
      if (session.expiresAt <= now) {
        this.#sessions.delete(id);
      }
    }
  }
}

export class RateLimiter {
  #connections = new Map<string, number>();
  #messages = new Map<string, number[]>();
  #now: () => number;
  #maxConnectionsPerIp: number;
  #maxMessagesPerMinute: number;

  constructor(maxConnectionsPerIp = 10, maxMessagesPerMinute = 30, now = () => Date.now()) {
    this.#maxConnectionsPerIp = maxConnectionsPerIp;
    this.#maxMessagesPerMinute = maxMessagesPerMinute;
    this.#now = now;
  }

  tryOpenConnection(ip: string): boolean {
    const current = this.#connections.get(ip) ?? 0;
    if (current >= this.#maxConnectionsPerIp) {
      return false;
    }

    this.#connections.set(ip, current + 1);
    return true;
  }

  releaseConnection(ip: string): void {
    const current = this.#connections.get(ip) ?? 0;
    if (current <= 1) {
      this.#connections.delete(ip);
      return;
    }

    this.#connections.set(ip, current - 1);
  }

  allowMessage(ip: string): boolean {
    const now = this.#now();
    const windowStart = now - 60_000;
    const recentMessages = (this.#messages.get(ip) ?? []).filter((timestamp) => timestamp >= windowStart);
    if (recentMessages.length >= this.#maxMessagesPerMinute) {
      this.#messages.set(ip, recentMessages);
      return false;
    }

    recentMessages.push(now);
    this.#messages.set(ip, recentMessages);
    return true;
  }
}