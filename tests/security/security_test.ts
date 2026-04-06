// deno-lint-ignore-file no-import-prefix no-unversioned-import
import {
  assert,
  assertEquals,
  assertMatch,
  assertNotEquals,
} from "jsr:@std/assert";
import {
  RateLimiter,
  SessionStore,
  applySecurityHeaders,
  buildSessionCookieHeader,
  injectSessionToken,
  isExternalOriginSecure,
  isOriginAllowed,
  parseClientMessage,
  parseTrustedProxyIps,
  resolveExternalOrigin,
  resolveClientIp,
  sanitizeUserId,
} from "../../libs/security.ts";
import { buildWebSocketUrl } from "../../static/app.js";

Deno.test("parseClientMessage rejects malformed JSON without throwing", () => {
  const result = parseClientMessage("{");
  assertEquals(result.ok, false);
  if (!result.ok) {
    assertEquals(result.clientMessage, "Invalid JSON payload.");
    assertEquals(result.closeCode, 1003);
  }
});

Deno.test("parseClientMessage rejects non-object payloads and deep oversized content", () => {
  const invalidRoot = parseClientMessage(JSON.stringify({ type: "data", data: null }));
  assertEquals(invalidRoot.ok, false);

  const tooLarge = parseClientMessage(JSON.stringify({
    type: "data",
    data: { userAgent: "A".repeat(3000) },
  }));
  assertEquals(tooLarge.ok, false);
});

Deno.test("parseClientMessage accepts a typical fingerprint envelope", () => {
  const valid = parseClientMessage(JSON.stringify({
    type: "data",
    data: {
      userAgent: "Mozilla/5.0",
      platform: "Linux x86_64",
      timezone: "UTC",
      screen: { width: 1920, height: 1080 },
      fonts: ["Arial", "Verdana"],
      cookieEnabled: true,
    },
  }));

  assertEquals(valid.ok, true);
});

Deno.test("origin allowlist only accepts same-origin or configured origins", () => {
  assert(isOriginAllowed("http://localhost:5000", "http://localhost:5000", []));
  assert(isOriginAllowed("https://dashboard.example.com", "http://localhost:5000", ["https://dashboard.example.com"]));
  assert(!isOriginAllowed("https://evil.example.com", "http://localhost:5000", []));
  assert(!isOriginAllowed(null, "http://localhost:5000", []));
});

Deno.test("external origin resolution honors forwarded headers and explicit public origin", () => {
  const proxiedHeaders = new Headers({
    host: "127.0.0.1:5000",
    "x-forwarded-proto": "https",
    "x-forwarded-host": "cicis.info",
  });
  assertEquals(
    resolveExternalOrigin(new URL("http://127.0.0.1:5000/wss"), proxiedHeaders),
    "https://cicis.info",
  );

  assertEquals(
    resolveExternalOrigin(new URL("http://127.0.0.1:5000/wss"), new Headers(), "https://cicis.info"),
    "https://cicis.info",
  );
  assertEquals(isExternalOriginSecure("https://cicis.info"), true);
  assertEquals(isExternalOriginSecure("http://localhost:5000"), false);
});

Deno.test("trusted proxy logic only honors forwarded IPs from configured proxies", () => {
  const proxies = parseTrustedProxyIps("127.0.0.1,::1");
  assertEquals(resolveClientIp("127.0.0.1", "203.0.113.10", proxies), "203.0.113.10");
  assertEquals(resolveClientIp("198.51.100.10", "203.0.113.10", proxies), "198.51.100.10");
  assertEquals(resolveClientIp("127.0.0.1", "203.0.113.10\r\nX-Bad: 1", proxies), "127.0.0.1");
});

Deno.test("session store ties websocket tokens to server-issued cookies", () => {
  let now = 0;
  const store = new SessionStore(1_000, () => now);
  const session = store.createSession();
  assert(store.validateSession(session.id, session.token));
  assert(!store.validateSession(session.id, "wrong-token"));

  now = 2_000;
  assert(!store.validateSession(session.id, session.token));
});

Deno.test("rate limiter enforces connection and message ceilings", () => {
  let now = 0;
  const limiter = new RateLimiter(2, 2, () => now);
  assert(limiter.tryOpenConnection("203.0.113.1"));
  assert(limiter.tryOpenConnection("203.0.113.1"));
  assert(!limiter.tryOpenConnection("203.0.113.1"));
  limiter.releaseConnection("203.0.113.1");
  assert(limiter.tryOpenConnection("203.0.113.1"));

  assert(limiter.allowMessage("203.0.113.1"));
  assert(limiter.allowMessage("203.0.113.1"));
  assert(!limiter.allowMessage("203.0.113.1"));
  now = 61_000;
  assert(limiter.allowMessage("203.0.113.1"));
});

Deno.test("security headers include CSP and transport hardening", () => {
  const headers = new Headers();
  applySecurityHeaders(headers, true);
  assertEquals(headers.get("x-frame-options"), "DENY");
  assertEquals(headers.get("x-content-type-options"), "nosniff");
  assertMatch(headers.get("content-security-policy") ?? "", /script-src 'self'/);
  assertEquals(headers.get("strict-transport-security"), "max-age=31536000; includeSubDomains");
});

Deno.test("session token injection replaces every placeholder", () => {
  const token = "abc123";
  const rendered = injectSessionToken("token=__WS_SESSION_TOKEN__&again=__WS_SESSION_TOKEN__", token);
  assertEquals(rendered, "token=abc123&again=abc123");
});

Deno.test("session cookie header can be emitted for proxied secure requests", () => {
  const header = buildSessionCookieHeader("fp_cicis_session", "session-id", true, 600);
  assertMatch(header, /^fp_cicis_session=session-id; Path=\//);
  assertMatch(header, /Max-Age=600/);
  assertMatch(header, /SameSite=Strict/);
  assertMatch(header, /HttpOnly/);
  assertMatch(header, /Secure/);
});

Deno.test("user ids are narrowed to safe characters", () => {
  assertEquals(sanitizeUserId("alice.user-01"), "alice.user-01");
  assertEquals(sanitizeUserId("<img src=x>"), undefined);
  assertEquals(sanitizeUserId(" "), undefined);
});

Deno.test("buildWebSocketUrl percent-encodes the session token", () => {
  const url = buildWebSocketUrl({ protocol: "https:", host: "localhost:5000" }, "token with spaces");
  assertEquals(url, "wss://localhost:5000/wss?token=token%20with%20spaces");
  assertNotEquals(url.includes("token with spaces"), true);
});