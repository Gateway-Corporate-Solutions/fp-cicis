import { Application, Router } from "oak";
import {
  devicer,
  ipDevicer,
  tlsDevicer,
  bbasDevicer,
  peerDevicer,
} from "devicer-suite";
import {
  createDevManagerSqliteAdapter,
  createIpManagerSqliteAdapter,
  createTlsManagerSqliteAdapter,
  createPeerManagerSqliteAdapter,
  createBbasManagerSqliteAdapter,
} from "./libs/sqlite.ts";
import { clusterFingerprints } from "./libs/clustering.ts";
import {
  buildSessionCookieHeader,
  SESSION_COOKIE_NAME,
  RateLimiter,
  SessionStore,
  applySecurityHeaders,
  injectSessionToken,
  isExternalOriginSecure,
  isOriginAllowed,
  parseClientMessage,
  parseConfiguredOrigins,
  parseTrustedProxyIps,
  resolveExternalOrigin,
  resolveClientIp,
  sanitizeUserId,
} from "./libs/security.ts";

type AnalyticsState = {
  fingerprints: devicer.StoredFingerprint[];
  clusters: devicer.StoredFingerprint[][];
  uniques: devicer.StoredFingerprint[];
};

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function buildAnalyticsMessage(state: AnalyticsState): string {
  return JSON.stringify({
    type: "analytics",
    data: {
      totalFingerprints: state.fingerprints.length,
      uniqueFingerprints: state.uniques.length,
      clusters: state.clusters.length,
      averageClusterSize: state.clusters.length > 0
        ? Math.floor((state.fingerprints.length - state.uniques.length) / state.clusters.length)
        : 0,
    },
  });
}

function sendSocketJson(socket: WebSocket, payload: unknown): void {
  if (socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify(payload));
  }
}

async function buildApplicationState() {
  const adapters = {
    device: createDevManagerSqliteAdapter("./data/fp.db"),
    ip: createIpManagerSqliteAdapter("./data/ip.db"),
    tls: createTlsManagerSqliteAdapter("./data/tls.db"),
    peer: createPeerManagerSqliteAdapter("./data/peer.db"),
    bbas: createBbasManagerSqliteAdapter("./data/bbas.db"),
  };

  for (const adapter of Object.values(adapters)) {
    await adapter.init();
  }

  const confidenceThreshold = 85;
  const licenseKey = Deno.env.get("DEVICER_LICENSE_KEY");
  const deviceManager = new devicer.DeviceManager(adapters.device, {
    matchThreshold: confidenceThreshold,
    candidateMinScore: 40,
    logger: console,
  });
  const ipManager = new ipDevicer.IpManager({
    licenseKey,
    maxmindPath: "./data/GeoLite2-City.mmdb",
    asnPath: "./data/GeoLite2-ASN.mmdb",
    enableReputation: true,
    storage: adapters.ip,
  });
  const tlsManager = new tlsDevicer.TlsManager({
    licenseKey,
    storage: adapters.tls,
  });
  const peerManager = new peerDevicer.PeerManager({
    licenseKey,
    storage: adapters.peer,
  });
  const bbasManager = new bbasDevicer.BbasManager({
    licenseKey,
    storage: adapters.bbas,
    enableBehavioralAnalysis: true,
    enableCrossPlugin: true,
  });

  deviceManager.use(ipManager);
  deviceManager.use(tlsManager);
  deviceManager.use(peerManager);
  deviceManager.use(bbasManager);

  return {
    adapters,
    confidenceThreshold,
    deviceManager,
  };
}

export async function createApp() {
  const app = new Application();
  const router = new Router();
  const root = "./static";
  const templatePath = `${root}/index.html`;
  const port = parseInt(Deno.env.get("PORT") ?? "8000", 10);
  const trustedProxyIps = parseTrustedProxyIps(Deno.env.get("FP_CICIS_TRUSTED_PROXIES"));
  const configuredOrigins = parseConfiguredOrigins(Deno.env.get("FP_CICIS_ALLOWED_ORIGINS"));
  const configuredPublicOrigin = Deno.env.get("FP_CICIS_PUBLIC_ORIGIN");
  const sessionStore = new SessionStore();
  const rateLimiter = new RateLimiter();
  const state = await buildApplicationState();
  const analytics: AnalyticsState = {
    fingerprints: [],
    clusters: [],
    uniques: [],
  };

  const refreshAnalytics = async () => {
    analytics.fingerprints = await state.adapters.device.getAllFingerprints();
    [analytics.clusters, analytics.uniques] = await clusterFingerprints(
      state.adapters.device,
      1 - state.confidenceThreshold / 100,
      2,
    );

    console.log(`Current fingerprints in database: ${analytics.fingerprints.length}`);
    console.log(`Current clusters: ${analytics.clusters.length}`);
    analytics.clusters.forEach((cluster, index) => {
      console.log(`Cluster ${index + 1}: ${cluster.length} fingerprints`);
      console.log(`Sample fingerprint from cluster ${index + 1}:`, cluster[0]);
    });
    console.log(`Unique fingerprints: ${analytics.uniques.length}`);
  };

  await refreshAnalytics();
  const analyticsRefreshTimer = setInterval(() => {
    void refreshAnalytics();
  }, 600_000);

  app.use(async (context, next) => {
    const externalOrigin = resolveExternalOrigin(context.request.url, context.request.headers, configuredPublicOrigin);
    try {
      await next();
    } finally {
      applySecurityHeaders(context.response.headers, isExternalOriginSecure(externalOrigin));
    }
  });

  router.get("/", async (context) => {
    const template = await Deno.readTextFile(templatePath);
    const externalOrigin = resolveExternalOrigin(context.request.url, context.request.headers, configuredPublicOrigin);
    const secureCookie = isExternalOriginSecure(externalOrigin);
    const session = sessionStore.createSession();
    context.response.headers.append(
      "set-cookie",
      buildSessionCookieHeader(SESSION_COOKIE_NAME, session.id, secureCookie, 600),
    );
    context.response.body = injectSessionToken(template, session.token);
  });

  router.get("/wss", async (context) => {
    if (!context.isUpgradable) {
      context.response.status = 426;
      context.response.body = "Upgrade Required";
      return;
    }

    const requestOrigin = resolveExternalOrigin(context.request.url, context.request.headers, configuredPublicOrigin);
    const originHeader = context.request.headers.get("origin");
    if (!isOriginAllowed(originHeader, requestOrigin, configuredOrigins)) {
      context.response.status = 403;
      context.response.body = "Origin not allowed.";
      return;
    }

    const sessionId = await context.cookies.get(SESSION_COOKIE_NAME);
    const websocketToken = context.request.url.searchParams.get("token");
    if (!sessionStore.validateSession(sessionId, websocketToken)) {
      context.response.status = 403;
      context.response.body = "Invalid websocket session.";
      return;
    }

    const requestHeaders = Object.fromEntries(context.request.headers.entries());
    const realIp = resolveClientIp(
      context.request.ip,
      context.request.headers.get("X-Real-IP"),
      trustedProxyIps,
    );

    if (!rateLimiter.tryOpenConnection(realIp)) {
      context.response.status = 429;
      context.response.body = "Too many websocket connections.";
      return;
    }

    const tlsHeaderLog = {
      "x-ja4": requestHeaders["x-ja4"] ?? null,
      "x-tls-ja4": requestHeaders["x-tls-ja4"] ?? null,
      "cf-ja4": requestHeaders["cf-ja4"] ?? null,
      "x-ja3": requestHeaders["x-ja3"] ?? null,
      "cf-ja3-fingerprint": requestHeaders["cf-ja3-fingerprint"] ?? null,
      "x-tls-ciphers": requestHeaders["x-tls-ciphers"] ?? null,
      "x-tls-extensions": requestHeaders["x-tls-extensions"] ?? null,
      "x-http2-settings": requestHeaders["x-http2-settings"] ?? null,
    };
    const tlsProfile = tlsDevicer.buildTlsProfile(requestHeaders);

    if (Object.values(tlsHeaderLog).some((value) => value !== null)) {
      console.log("TLS proxy headers received for websocket upgrade:", tlsHeaderLog);
      console.log("Derived TLS profile for websocket upgrade:", tlsProfile);
    } else {
      console.log("No TLS proxy headers received for websocket upgrade");
    }

    const socket = await context.upgrade();
    let analyticsSocketTimer: number | undefined;

    const cleanupSocket = () => {
      if (analyticsSocketTimer !== undefined) {
        clearInterval(analyticsSocketTimer);
        analyticsSocketTimer = undefined;
      }
      rateLimiter.releaseConnection(realIp);
    };

    socket.onopen = () => {
      console.log("WebSocket connection opened");
      if (socket.readyState === WebSocket.OPEN) {
        socket.send(buildAnalyticsMessage(analytics));
      }
      analyticsSocketTimer = setInterval(() => {
        if (socket.readyState !== WebSocket.OPEN) {
          cleanupSocket();
          return;
        }
        socket.send(buildAnalyticsMessage(analytics));
      }, 60_000);
    };

    socket.onclose = cleanupSocket;
    socket.onerror = (event) => {
      console.error("WebSocket error:", event);
      cleanupSocket();
    };

    socket.onmessage = async (event) => {
      if (!rateLimiter.allowMessage(realIp)) {
        sendSocketJson(socket, {
          type: "error",
          data: "Too many websocket messages. Please retry later.",
        });
        socket.close(1008, "Rate limit exceeded");
        cleanupSocket();
        return;
      }

      const parsedMessage = parseClientMessage(event.data);
      if (!parsedMessage.ok) {
        sendSocketJson(socket, {
          type: "error",
          data: parsedMessage.clientMessage,
        });
        socket.close(parsedMessage.closeCode, parsedMessage.clientMessage);
        cleanupSocket();
        return;
      }

      try {
        const fingerprintData = parsedMessage.value.data;
        const hash = devicer.getHash(JSON.stringify(fingerprintData));
        const fingerprintCandidates = await state.adapters.device.findCandidates(fingerprintData, 50, 50);
        const exactMatchFound = fingerprintCandidates.some((fp: devicer.DeviceMatch) => fp.confidence >= 100);
        const closestMatch = Math.max(0, ...fingerprintCandidates.map((fp: devicer.DeviceMatch) => fp.confidence));
        const userId = sanitizeUserId(requestHeaders["x-user-id"]);

        const identifyResult = await state.deviceManager.identify(fingerprintData, {
          ip: realIp,
          userId,
          tlsProfile,
          headers: requestHeaders,
        }) as unknown as Record<string, unknown>;
        const tlsConsistency = asRecord(identifyResult.tlsConsistency);
        const peerReputation = asRecord(identifyResult.peerReputation);
        const bbasEnrichment = asRecord(identifyResult.bbasEnrichment);
        const enrichmentInfo = asRecord(identifyResult.enrichmentInfo);
        const enrichmentDetails = asRecord(enrichmentInfo?.details);
        const ipDetails = asRecord(enrichmentDetails?.ip);
        const agentInfo = asRecord(ipDetails?.agentInfo);
        const uaClassification = asRecord(bbasEnrichment?.uaClassification);
        const peerConfidenceBoost = typeof identifyResult.peerConfidenceBoost === "number" ? identifyResult.peerConfidenceBoost : null;
        const bbasDecision = typeof identifyResult.bbasDecision === "string" ? identifyResult.bbasDecision : null;
        const country = typeof ipDetails?.country === "string" ? ipDetails.country : null;

        sendSocketJson(socket, {
          type: "fingerprint",
          data: {
            hash,
            exactMatchFound,
            closestMatch: closestMatch || 0,
            deviceId: typeof identifyResult.deviceId === "string" ? identifyResult.deviceId : null,
            isNewDevice: identifyResult.isNewDevice === true,
            ip: {
              riskScore: typeof ipDetails?.riskScore === "number" ? ipDetails.riskScore : null,
              isProxy: ipDetails?.isProxy === true,
              isVpn: ipDetails?.isVpn === true,
              isTor: ipDetails?.isTor === true,
              isHosting: ipDetails?.isHosting === true,
              isAiAgent: agentInfo?.isAiAgent === true,
              aiAgentProvider: typeof agentInfo?.aiAgentProvider === "string" ? agentInfo.aiAgentProvider : null,
              country,
            },
            tls: tlsConsistency ? {
              consistencyScore: typeof tlsConsistency.consistencyScore === "number" ? tlsConsistency.consistencyScore : null,
              ja4Match: typeof tlsConsistency.ja4Match === "boolean" ? tlsConsistency.ja4Match : null,
              factors: asStringArray(tlsConsistency.factors),
            } : null,
            peer: peerReputation ? {
              peerCount: typeof peerReputation.peerCount === "number" ? peerReputation.peerCount : 0,
              taintScore: typeof peerReputation.taintScore === "number" ? peerReputation.taintScore : null,
              trustScore: typeof peerReputation.trustScore === "number" ? peerReputation.trustScore : null,
              confidenceBoost: peerConfidenceBoost,
              factors: asStringArray(peerReputation.factors),
            } : null,
            bot: bbasEnrichment ? {
              botScore: typeof bbasEnrichment.botScore === "number" ? bbasEnrichment.botScore : null,
              decision: bbasDecision,
              isHeadless: uaClassification?.isHeadless === true,
              isBot: uaClassification?.isBot === true,
              isCrawler: uaClassification?.isCrawler === true,
              behavioralHumanScore: typeof asRecord(bbasEnrichment.behavioralSignals)?.humanScore === "number"
                ? asRecord(bbasEnrichment.behavioralSignals)?.humanScore
                : null,
              factors: asStringArray(bbasEnrichment.botFactors),
            } : null,
          },
        });

        if (["IN", "BD", "NG", "RO", "RU", "IR", "CN", "KP"].includes(country as string)) {
          sendSocketJson(socket, {
            type: "blacklistAlert",
            data: {
              hash,
              country,
            },
          });
        }

        if (bbasDecision === "block" || bbasDecision === "challenge") {
          sendSocketJson(socket, {
            type: "botAlert",
            data: {
              hash,
              decision: bbasDecision,
              botScore: typeof bbasEnrichment?.botScore === "number" ? bbasEnrichment.botScore : null,
              factors: asStringArray(bbasEnrichment?.botFactors),
            },
          });
        }
      } catch (error) {
        console.error("Error processing websocket payload:", error);
        sendSocketJson(socket, {
          type: "error",
          data: "Unable to process fingerprint payload.",
        });
      }
    };
  });

  app.use(router.routes());
  app.use(router.allowedMethods());

  app.use(async (context, next) => {
    try {
      await context.send({ root });
    } catch {
      await next();
    }
  });

  return {
    app,
    port,
    dispose() {
      clearInterval(analyticsRefreshTimer);
    },
  };
}

if (import.meta.main) {
  const { app, port } = await createApp();
  console.log(`Server is running on http://localhost:${port}`);
  await app.listen({ port });
}