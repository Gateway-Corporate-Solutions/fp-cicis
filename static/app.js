// deno-lint-ignore-file no-window no-window-prefix
export function buildWebSocketUrl(locationObject, token) {
  const scheme = locationObject.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${locationObject.host}/wss?token=${encodeURIComponent(token)}`;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function clearElement(element, fallbackText = "") {
  if (!element) {
    return;
  }

  element.replaceChildren();
  if (fallbackText) {
    element.textContent = fallbackText;
  }
}

function appendBreak(element) {
  element.append(document.createElement("br"));
}

function appendLabelValue(element, label, value) {
  if (value === null || value === undefined || value === "") {
    return;
  }

  const labelNode = document.createElement("strong");
  labelNode.textContent = `${label}: `;
  element.append(labelNode, document.createTextNode(String(value)));
  appendBreak(element);
}

function appendBoolean(element, label, value) {
  if (typeof value !== "boolean") {
    return;
  }

  appendLabelValue(element, label, value ? "Yes" : "No");
}

function appendList(element, label, values) {
  if (!Array.isArray(values) || values.length === 0) {
    return;
  }

  appendLabelValue(element, label, values.join(", "));
}

function appendSectionHeading(element, text) {
  if (element.childNodes.length > 0) {
    appendBreak(element);
  }
  const heading = document.createElement("strong");
  heading.textContent = text;
  element.append(heading);
  appendBreak(element);
}

function renderAnalytics(target, analytics) {
  if (!target) {
    return;
  }

  clearElement(target);
  appendLabelValue(target, "Total Fingerprints", analytics.totalFingerprints);
  appendLabelValue(target, "Unique Fingerprints", analytics.uniqueFingerprints);
  appendLabelValue(target, "Fingerprint Clusters", analytics.clusters);
  appendLabelValue(target, "Average Cluster Size", analytics.averageClusterSize);
}

function appendAgentDataset(target, agent) {
  appendSectionHeading(target, "Browser Dataset");
  appendLabelValue(target, "User Agent", agent?.dataset?.userAgent ?? null);
  appendLabelValue(target, "Platform", agent?.dataset?.platform ?? null);
  appendLabelValue(target, "Timezone", agent?.dataset?.timezone ?? null);
  appendLabelValue(target, "User Data", JSON.stringify(agent?.dataset ?? {}));
}

function renderFingerprint(target, payload, agent) {
  if (!target) {
    return;
  }

  clearElement(target);
  appendLabelValue(target, "Fingerprint Hash", payload.hash);
  appendLabelValue(target, "Device ID", payload.deviceId);
  appendBoolean(target, "New Device", payload.isNewDevice);

  if (payload.closestMatch === 100) {
    appendLabelValue(target, "Closest Match", `${payload.closestMatch} (Exact Match)`);
  } else if (typeof payload.closestMatch === "number" && payload.closestMatch >= 85) {
    appendLabelValue(target, "Closest Match", `${payload.closestMatch} (Close Match)`);
  } else {
    appendLabelValue(target, "Closest Match", `${payload.closestMatch ?? 0} (No Close Match)`);
  }

  if (payload.ip) {
    appendSectionHeading(target, "IP Enrichment");
    appendLabelValue(target, "Country", payload.ip.country);
    appendLabelValue(target, "Risk Score", payload.ip.riskScore);
    appendBoolean(target, "Proxy", payload.ip.isProxy);
    appendBoolean(target, "VPN", payload.ip.isVpn);
    appendBoolean(target, "Tor", payload.ip.isTor);
    appendBoolean(target, "Hosting", payload.ip.isHosting);
    appendBoolean(target, "AI Agent", payload.ip.isAiAgent);
    appendLabelValue(target, "AI Agent Provider", payload.ip.aiAgentProvider);
  }

  if (payload.tls) {
    appendSectionHeading(target, "TLS Enrichment");
    appendLabelValue(target, "Consistency Score", payload.tls.consistencyScore);
    appendBoolean(target, "JA4 Match", payload.tls.ja4Match);
    appendList(target, "TLS Factors", payload.tls.factors);
  }

  if (payload.peer) {
    appendSectionHeading(target, "Peer Reputation");
    appendLabelValue(target, "Peer Count", payload.peer.peerCount);
    appendLabelValue(target, "Taint Score", payload.peer.taintScore);
    appendLabelValue(target, "Trust Score", payload.peer.trustScore);
    appendLabelValue(target, "Confidence Boost", payload.peer.confidenceBoost);
    appendList(target, "Peer Factors", payload.peer.factors);
  }

  if (payload.bot) {
    appendSectionHeading(target, "Bot Analysis");
    appendLabelValue(target, "Decision", payload.bot.decision);
    appendLabelValue(target, "Bot Score", payload.bot.botScore);
    appendBoolean(target, "Headless", payload.bot.isHeadless);
    appendBoolean(target, "Bot UA", payload.bot.isBot);
    appendBoolean(target, "Crawler", payload.bot.isCrawler);
    appendLabelValue(target, "Behavioral Human Score", payload.bot.behavioralHumanScore);
    appendList(target, "Bot Factors", payload.bot.factors);
  }

  appendAgentDataset(target, agent);
}

function renderError(target, message, agent) {
  if (!target) {
    return;
  }

  clearElement(target);
  appendLabelValue(target, "Error", message);
  appendAgentDataset(target, agent);
}

async function collectFingerprintPayload(agent) {
  if (typeof agent.capture === "function") {
    return agent.capture({
      minBehavioralDurationMs: 1500,
      maxBehavioralWaitMs: 6000,
      pollIntervalMs: 100,
      requireInteraction: true,
    });
  }

  console.warn("FP-Snatch bundle does not expose capture(); using compatibility fallback.");
  await agent.ready;
  await sleep(1500);

  if (agent._behavioral && typeof agent._behavioral.computeBehavioralMetrics === "function") {
    agent.dataset.behavioralMetrics = agent._behavioral.computeBehavioralMetrics();
  }

  return agent.dataset;
}

function initializeClient() {
  if (typeof window === "undefined" || typeof document === "undefined") {
    return;
  }

  const tokenMeta = document.querySelector('meta[name="fp-cicis-ws-token"]');
  const fingerprintEl = document.getElementById("fingerprint");
  const analyticsEl = document.getElementById("analytics");
  const sessionToken = tokenMeta?.getAttribute("content") ?? "";

  if (!sessionToken) {
    clearElement(fingerprintEl, "Missing websocket session token.");
    return;
  }

  const Snatch = window["snatch"];
  const agent = new Snatch();
  clearElement(fingerprintEl, "Collecting device and behavioral signals...");

  const ws = new WebSocket(buildWebSocketUrl(window.location, sessionToken));

  ws.onmessage = function onMessage(event) {
    try {
      const message = JSON.parse(event.data);
      switch (message.type) {
        case "fingerprint":
          renderFingerprint(fingerprintEl, message.data, agent);
          break;
        case "error":
          renderError(fingerprintEl, message.data, agent);
          break;
        case "analytics":
          renderAnalytics(analyticsEl, message.data);
          break;
        case "blacklistAlert":
          alert(`ALERT: Your device is from a country (${message.data.country}) with a high risk of fraud. FP-Devicer has flagged your fingerprint as potentially malicious based on its IP address and other factors. Please contact support if you believe this is an error.`);
          break;
        case "botAlert":
          alert(`ALERT: Bot-Block & Anti-Scrape flagged this request as ${message.data.decision}. Bot score: ${message.data.botScore ?? "unknown"}. Factors: ${(message.data.factors || []).join(", ") || "none provided"}.`);
          break;
        default:
          console.warn("Ignoring unknown websocket message type", message.type);
      }
    } catch (error) {
      console.error("Unable to parse websocket message", error);
    }
  };

  ws.onopen = async function onOpen() {
    const payload = await collectFingerprintPayload(agent);
    if (ws.readyState !== WebSocket.OPEN) {
      return;
    }

    ws.send(JSON.stringify({
      type: "data",
      data: payload,
    }));
  };
}

if (typeof window !== "undefined") {
  window.addEventListener("load", () => {
    void initializeClient();
  });
}