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

function getFingerprintCardBody(cardId) {
  return document.querySelector(`#${cardId} .fp-card-body`);
}

function setCardVisibility(cardId, isVisible) {
  const card = document.getElementById(cardId);
  if (!card) {
    return;
  }

  card.style.display = isVisible ? "block" : "none";
}

function appendCardEntry(element, label, value) {
  if (!element || value === null || value === undefined || value === "") {
    return;
  }

  const row = document.createElement("div");
  row.className = "fp-entry";

  const labelNode = document.createElement("span");
  labelNode.className = "fp-label";
  labelNode.textContent = label;

  const valueNode = document.createElement("span");
  valueNode.className = "fp-value";
  valueNode.textContent = String(value);

  row.append(labelNode, valueNode);
  element.append(row);
}

function appendCardBoolean(element, label, value) {
  if (typeof value !== "boolean") {
    return;
  }

  appendCardEntry(element, label, value ? "Yes" : "No");
}

function appendCardList(element, label, values) {
  if (!Array.isArray(values) || values.length === 0) {
    return;
  }

  appendCardEntry(element, label, values.join(", "));
}

function appendBrowserPanel(element, label, value) {
  if (!element || value === null || value === undefined || value === "") {
    return;
  }

  const panel = document.createElement("section");
  panel.className = "fp-browser-panel";

  const labelNode = document.createElement("span");
  labelNode.className = "fp-browser-panel-label";
  labelNode.textContent = label;

  const valueNode = document.createElement("pre");
  valueNode.className = "fp-browser-json";
  valueNode.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);

  panel.append(labelNode, valueNode);
  element.append(panel);
}

function clearFingerprintCards() {
  const cardIds = [
    "fp-card-core",
    "fp-card-ip",
    "fp-card-tls",
    "fp-card-peer",
    "fp-card-bot",
    "fp-card-browser",
  ];

  for (const cardId of cardIds) {
    clearElement(getFingerprintCardBody(cardId));
    setCardVisibility(cardId, true);
  }
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

function appendAnalyticsEntry(element, label, value) {
  if (!element || value === null || value === undefined || value === "") {
    return;
  }

  const entry = document.createElement("div");
  entry.className = "analytics-entry";

  const labelNode = document.createElement("span");
  labelNode.className = "analytics-label";
  labelNode.textContent = label;

  const valueNode = document.createElement("span");
  valueNode.className = "analytics-value";
  valueNode.textContent = String(value);

  entry.append(labelNode, valueNode);
  element.append(entry);
}

function renderAnalytics(target, analytics) {
  if (!target) {
    return;
  }

  clearElement(target);
  appendAnalyticsEntry(target, "Total Fingerprints", analytics.totalFingerprints);
  appendAnalyticsEntry(target, "Unique Fingerprints", analytics.uniqueFingerprints);
  appendAnalyticsEntry(target, "Fingerprint Clusters", analytics.clusters);
  appendAnalyticsEntry(target, "Average Cluster Size", analytics.averageClusterSize);
}

function renderBrowserCard(agent) {
  const browserCard = getFingerprintCardBody("fp-card-browser");
  if (!browserCard) {
    return;
  }

  clearElement(browserCard);

  const metadata = document.createElement("div");
  metadata.className = "fp-browser-meta";
  browserCard.append(metadata);

  appendCardEntry(metadata, "User Agent", agent?.dataset?.userAgent ?? null);
  appendCardEntry(metadata, "Platform", agent?.dataset?.platform ?? null);
  appendCardEntry(metadata, "Timezone", agent?.dataset?.timezone ?? null);
  appendBrowserPanel(browserCard, "Full Dataset", agent?.dataset ?? {});
}

function renderFingerprint(target, payload, agent) {
  if (!target) {
    return;
  }

  clearElement(target);
  clearFingerprintCards();

  const coreCard = getFingerprintCardBody("fp-card-core");
  const ipCard = getFingerprintCardBody("fp-card-ip");
  const tlsCard = getFingerprintCardBody("fp-card-tls");
  const peerCard = getFingerprintCardBody("fp-card-peer");
  const botCard = getFingerprintCardBody("fp-card-bot");

  appendCardEntry(coreCard, "Fingerprint Hash", payload.hash);
  appendCardEntry(coreCard, "Device ID", payload.deviceId);
  appendCardBoolean(coreCard, "New Device", payload.isNewDevice);

  if (payload.closestMatch === 100) {
    appendCardEntry(coreCard, "Closest Match", `${payload.closestMatch} (Exact Match)`);
  } else if (typeof payload.closestMatch === "number" && payload.closestMatch >= 85) {
    appendCardEntry(coreCard, "Closest Match", `${payload.closestMatch} (Close Match)`);
  } else {
    appendCardEntry(coreCard, "Closest Match", `${payload.closestMatch ?? 0} (No Close Match)`);
  }

  if (payload.ip) {
    appendCardEntry(ipCard, "Country", payload.ip.country);
    appendCardEntry(ipCard, "Risk Score", payload.ip.riskScore);
    appendCardBoolean(ipCard, "Proxy", payload.ip.isProxy);
    appendCardBoolean(ipCard, "VPN", payload.ip.isVpn);
    appendCardBoolean(ipCard, "Tor", payload.ip.isTor);
    appendCardBoolean(ipCard, "Hosting", payload.ip.isHosting);
    appendCardBoolean(ipCard, "AI Agent", payload.ip.isAiAgent);
    appendCardEntry(ipCard, "AI Agent Provider", payload.ip.aiAgentProvider);
  } else {
    setCardVisibility("fp-card-ip", false);
  }

  if (payload.tls) {
    appendCardEntry(tlsCard, "Consistency Score", payload.tls.consistencyScore);
    appendCardBoolean(tlsCard, "JA4 Match", payload.tls.ja4Match);
    appendCardList(tlsCard, "TLS Factors", payload.tls.factors);
  } else {
    setCardVisibility("fp-card-tls", false);
  }

  if (payload.peer) {
    appendCardEntry(peerCard, "Peer Count", payload.peer.peerCount);
    appendCardEntry(peerCard, "Taint Score", payload.peer.taintScore);
    appendCardEntry(peerCard, "Trust Score", payload.peer.trustScore);
    appendCardEntry(peerCard, "Confidence Boost", payload.peer.confidenceBoost);
    appendCardList(peerCard, "Peer Factors", payload.peer.factors);
  } else {
    setCardVisibility("fp-card-peer", false);
  }

  if (payload.bot) {
    appendCardEntry(botCard, "Decision", payload.bot.decision);
    appendCardEntry(botCard, "Bot Score", payload.bot.botScore);
    appendCardBoolean(botCard, "Headless", payload.bot.isHeadless);
    appendCardBoolean(botCard, "Bot UA", payload.bot.isBot);
    appendCardBoolean(botCard, "Crawler", payload.bot.isCrawler);
    appendCardEntry(botCard, "Behavioral Human Score", payload.bot.behavioralHumanScore);
    appendCardList(botCard, "Bot Factors", payload.bot.factors);
  } else {
    setCardVisibility("fp-card-bot", false);
  }

  renderBrowserCard(agent);
}

function renderError(target, message, agent) {
  if (!target) {
    return;
  }

  clearElement(target);
  appendLabelValue(target, "Error", message);
  clearFingerprintCards();
  setCardVisibility("fp-card-core", false);
  setCardVisibility("fp-card-ip", false);
  setCardVisibility("fp-card-tls", false);
  setCardVisibility("fp-card-peer", false);
  setCardVisibility("fp-card-bot", false);
  renderBrowserCard(agent);
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
  const fingerprintEl = document.getElementById("fp-status");
  const analyticsStatusEl = document.getElementById("analytics-status");
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
          clearElement(analyticsStatusEl);
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