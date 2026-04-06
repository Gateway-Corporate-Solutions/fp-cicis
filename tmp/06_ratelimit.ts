const target = Deno.args[0] ?? "ws://localhost:5000/wss";

async function burstMessages() {
  const ws = new WebSocket(target);
  await new Promise<void>((resolve, reject) => {
    ws.onopen = () => resolve();
    ws.onerror = () => reject(new Error("open failed"));
  });

  for (let index = 0; index < 200; index += 1) {
    ws.send(JSON.stringify({
      type: "data",
      data: {
        userAgent: `burst-${index}`,
        platform: "linux",
        timezone: "UTC",
      },
    }));
  }
  ws.close();
  console.log("[VULN][HIGH] Sent 200 messages on one websocket without client-side throttling barrier");
}

async function concurrentConnections() {
  const sockets = await Promise.all(Array.from({ length: 50 }, async (_, index) => {
    const ws = new WebSocket(target);
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`timeout ${index}`)), 4000);
      ws.onopen = () => {
        clearTimeout(timer);
        resolve();
      };
      ws.onerror = () => {
        clearTimeout(timer);
        reject(new Error(`open failed ${index}`));
      };
    });
    return ws;
  }));

  for (const ws of sockets) {
    ws.close();
  }
  console.log(`[VULN][HIGH] Opened ${sockets.length} concurrent websocket connections without rejection`);
}

async function intervalLeakProbe() {
  for (let index = 0; index < 100; index += 1) {
    const ws = new WebSocket(target);
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`timeout ${index}`)), 3000);
      ws.onopen = () => {
        clearTimeout(timer);
        resolve();
      };
      ws.onerror = () => {
        clearTimeout(timer);
        reject(new Error(`open failed ${index}`));
      };
    });
    ws.close();
  }
  console.log("[VULN][MEDIUM] Completed 100 connection cycles; code review shows analytics intervals are never cleared on close");
}

await burstMessages();
await concurrentConnections();
await intervalLeakProbe();
