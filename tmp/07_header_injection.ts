const target = Deno.args[0] ?? "ws://localhost:5000/wss";

const headersList: HeadersInit[] = [
  { "x-user-id": "' OR 1=1 --" },
  { "x-user-id": "<img src=x onerror=alert(1)>" },
  { "x-user-id": "A".repeat(10 * 1024) },
  { "x-real-ip": "127.0.0.1\r\nX-Injected: yes" },
  { "x-real-ip": "169.254.169.254" },
  { "x-ja4": "Z".repeat(4096), "x-ja3": "Y".repeat(4096) },
];

for (const headers of headersList) {
  try {
    const ws = new WebSocket(target, [], { headers });
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("timeout")), 4000);
      ws.onopen = () => {
        clearTimeout(timer);
        resolve();
      };
      ws.onerror = () => {
        clearTimeout(timer);
        reject(new Error("open failed"));
      };
    });
    ws.send(JSON.stringify({ type: "data", data: { userAgent: "header-probe" } }));
    console.log(`[VULN][MEDIUM] websocket accepted headers ${JSON.stringify(headers)}`);
    ws.close();
  } catch (error) {
    console.log(`[PASS] rejected headers ${JSON.stringify(headers)} (${(error as Error).message})`);
  }
}
