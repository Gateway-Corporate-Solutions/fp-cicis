const target = Deno.args[0] ?? "ws://localhost:5000/wss";

async function attempt(name: string, origin?: string) {
  try {
    const ws = new WebSocket(target, origin ? [] : undefined);
    const opened = await new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => resolve(false), 3000);
      ws.onopen = () => {
        clearTimeout(timer);
        resolve(true);
      };
      ws.onerror = () => {
        clearTimeout(timer);
        resolve(false);
      };
      ws.onclose = () => {
        clearTimeout(timer);
      };
    });
    if (opened) {
      console.log(`[VULN][HIGH] ${name}: websocket accepted without restriction`);
      ws.close();
    } else {
      console.log(`[PASS] ${name}: websocket not accepted`);
    }
  } catch (error) {
    console.log(`[PASS] ${name}: connection rejected (${(error as Error).message})`);
  }
}

await attempt("anonymous connection");
await attempt("second anonymous connection");
