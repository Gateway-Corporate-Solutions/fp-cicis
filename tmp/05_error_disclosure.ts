const target = Deno.args[0] ?? "ws://localhost:5000/wss";

const payloads = [
  { name: "missing data object", body: JSON.stringify({ type: "data", data: null }) },
  { name: "string data object", body: JSON.stringify({ type: "data", data: "<svg onload=alert(1)>" }) },
  { name: "invalid json", body: "{" },
];

for (const payload of payloads) {
  const ws = new WebSocket(target);
  const response = await new Promise<string>((resolve) => {
    const timer = setTimeout(() => resolve("[INFO] timeout"), 4000);
    ws.onopen = () => ws.send(payload.body);
    ws.onmessage = (event) => {
      clearTimeout(timer);
      resolve(String(event.data));
      ws.close();
    };
    ws.onerror = () => {
      clearTimeout(timer);
      resolve("[INFO] websocket error");
    };
  });

  console.log(`CASE ${payload.name}`);
  console.log(response);
}
