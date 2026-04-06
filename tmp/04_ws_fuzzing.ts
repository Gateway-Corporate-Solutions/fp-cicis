const target = Deno.args[0] ?? "ws://localhost:5000/wss";

type Case = { name: string; payload: string };

const huge = "A".repeat(1024 * 1024);
const deepObject = Array.from({ length: 200 }).reduceRight<Record<string, unknown>>(
  (accumulator, _, index) => ({ [`level${index}`]: accumulator }),
  { leaf: "value" },
);

const cases: Case[] = [
  { name: "malformed json", payload: "{" },
  { name: "null data", payload: JSON.stringify({ type: "data", data: null }) },
  { name: "numeric data", payload: JSON.stringify({ type: "data", data: 42 }) },
  { name: "array data", payload: JSON.stringify({ type: "data", data: [1, 2, 3] }) },
  { name: "proto pollution probe", payload: JSON.stringify({ type: "data", data: { "__proto__": { polluted: true }, constructor: { prototype: { poisoned: true } } } }) },
  { name: "deep nesting", payload: JSON.stringify({ type: "data", data: deepObject }) },
  { name: "huge string", payload: JSON.stringify({ type: "data", data: { canvas: huge } }) },
  { name: "xss payload", payload: JSON.stringify({ type: "data", data: { userAgent: '<img src=x onerror=alert(1)>' } }) },
  { name: "null byte", payload: JSON.stringify({ type: "data", data: { platform: 'abc\u0000def' } }) },
];

for (const testCase of cases) {
  const ws = new WebSocket(target);
  const result = await new Promise<string>((resolve) => {
    const timer = setTimeout(() => {
      try {
        ws.close();
      } catch {
      }
      resolve("[INFO] timed out without server response");
    }, 4000);

    ws.onopen = () => {
      ws.send(testCase.payload);
    };
    ws.onmessage = (event) => {
      clearTimeout(timer);
      resolve(String(event.data));
      ws.close();
    };
    ws.onerror = () => {
      clearTimeout(timer);
      resolve("[INFO] websocket error");
    };
    ws.onclose = () => {
      clearTimeout(timer);
    };
  });

  console.log(`CASE ${testCase.name}`);
  console.log(result);
}
