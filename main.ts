import { Application, Router } from 'oak';
import { getHash } from 'devicer/src/libs/tlsh.js';
import { calculateConfidence } from "devicer";
import { FPDB, FingerPrint } from "./libs/db.ts";

const app = new Application();
const router = new Router();
const fpdb = new FPDB();

router.get('/', (context) => {
  const indexBody = Deno.readTextFileSync('./static/index.html');
  context.response.body = indexBody;
});

router.get('/wss', async (context) => {
  if (!context.isUpgradable) {
    context.response.status = 426; // Upgrade Required
    context.response.body = 'Upgrade Required';
    return;
  }
  const socket = await context.upgrade();
  socket.onopen = () => {
    console.log('WebSocket connection opened');
  }
  socket.onmessage = (event) => {
    console.log('Message received:', event.data);
    const json = JSON.parse(event.data);
    if (json.type === 'data') {
      const hash = getHash(json.data);
      console.log('Hash generated:', hash);
      const existingFP = fpdb.getFingerPrintByHash(hash);
      if (existingFP) {
        console.log('Exact match exists for hash:', hash)
        socket.send(JSON.stringify({
          type: 'fingerprint',
          data: {
            hash: hash,
            exactMatchFound: true,
            closestMatch: 100 // Assuming 100% confidence for exact match
          }
        }));
        return;
      }
      const existingFingerprints = fpdb.getAllFingerprints() as FingerPrint[];
      const closestMatch = Math.max(...existingFingerprints.map(fp => calculateConfidence(JSON.parse(fp.data), json.data)));
      fpdb.insertFingerPrint({
        hash: hash,
        data: JSON.stringify(json.data)
      });
      socket.send(JSON.stringify({
        type: 'fingerprint',
        data: {
          hash: hash,
          exactMatchFound: false,
          closestMatch: closestMatch
        }
      }));
    }
  }
});

router.get('/:file', async (context) => {
  const filePath = `./static/${context.params.file}`;
  try {
    const fileContent = await Deno.readTextFile(filePath);
    context.response.body = fileContent;
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) {
      context.response.status = 404;
      context.response.body = 'File not found';
    } else {
      context.response.status = 500;
      context.response.body = 'Internal server error';
    }
  }
});

app.use(router.routes());
app.use(router.allowedMethods());

app.listen({ port: 8000 });
console.log('Server is running on http://localhost:8000');