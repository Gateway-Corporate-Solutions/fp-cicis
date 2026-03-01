import { Application, Router } from 'oak';
import { getHash } from 'devicer/src/libs/tlsh.js';
import { calculateConfidence } from "devicer";
import { FPDB, FingerPrint } from "./libs/db.ts";

const app = new Application();
const router = new Router();
const fpdb = new FPDB();

router.get('/', async (context) => {
  const indexBody = await Deno.readTextFile('./static/index.html');
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
  socket.onmessage = (event) => { // Trigger on socket messages
    console.log('Message received:', event.data);
    const json = JSON.parse(event.data);
    if (json.type === 'data') { // If message type == data, execute hashing procedure
      try {
        const hash = getHash(JSON.stringify(json.data)); // Generate hash
        console.log('Hash generated:', hash);
        const existingFP = fpdb.getFingerPrintByHash(hash); // Locate any fingerprints in database that match exactly
        if (existingFP) { // If an exact match exists, return early
          console.log('Exact match exists for hash:', hash)
          socket.send(JSON.stringify({ // Send match info back over socket
            type: 'fingerprint',
            data: {
              hash: hash,
              exactMatchFound: true,
              closestMatch: 100 // Assuming 100% confidence for exact match
            }
          }));
          return;
        }
        const existingFingerprints = fpdb.getAllFingerprints() as FingerPrint[]; // Get all fingerprints from database
        const closestMatch = Math.max(...existingFingerprints.map((fp) => { // Return the closest match
          try {
            return calculateConfidence(JSON.parse(fp.data), json.data) // Calculate confidence for each fingerprint
          } catch (error) {
            console.error('Error calculating confidence:', error);
            return 0; // Return 0 if confidence calculation fails
          }
        }));
        fpdb.insertFingerPrint({ // Insert current fingerprint into database for storage
          hash: hash,
          data: JSON.stringify(json.data)
        });
        socket.send(JSON.stringify({ // Send match info back over socket
          type: 'fingerprint',
          data: {
            hash: hash,
            exactMatchFound: false,
            closestMatch: closestMatch
          }
        }));
      } catch (error) { // If an error occurs, catch and return
        console.error('Error processing data:', error);
        socket.send(JSON.stringify({ // Send error back over socket
          type: 'error',
          data: (error as Error).message
        }));
      }
    }
  }
});

app.use(router.routes());
app.use(router.allowedMethods());

app.use(async (context, next) => {
  const root = "./static";
  try {
    await context.send({ root });
  } catch {
    next();
  }
});

app.listen({ port: parseInt(Deno.env.get('PORT') ?? '8000') });
console.log('Server is running on http://localhost:8000');