import { Application, Router } from 'oak';
import { getHash } from "devicer";
import { calculateConfidence } from "devicer";
import { FPDB, FingerPrint } from "./libs/db.ts";
import { clusterFingerprints } from "./libs/clustering.ts";

const app = new Application();
const router = new Router();
const fpdb = new FPDB();

let fingerprints: FingerPrint[] = [];
let clusters: FingerPrint[][] = [];
let uniques: FingerPrint[] = [];

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
    socket.send(JSON.stringify({ // Send initial analytics on connection
      type: 'analytics',
      data: {
        totalFingerprints: fingerprints.length,
        uniqueFingerprints: uniques.length,
        clusters: clusters.length,
        averageClusterSize: clusters.length > 0 ? Math.floor((fingerprints.length - uniques.length) / clusters.length) : 0
      }
    }))
    setInterval(() => {  // And send updated analytics every minute after
      socket.send(JSON.stringify({
      type: 'analytics',
      data: {
        totalFingerprints: fingerprints.length,
        uniqueFingerprints: uniques.length,
        clusters: clusters.length,
        averageClusterSize: clusters.length > 0 ? Math.floor((fingerprints.length - uniques.length) / clusters.length) : 0
      }
    }))
    }, 60000);
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
        console.log('Fingerprint inserted into database with hash:', hash);
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

fingerprints = fpdb.getAllFingerprints();
console.log(`Current fingerprints in database: ${fingerprints.length}`);
[clusters, uniques] = clusterFingerprints(fpdb, 0.4, 2); // Cluster fingerprints every 10 minutes with eps=0.4 and minPts=2
console.log(`Current clusters: ${clusters.length}`);
clusters.forEach((cluster, index) => { // Log cluster details
  console.log(`Cluster ${index + 1}: ${cluster.length} fingerprints`);
  console.log(`Sample fingerprint from cluster ${index + 1}:`, cluster[0]); // Log a sample fingerprint from each cluster
});
console.log(`Unique fingerprints: ${uniques.length}`); // Log number of unique fingerprints that don't belong to any cluster

setInterval(() => {
  fingerprints = fpdb.getAllFingerprints();
  console.log(`Current fingerprints in database: ${fingerprints.length}`);
  [clusters, uniques] = clusterFingerprints(fpdb, 0.4, 2); // Cluster fingerprints every 10 minutes with eps=0.4 and minPts=2
  console.log(`Current clusters: ${clusters.length}`);
  clusters.forEach((cluster, index) => { // Log cluster details
    console.log(`Cluster ${index + 1}: ${cluster.length} fingerprints`);
    console.log(`Sample fingerprint from cluster ${index + 1}:`, cluster[0]); // Log a sample fingerprint from each cluster
  });
  console.log(`Unique fingerprints: ${uniques.length}`); // Log number of unique fingerprints that don't belong to any cluster
}, 600000); // Run and log analytics every 10 minutes