import { Application, Router } from 'oak';
import { 
	getHash,
	DeviceManager,
	StoredFingerprint
} from "devicer";
import { createSqliteAdapter } from "./libs/sqlite.ts";
import { clusterFingerprints } from "./libs/clustering.ts";

const app = new Application();
const router = new Router();

const adapter = createSqliteAdapter('./fp.db');
await adapter.init(); // Initialize the SQLite adapter (creates table if not exists)
const confidenceThreshold = 75; // Set confidence threshold for device matching
const deviceManager = new DeviceManager(adapter, { matchThreshold: confidenceThreshold, candidateMinScore: 40 }); // Initialize DeviceManager with SQLite adapter

let fingerprints: StoredFingerprint[] = [];
let clusters: StoredFingerprint[][] = [];
let uniques: StoredFingerprint[] = [];

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
  socket.onmessage = async (event) => { // Trigger on socket messages
    console.log('Message received:', event.data);
    const json = JSON.parse(event.data);
    if (json.type === 'data') { // If message type == data, execute hashing procedure
      try {
        const hash = getHash(JSON.stringify(json.data)); // Generate hash
        console.log('Hash generated:', hash);

        const existingFingerprint = await adapter.findCandidates(json.data, 100, 1); // Check for existing candidates with confidence >= 100
        if (existingFingerprint.length > 0) { // If an exact match exists, return early
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

        const fingerprintCandidates = await adapter.findCandidates(json.data, 50, 50); // Get up to 50 fingerprint candidates from database
        const closestMatch = Math.max(0, ...fingerprintCandidates.map((fp) => fp.confidence)); // Return the closest match, defaulting to 0 if no candidates
        
				deviceManager.identify(json.data, { ip: context.request.ip }).then(_result => { /* Identify device and save fingerprint to database */});

        console.log('Fingerprint inserted into database with hash:', hash);
				socket.send(JSON.stringify({ // Send match info back over socket
					type: 'fingerprint',
					data: {
						hash: hash,
						exactMatchFound: false,
						closestMatch: closestMatch || 0
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

fingerprints = await adapter.getAllFingerprints();
console.log(`Current fingerprints in database: ${fingerprints.length}`);
[clusters, uniques] = await clusterFingerprints(adapter, 1 - confidenceThreshold / 100, 2); // Cluster fingerprints every 10 minutes with eps=0.4 and minPts=2
console.log(`Current clusters: ${clusters.length}`);
clusters.forEach((cluster, index) => { // Log cluster details
  console.log(`Cluster ${index + 1}: ${cluster.length} fingerprints`);
  console.log(`Sample fingerprint from cluster ${index + 1}:`, cluster[0]); // Log a sample fingerprint from each cluster
});
console.log(`Unique fingerprints: ${uniques.length}`); // Log number of unique fingerprints that don't belong to any cluster

setInterval(async () => {
  fingerprints = await adapter.getAllFingerprints();
  console.log(`Current fingerprints in database: ${fingerprints.length}`);
  [clusters, uniques] = await clusterFingerprints(adapter, 1 - confidenceThreshold / 100, 2); // Cluster fingerprints every 10 minutes with eps=0.4 and minPts=2
  console.log(`Current clusters: ${clusters.length}`);
  clusters.forEach((cluster, index) => { // Log cluster details
    console.log(`Cluster ${index + 1}: ${cluster.length} fingerprints`);
    console.log(`Sample fingerprint from cluster ${index + 1}:`, cluster[0]); // Log a sample fingerprint from each cluster
  });
  console.log(`Unique fingerprints: ${uniques.length}`); // Log number of unique fingerprints that don't belong to any cluster
}, 600000); // Run and log analytics every 10 minutes