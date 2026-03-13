import { Application, Router } from 'oak';
import { 
	getHash,
	DeviceManager,
	StoredFingerprint
} from "devicer";
import { IpManager } from "ip-devicer";
import { TlsManager } from "tls-devicer";
import { createSqliteAdapter } from "./libs/sqlite.ts";
import { clusterFingerprints } from "./libs/clustering.ts";

const licenseKey = Deno.env.get('DEVICER_LICENSE_KEY');

const app = new Application();
const router = new Router();

const adapter = createSqliteAdapter('./fp.db');
await adapter.init(); // Initialize the SQLite adapter (creates table if not exists)
const confidenceThreshold = 80; // Set confidence threshold for device matching

const deviceManager = new DeviceManager(adapter, {  // Initialize DeviceManager with SQLite adapter
	matchThreshold: confidenceThreshold,
	candidateMinScore: 40,
	logger: console
});
const ipManager = new IpManager({
	licenseKey: licenseKey,
	maxmindPath: "./data/GeoLite2-City.mmdb",
	asnPath: "./data/GeoLite2-ASN.mmdb",
	enableReputation: true,
});
const tlsManager = new TlsManager({
	licenseKey: licenseKey,
});

ipManager.registerWith(deviceManager);
tlsManager.registerWith(deviceManager);

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
  const realIp = context.request.headers.get('X-Real-IP') ?? context.request.ip;
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

        const fingerprintCandidates = await adapter.findCandidates(json.data, 50, 50); // Get up to 50 fingerprint candidates from database
        const exactMatchFound = fingerprintCandidates.some((fp) => fp.confidence >= 100);
        const closestMatch = Math.max(0, ...fingerprintCandidates.map((fp) => fp.confidence)); // Return the closest match, defaulting to 0 if no candidates
        
				await deviceManager.identify(json.data, { ip: realIp }); // Identify device and insert fingerprint into database

				if (exactMatchFound) {
					console.log('Exact match found for fingerprint with hash:', hash);
				} else if (closestMatch >= confidenceThreshold) {
					console.log(`Close match found for fingerprint with hash: ${hash}, confidence: ${closestMatch}`);
				} else {
					console.log('No close match found for fingerprint with hash:', hash);
				}

        console.log('Fingerprint inserted into database with hash:', hash);
				socket.send(JSON.stringify({ // Send match info back over socket
					type: 'fingerprint',
					data: {
						hash: hash,
						exactMatchFound,
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