import { Application, Router } from 'oak';
import { devicer, ipDevicer, tlsDevicer } from "devicer-suite";
import { createSqliteAdapter } from "./libs/sqlite.ts";
import { clusterFingerprints } from "./libs/clustering.ts";

const licenseKey = Deno.env.get('DEVICER_LICENSE_KEY');

const app = new Application();
const router = new Router();

const adapter = createSqliteAdapter('./fp.db');
await adapter.init(); // Initialize the SQLite adapter (creates table if not exists)
const confidenceThreshold = 80; // Set confidence threshold for device matching

const deviceManager = new devicer.DeviceManager(adapter, {  // Initialize DeviceManager with SQLite adapter
	matchThreshold: confidenceThreshold,
	candidateMinScore: 40,
	logger: console
});
const ipManager = new ipDevicer.IpManager({ // Initialize IpManager with config
	licenseKey: licenseKey,
	maxmindPath: "./data/GeoLite2-City.mmdb",
	asnPath: "./data/GeoLite2-ASN.mmdb",
	enableReputation: true,
});
const tlsManager = new tlsDevicer.TlsManager({ // Initialize TlsManager with config
	licenseKey: licenseKey,
});

ipManager.registerWith(deviceManager); // Register IpManager with DeviceManager to enable IP enrichment during identification
tlsManager.registerWith(deviceManager); // Register TlsManager with DeviceManager to enable TLS enrichment during identification

let fingerprints: devicer.StoredFingerprint[] = [];
let clusters: devicer.StoredFingerprint[][] = [];
let uniques: devicer.StoredFingerprint[] = [];

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
  const requestHeaders = Object.fromEntries(context.request.headers.entries());
  const tlsHeaderLog = {
    'x-ja4': requestHeaders['x-ja4'] ?? null,
    'x-tls-ja4': requestHeaders['x-tls-ja4'] ?? null,
    'cf-ja4': requestHeaders['cf-ja4'] ?? null,
    'x-ja3': requestHeaders['x-ja3'] ?? null,
    'cf-ja3-fingerprint': requestHeaders['cf-ja3-fingerprint'] ?? null,
    'x-tls-ciphers': requestHeaders['x-tls-ciphers'] ?? null,
    'x-tls-extensions': requestHeaders['x-tls-extensions'] ?? null,
    'x-http2-settings': requestHeaders['x-http2-settings'] ?? null,
  };
  const tlsProfile = tlsDevicer.buildTlsProfile(requestHeaders);
  const realIp = context.request.headers.get('X-Real-IP') ?? context.request.ip;

  if (Object.values(tlsHeaderLog).some((value) => value !== null)) {
    console.log('TLS proxy headers received for websocket upgrade:', tlsHeaderLog);
    console.log('Derived TLS profile for websocket upgrade:', tlsProfile);
  } else {
    console.log('No TLS proxy headers received for websocket upgrade');
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
        const hash = devicer.getHash(JSON.stringify(json.data)); // Generate hash
        console.log('Hash generated:', hash);

        const fingerprintCandidates = await adapter.findCandidates(json.data, 65, 50); // Get up to 50 fingerprint candidates from database
        const exactMatchFound = fingerprintCandidates.some((fp: devicer.StoredFingerprint) => fp.confidence >= 100);
        const closestMatch = Math.max(0, ...fingerprintCandidates.map((fp: devicer.StoredFingerprint) => fp.confidence)); // Return the closest match, defaulting to 0 if no candidates
        
        const identifyResult = await deviceManager.identify(json.data, { ip: realIp, tlsProfile, headers: requestHeaders }) as unknown as Record<string, unknown>; // Identify device and insert fingerprint into database
        const tlsConsistency = identifyResult.tlsConsistency as Record<string, unknown> | undefined;

        if (tlsConsistency) {
          if (tlsConsistency.ja4Match === null) {
            if (tlsConsistency.isNewDevice === true) {
              console.info('This is the first stored TLS snapshot for the resolved device');
            } else if (!tlsProfile.ja4) {
              console.info('No JA4 value was present in the incoming TLS profile');
            } else {
              console.info('JA4 was not available on one side of the comparison');
            }
          }
        } else {
          console.info('No tlsConsistency was attached to the identify result');
        }

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