import { Application, Router } from 'oak';
import { 
	devicer, 
	ipDevicer, 
	tlsDevicer, 
	bbasDevicer, 
	peerDevicer 
} from "devicer-suite";
import { 
	createDevManagerSqliteAdapter,
	createIpManagerSqliteAdapter,
  createTlsManagerSqliteAdapter,
  createPeerManagerSqliteAdapter,
  createBbasManagerSqliteAdapter,
} from "./libs/sqlite.ts";
import { clusterFingerprints } from "./libs/clustering.ts";

const licenseKey = Deno.env.get('DEVICER_LICENSE_KEY');

const app = new Application();
const router = new Router();

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

// Initialize SQLite adapters for DeviceManager, IpManager, and TlsManager
// These adapters are specific to Deno. In a Node.js environment, you would
// use the built-in better-sqlite3 implementations.
const adapters = {
	device: createDevManagerSqliteAdapter('./data/fp.db'),
	ip: createIpManagerSqliteAdapter('./data/ip.db'),
	tls: createTlsManagerSqliteAdapter('./data/tls.db'),
  peer: createPeerManagerSqliteAdapter('./data/peer.db'),
  bbas: createBbasManagerSqliteAdapter('./data/bbas.db'),
}
for (const adapter of Object.values(adapters)) {
	await adapter.init();
}

// Set confidence threshold for device matching
const confidenceThreshold = 85;

// Initialize DeviceManager with config
const deviceManager = new devicer.DeviceManager(adapters.device, {  
	matchThreshold: confidenceThreshold,
	candidateMinScore: 40,
	logger: console
});
// Initialize IpManager with config
const ipManager = new ipDevicer.IpManager({ 
	licenseKey: licenseKey,
	maxmindPath: "./data/GeoLite2-City.mmdb",
	asnPath: "./data/GeoLite2-ASN.mmdb",
	enableReputation: true,
	storage: adapters.ip
});
// Initialize TlsManager with config
const tlsManager = new tlsDevicer.TlsManager({ 
	licenseKey: licenseKey,
	storage: adapters.tls
});
const peerManager = new peerDevicer.PeerManager({
  licenseKey: licenseKey,
  storage: adapters.peer,
});
const bbasManager = new bbasDevicer.BbasManager({
  licenseKey: licenseKey,
  storage: adapters.bbas,
  enableBehavioralAnalysis: true,
  enableCrossPlugin: true,
});

deviceManager.use(ipManager); // Register IpManager with DeviceManager to enable IP enrichment during identification
deviceManager.use(tlsManager); // Register TlsManager with DeviceManager to enable TLS enrichment during identification
deviceManager.use(peerManager); // Register PeerManager after IP/TLS so peer reputation can reuse their enrichments
deviceManager.use(bbasManager); // Register BbasManager after peer-devicer so cross-plugin bot signals are available

// Global variables to hold fingerprints, clusters, and uniques for analytics
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

        const fingerprintCandidates = await adapters.device.findCandidates(json.data, 50, 50); // Get up to 50 fingerprint candidates from database
        const exactMatchFound = fingerprintCandidates.some((fp: devicer.DeviceMatch) => fp.confidence >= 100);
        const closestMatch = Math.max(0, ...fingerprintCandidates.map((fp: devicer.DeviceMatch) => fp.confidence)); // Return the closest match, defaulting to 0 if no candidates
        const userId = requestHeaders['x-user-id'];
        
        const identifyResult = await deviceManager.identify(json.data, {
          ip: realIp,
          userId: typeof userId === 'string' ? userId : undefined,
          tlsProfile,
          headers: requestHeaders,
        }) as unknown as Record<string, unknown>; // Identify device and insert fingerprint into database
        const tlsConsistency = asRecord(identifyResult.tlsConsistency);
        const peerReputation = asRecord(identifyResult.peerReputation);
        const bbasEnrichment = asRecord(identifyResult.bbasEnrichment);
        const enrichmentInfo = asRecord(identifyResult.enrichmentInfo);
        const enrichmentDetails = asRecord(enrichmentInfo?.details);
        const ipDetails = asRecord(enrichmentDetails?.ip);
        const agentInfo = asRecord(ipDetails?.agentInfo);
        const uaClassification = asRecord(bbasEnrichment?.uaClassification);
        const peerConfidenceBoost = typeof identifyResult.peerConfidenceBoost === 'number' ? identifyResult.peerConfidenceBoost : null;
        const bbasDecision = typeof identifyResult.bbasDecision === 'string' ? identifyResult.bbasDecision : null;
        const country = typeof ipDetails?.country === 'string' ? ipDetails.country : null;

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
            closestMatch: closestMatch || 0,
            deviceId: typeof identifyResult.deviceId === 'string' ? identifyResult.deviceId : null,
            isNewDevice: identifyResult.isNewDevice === true,
            ip: {
              riskScore: typeof ipDetails?.riskScore === 'number' ? ipDetails.riskScore : null,
              isProxy: ipDetails?.isProxy === true,
              isVpn: ipDetails?.isVpn === true,
              isTor: ipDetails?.isTor === true,
              isHosting: ipDetails?.isHosting === true,
              isAiAgent: agentInfo?.isAiAgent === true,
              aiAgentProvider: typeof agentInfo?.aiAgentProvider === 'string' ? agentInfo.aiAgentProvider : null,
              country,
            },
            tls: tlsConsistency ? {
              consistencyScore: typeof tlsConsistency.consistencyScore === 'number' ? tlsConsistency.consistencyScore : null,
              ja4Match: typeof tlsConsistency.ja4Match === 'boolean' ? tlsConsistency.ja4Match : null,
              factors: asStringArray(tlsConsistency.factors),
            } : null,
            peer: peerReputation ? {
              peerCount: typeof peerReputation.peerCount === 'number' ? peerReputation.peerCount : 0,
              taintScore: typeof peerReputation.taintScore === 'number' ? peerReputation.taintScore : null,
              trustScore: typeof peerReputation.trustScore === 'number' ? peerReputation.trustScore : null,
              confidenceBoost: peerConfidenceBoost,
              factors: asStringArray(peerReputation.factors),
            } : null,
            bot: bbasEnrichment ? {
              botScore: typeof bbasEnrichment.botScore === 'number' ? bbasEnrichment.botScore : null,
              decision: bbasDecision,
              isHeadless: uaClassification?.isHeadless === true,
              isBot: uaClassification?.isBot === true,
              isCrawler: uaClassification?.isCrawler === true,
              behavioralHumanScore: typeof asRecord(bbasEnrichment.behavioralSignals)?.humanScore === 'number'
                ? asRecord(bbasEnrichment.behavioralSignals)?.humanScore
                : null,
              factors: asStringArray(bbasEnrichment.botFactors),
            } : null,
					}
				}));

				if (['IN', 'BD', 'NG', 'RO', 'RU', 'IR', 'CN', 'KP'].includes(country as string)) {
					console.warn('Device with fingerprint hash', hash, 'is associated with a high-risk country:', country);
					socket.send(JSON.stringify({ // Send blacklist alert back over socket
						type: 'blacklistAlert',
						data: {
							hash: hash,
							country: country
						}
					}));
				}

				if (bbasDecision === 'block' || bbasDecision === 'challenge') {
					console.warn('Device with fingerprint hash', hash, 'triggered BBAS decision:', bbasDecision);
					socket.send(JSON.stringify({
						type: 'botAlert',
						data: {
							hash,
							decision: bbasDecision,
							botScore: typeof bbasEnrichment?.botScore === 'number' ? bbasEnrichment.botScore : null,
							factors: asStringArray(bbasEnrichment?.botFactors),
						}
					}));
				}
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

app.listen({ port: parseInt(Deno.env.get('PORT') ?? '5000') });
console.log('Server is running on http://localhost:5000');

fingerprints = await adapters.device.getAllFingerprints();
console.log(`Current fingerprints in database: ${fingerprints.length}`);
[clusters, uniques] = await clusterFingerprints(adapters.device, 1 - confidenceThreshold / 100, 2); // Cluster fingerprints every 10 minutes with eps=0.4 and minPts=2
console.log(`Current clusters: ${clusters.length}`);
clusters.forEach((cluster, index) => { // Log cluster details
  console.log(`Cluster ${index + 1}: ${cluster.length} fingerprints`);
  console.log(`Sample fingerprint from cluster ${index + 1}:`, cluster[0]); // Log a sample fingerprint from each cluster
});
console.log(`Unique fingerprints: ${uniques.length}`); // Log number of unique fingerprints that don't belong to any cluster

setInterval(async () => {
  fingerprints = await adapters.device.getAllFingerprints();
  console.log(`Current fingerprints in database: ${fingerprints.length}`);
  [clusters, uniques] = await clusterFingerprints(adapters.device, 1 - confidenceThreshold / 100, 2); // Cluster fingerprints every 10 minutes with eps=0.4 and minPts=2
  console.log(`Current clusters: ${clusters.length}`);
  clusters.forEach((cluster, index) => { // Log cluster details
    console.log(`Cluster ${index + 1}: ${cluster.length} fingerprints`);
    console.log(`Sample fingerprint from cluster ${index + 1}:`, cluster[0]); // Log a sample fingerprint from each cluster
  });
  console.log(`Unique fingerprints: ${uniques.length}`); // Log number of unique fingerprints that don't belong to any cluster
}, 600000); // Run and log analytics every 10 minutes