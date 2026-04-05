import { Database } from "sqlite";
import { randomUUID } from "node:crypto";
import { bbasDevicer, devicer, ipDevicer, peerDevicer, tlsDevicer } from "devicer-suite"; 

// These adapters are specific to Deno. In a Node.js environment, you would
// use the built-in better-sqlite3 implementations.

// --- DeviceManager storage --------------------------------------------------------------

export function createDevManagerSqliteAdapter(dbPath: string): devicer.StorageAdapter {
	let db: Database;

	return {
		// deno-lint-ignore require-await
		async init() {
			if (db) {
				return;
			}
			db = new Database(dbPath);
			db.prepare(`
				CREATE TABLE IF NOT EXISTS fingerprints (
					id TEXT PRIMARY KEY,
					deviceId TEXT NOT NULL,
					data TEXT NOT NULL,
					timestamp TEXT NOT NULL
				)
			`).run();
		},
		async save(snapshot) {
			const id = randomUUID();
			await db.prepare(
				`INSERT INTO fingerprints (id, deviceId, data, timestamp) VALUES (?, ?, ?, ?)`
			).run(
				id,
				snapshot.deviceId,
				JSON.stringify(snapshot.fingerprint),
				snapshot.timestamp instanceof Date ? snapshot.timestamp.toISOString() : snapshot.timestamp
			);
			return id;
		},
		async getHistory(deviceId: string, limit = 50) {
			const rows = await db.prepare(
				`SELECT * FROM fingerprints WHERE deviceId = ? ORDER BY timestamp DESC LIMIT ?`
			).all(deviceId, limit);
			return rows.map(row => ({
				id: row.id,
				deviceId: row.deviceId,
				fingerprint: JSON.parse(row.data),
				timestamp: new Date(row.timestamp),
			}));
		},
		async findCandidates(query, minConfidence: number, limit = 20) {
			const rows = await db.prepare(
				`SELECT * FROM fingerprints WHERE 
					JSON_EXTRACT(data, '$.deviceMemory') = ? OR 
					JSON_EXTRACT(data, '$.hardwareConcurrency') = ? OR 
					JSON_EXTRACT(data, '$.platform') = ?
				ORDER BY timestamp DESC`
			).all(query.deviceMemory, query.hardwareConcurrency, query.platform);

			const prelim = rows.filter(row => {
				const fp = JSON.parse(row.data);
				return (query.canvas && fp?.canvas === query.canvas) ||
					(query.webgl && fp?.webgl === query.webgl);
			});

			// Keep the broader SQL-filtered pool when stronger biometric signals
			// are unavailable or do not match yet.
			const pool = prelim.length > 0 ? prelim : rows;

			const candidates: Array<devicer.DeviceMatch & { confidence: number }> = [];
			for (const row of pool) {
				const confidence = devicer.calculateConfidence(query, JSON.parse(row.data));
				if (confidence >= minConfidence) {
					candidates.push({
						deviceId: row.deviceId,
						confidence,
						lastSeen: new Date(row.timestamp),
					});
				}
			}
			return candidates.sort((a, b) => b.confidence - a.confidence).slice(0, limit);
		},
		linkToUser(_deviceId: string, _userId: string) {
			// This adapter stores fingerprint snapshots only; user-device links are omitted.
			return Promise.resolve();
		},
		// deno-lint-ignore require-await
		async deleteOldSnapshots(maxAgeDays: number) {
			const cutoff = new Date(Date.now() - maxAgeDays * 24 * 60 * 60 * 1000).toISOString();
			const result = db.prepare(`DELETE FROM fingerprints WHERE timestamp < ?`).run(cutoff);
			return result; // number of rows deleted
		},
		async getAllFingerprints() {
			const rows = await db.prepare(`SELECT * FROM fingerprints`).all();
			return rows.map(row => ({
				id: row.id,
				deviceId: row.deviceId,
				fingerprint: JSON.parse(row.data),
				timestamp: new Date(row.timestamp),
			}));
		}
	};
}

// ── TLS snapshots ───────────────────────────────────────────

export function createTlsManagerSqliteAdapter(dbPath: string): tlsDevicer.AsyncTlsStorage {
	let db: Database;
	
	return {
		// deno-lint-ignore require-await
		async init() {
			if (db) {
				return;
			}
			db = new Database(dbPath);
			db.prepare(`
				CREATE TABLE IF NOT EXISTS tls_snapshots (
					id TEXT PRIMARY KEY,
					deviceId TEXT NOT NULL,
					timestamp TEXT NOT NULL,
					profile TEXT NOT NULL
				)
			`).run();
		},

		async save(partial) {
			const snapshot = { ...partial, id: randomUUID() };
			await db.prepare(
				`INSERT INTO tls_snapshots (id, deviceId, timestamp, profile) VALUES (?, ?, ?, ?)`
			).run(
				snapshot.id,
				snapshot.deviceId,
				snapshot.timestamp.toISOString(),
				JSON.stringify(snapshot.profile)
			);
			return snapshot;
		},

		// deno-lint-ignore require-await
		async getHistory(deviceId, limit) {
			const rows = limit !== undefined
				? db.prepare(`SELECT * FROM tls_snapshots WHERE deviceId = ? ORDER BY timestamp DESC LIMIT ?`).all(deviceId, limit)
				: db.prepare(`SELECT * FROM tls_snapshots WHERE deviceId = ? ORDER BY timestamp DESC`).all(deviceId);
			return rows.map(row => ({
				id: row.id,
				deviceId: row.deviceId,
				timestamp: new Date(row.timestamp),
				profile: JSON.parse(row.profile),
			}));
		},

		async getLatest(deviceId) {
			const row = await db.prepare(
				`SELECT * FROM tls_snapshots WHERE deviceId = ? ORDER BY timestamp DESC LIMIT 1`
			).get(deviceId);
			return row ? {
				id: row.id,
				deviceId: row.deviceId,
				timestamp: new Date(row.timestamp),
				profile: JSON.parse(row.profile),
			} : null;
		},

		async clear(deviceId) {
			if (deviceId !== undefined) {
				await db.prepare(`DELETE FROM tls_snapshots WHERE deviceId = ?`).run(deviceId);
			} else {
				await db.prepare(`DELETE FROM tls_snapshots`).run();
			}
		},

		async size() {
			const row = await db.prepare(`SELECT COUNT(DISTINCT deviceId) as count FROM tls_snapshots`).get();
			return row ? row.count : 0;
		}
	};
}

// --- Peer graph snapshots ----------------------------------------------------------------------

export function createPeerManagerSqliteAdapter(
	dbPath: string,
	maxEdgesPerDevice = 50,
): peerDevicer.AsyncPeerStorage {
	let db: Database;

	function rowToPeerEdge(row: Record<string, unknown>): peerDevicer.PeerEdge {
		return {
			id: row.id as string,
			deviceIdA: row.deviceIdA as string,
			deviceIdB: row.deviceIdB as string,
			edgeType: row.edgeType as peerDevicer.PeerEdgeType,
			signalValue: row.signalValue as string,
			weight: row.weight as number,
			occurrences: row.occurrences as number,
			firstSeen: new Date(row.firstSeen as string),
			lastSeen: new Date(row.lastSeen as string),
		};
	}

	function rowToPeerCache(row: Record<string, unknown>): peerDevicer.PeerDeviceCache {
		return {
			deviceId: row.deviceId as string,
			updatedAt: new Date(row.updatedAt as string),
			ipRisk: row.ipRisk != null ? Number(row.ipRisk) : undefined,
			tlsConsistency: row.tlsConsistency != null ? Number(row.tlsConsistency) : undefined,
			driftScore: row.driftScore != null ? Number(row.driftScore) : undefined,
			flagReasons: JSON.parse((row.flagReasons as string) ?? '[]') as string[],
		};
	}

	return {
		// deno-lint-ignore require-await
		async init() {
			db = new Database(dbPath);
			db.prepare(`
				CREATE TABLE IF NOT EXISTS peer_edges (
					id TEXT PRIMARY KEY,
					deviceIdA TEXT NOT NULL,
					deviceIdB TEXT NOT NULL,
					edgeType TEXT NOT NULL,
					signalValue TEXT NOT NULL,
					weight REAL NOT NULL,
					occurrences INTEGER NOT NULL DEFAULT 1,
					firstSeen TEXT NOT NULL,
					lastSeen TEXT NOT NULL,
					UNIQUE(deviceIdA, deviceIdB, edgeType, signalValue)
				)
			`).run();
			db.prepare(`CREATE INDEX IF NOT EXISTS idx_peer_edges_a ON peer_edges(deviceIdA, lastSeen DESC)`).run();
			db.prepare(`CREATE INDEX IF NOT EXISTS idx_peer_edges_b ON peer_edges(deviceIdB, lastSeen DESC)`).run();
			db.prepare(`CREATE INDEX IF NOT EXISTS idx_peer_edges_signal ON peer_edges(edgeType, signalValue)`).run();

			db.prepare(`
				CREATE TABLE IF NOT EXISTS peer_device_cache (
					deviceId TEXT PRIMARY KEY,
					updatedAt TEXT NOT NULL,
					ipRisk REAL,
					tlsConsistency REAL,
					driftScore REAL,
					flagReasons TEXT NOT NULL DEFAULT '[]'
				)
			`).run();

			db.prepare(`
				CREATE TABLE IF NOT EXISTS peer_device_signals (
					deviceId TEXT NOT NULL,
					edgeType TEXT NOT NULL,
					signalValue TEXT NOT NULL,
					seenAt TEXT NOT NULL,
					PRIMARY KEY (deviceId, edgeType, signalValue)
				)
			`).run();
			db.prepare(`CREATE INDEX IF NOT EXISTS idx_peer_signals ON peer_device_signals(edgeType, signalValue)`).run();
		},

		async upsertEdge(partial) {
			const id = randomUUID();
			const now = new Date().toISOString();
			const firstSeen = partial.firstSeen instanceof Date ? partial.firstSeen.toISOString() : now;

			await db.prepare(`
				INSERT INTO peer_edges (id, deviceIdA, deviceIdB, edgeType, signalValue, weight, occurrences, firstSeen, lastSeen)
				VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
				ON CONFLICT(deviceIdA, deviceIdB, edgeType, signalValue)
				DO UPDATE SET occurrences = occurrences + 1, lastSeen = excluded.lastSeen
			`).run(
				id,
				partial.deviceIdA,
				partial.deviceIdB,
				partial.edgeType,
				partial.signalValue,
				partial.weight,
				firstSeen,
				now,
			);

			const rows = await db.prepare(`
				SELECT * FROM peer_edges
				WHERE deviceIdA = ? AND deviceIdB = ? AND edgeType = ? AND signalValue = ?
				LIMIT 1
			`).all(
				partial.deviceIdA,
				partial.deviceIdB,
				partial.edgeType,
				partial.signalValue,
			) as Record<string, unknown>[];
			const row = rows[0];

			const edgeRows = await db.prepare(`
				SELECT id FROM peer_edges WHERE (deviceIdA = ? OR deviceIdB = ?) ORDER BY lastSeen DESC LIMIT ?
			`).all(partial.deviceIdA, partial.deviceIdA, maxEdgesPerDevice + 1) as Array<Record<string, unknown>>;
			if (edgeRows.length > maxEdgesPerDevice) {
				for (const edgeRow of edgeRows.slice(maxEdgesPerDevice)) {
					await db.prepare(`DELETE FROM peer_edges WHERE id = ?`).run(edgeRow.id as string);
				}
			}

			return rowToPeerEdge(row);
		},

		async getEdges(deviceId, limit) {
			const rows = limit !== undefined
				? await db.prepare(`
					SELECT * FROM peer_edges WHERE (deviceIdA = ? OR deviceIdB = ?) ORDER BY lastSeen DESC LIMIT ?
				`).all(deviceId, deviceId, limit)
				: await db.prepare(`
					SELECT * FROM peer_edges WHERE (deviceIdA = ? OR deviceIdB = ?) ORDER BY lastSeen DESC
				`).all(deviceId, deviceId);
			return (rows as Record<string, unknown>[]).map(rowToPeerEdge);
		},

		async findPeersBySignal(edgeType, signalValue, limit) {
			const rows = limit !== undefined
				? await db.prepare(`
					SELECT deviceIdA, deviceIdB FROM peer_edges WHERE edgeType = ? AND signalValue = ? LIMIT ?
				`).all(edgeType, signalValue, limit * 2)
				: await db.prepare(`
					SELECT deviceIdA, deviceIdB FROM peer_edges WHERE edgeType = ? AND signalValue = ?
				`).all(edgeType, signalValue);

			const peers = [...new Set((rows as Array<Record<string, unknown>>).flatMap((row) => [
				row.deviceIdA as string,
				row.deviceIdB as string,
			]))];
			return limit !== undefined ? peers.slice(0, limit) : peers;
		},

		async registerDeviceSignal(deviceId, edgeType, signalValue) {
			await db.prepare(`
				INSERT INTO peer_device_signals (deviceId, edgeType, signalValue, seenAt)
				VALUES (?, ?, ?, ?)
				ON CONFLICT(deviceId, edgeType, signalValue) DO UPDATE SET seenAt = excluded.seenAt
			`).run(deviceId, edgeType, signalValue, new Date().toISOString());

			const rows = await db.prepare(`
				SELECT deviceId FROM peer_device_signals WHERE edgeType = ? AND signalValue = ? AND deviceId != ?
			`).all(edgeType, signalValue, deviceId) as Array<Record<string, unknown>>;
			return rows.map((row) => row.deviceId as string);
		},

		async saveDeviceCache(cache) {
			await db.prepare(`
				INSERT INTO peer_device_cache (deviceId, updatedAt, ipRisk, tlsConsistency, driftScore, flagReasons)
				VALUES (?, ?, ?, ?, ?, ?)
				ON CONFLICT(deviceId)
				DO UPDATE SET updatedAt = excluded.updatedAt, ipRisk = excluded.ipRisk,
					tlsConsistency = excluded.tlsConsistency, driftScore = excluded.driftScore,
					flagReasons = excluded.flagReasons
			`).run(
				cache.deviceId,
				cache.updatedAt.toISOString(),
				cache.ipRisk ?? null,
				cache.tlsConsistency ?? null,
				cache.driftScore ?? null,
				JSON.stringify(cache.flagReasons),
			);
		},

		async getDeviceCache(deviceId) {
			const row = await db.prepare(`SELECT * FROM peer_device_cache WHERE deviceId = ?`).get(deviceId) as Record<string, unknown> | undefined;
			return row ? rowToPeerCache(row) : null;
		},

		async size() {
			const row = await db.prepare(`
				SELECT COUNT(*) AS n FROM (
					SELECT deviceIdA AS d FROM peer_edges
					UNION SELECT deviceIdB FROM peer_edges
				)
			`).get() as { n?: number } | undefined;
			return row?.n ?? 0;
		},

		async pruneStaleEdges(olderThanMs) {
			const cutoff = new Date(Date.now() - olderThanMs).toISOString();
			const result = await db.prepare(`DELETE FROM peer_edges WHERE lastSeen < ?`).run(cutoff) as { changes?: number };
			return result.changes ?? 0;
		},

		async clearEdges(deviceId) {
			if (deviceId !== undefined) {
				await db.prepare(`DELETE FROM peer_edges WHERE deviceIdA = ? OR deviceIdB = ?`).run(deviceId, deviceId);
				return;
			}
			await db.prepare(`DELETE FROM peer_edges`).run();
		},

		async close() {
			await db.close();
		},
	};
}

// --- BBAS snapshots ---------------------------------------------------------------------------

export function createBbasManagerSqliteAdapter(
	dbPath: string,
	maxPerDevice = 50,
): bbasDevicer.AsyncBbasStorage {
	let db: Database;

	function rowToBbasSnapshot(row: Record<string, unknown>): bbasDevicer.BbasSnapshot {
		return {
			id: row.id as string,
			deviceId: row.device_id as string,
			timestamp: new Date(row.timestamp as string),
			enrichment: JSON.parse(row.enrichment as string) as bbasDevicer.BbasEnrichment,
		};
	}

	return {
		// deno-lint-ignore require-await
		async init() {
			db = new Database(dbPath);
			db.prepare(`
				CREATE TABLE IF NOT EXISTS bbas_snapshots (
					id TEXT PRIMARY KEY,
					device_id TEXT NOT NULL,
					timestamp TEXT NOT NULL,
					enrichment TEXT NOT NULL
				)
			`).run();
			db.prepare(`CREATE INDEX IF NOT EXISTS idx_bbas_device ON bbas_snapshots(device_id, timestamp DESC)`).run();
		},

		async save(snapshot) {
			const id = snapshot.id || randomUUID();
			const timestamp = snapshot.timestamp instanceof Date
				? snapshot.timestamp.toISOString()
				: String(snapshot.timestamp);

			await db.prepare(`
				INSERT INTO bbas_snapshots (id, device_id, timestamp, enrichment) VALUES (?, ?, ?, ?)
			`).run(id, snapshot.deviceId, timestamp, JSON.stringify(snapshot.enrichment));

			await db.prepare(`
				DELETE FROM bbas_snapshots
				WHERE device_id = ?
				AND id NOT IN (
					SELECT id FROM bbas_snapshots WHERE device_id = ? ORDER BY timestamp DESC, rowid DESC LIMIT ?
				)
			`).run(snapshot.deviceId, snapshot.deviceId, maxPerDevice);
		},

		async getHistory(deviceId, limit) {
			const rows = limit !== undefined
				? await db.prepare(`
					SELECT * FROM bbas_snapshots WHERE device_id = ? ORDER BY timestamp DESC, rowid DESC LIMIT ?
				`).all(deviceId, limit)
				: await db.prepare(`
					SELECT * FROM bbas_snapshots WHERE device_id = ? ORDER BY timestamp DESC, rowid DESC
				`).all(deviceId);
			return (rows as Record<string, unknown>[]).map(rowToBbasSnapshot);
		},

		async getLatest(deviceId) {
			const row = await db.prepare(`
				SELECT * FROM bbas_snapshots WHERE device_id = ? ORDER BY timestamp DESC, rowid DESC LIMIT 1
			`).get(deviceId) as Record<string, unknown> | undefined;
			return row ? rowToBbasSnapshot(row) : null;
		},

		async clear(deviceId) {
			await db.prepare(`DELETE FROM bbas_snapshots WHERE device_id = ?`).run(deviceId);
		},

		async size() {
			const row = await db.prepare(`SELECT COUNT(DISTINCT device_id) AS n FROM bbas_snapshots`).get() as { n?: number } | undefined;
			return row?.n ?? 0;
		},

		async close() {
			await db.close();
		},
	};
}

// --- IP Snapshots ------------------------------------------------------------------------------

export function createIpManagerSqliteAdapter(dbPath: string): ipDevicer.AsyncIpStorage {
	let db: Database;
	
	return {
		// deno-lint-ignore require-await
		async init() {
			db = new Database(dbPath);
			db.prepare(`
				CREATE TABLE IF NOT EXISTS ip_snapshots (
					id TEXT PRIMARY KEY,
					deviceId TEXT NOT NULL,
					timestamp TEXT NOT NULL,
					ip TEXT NOT NULL,
					enrichment TEXT NOT NULL
				)
			`).run();
		},

		async save(partial) {
			const snapshot = { ...partial, id: randomUUID() };
			await db.prepare(
				`INSERT INTO ip_snapshots (id, deviceId, timestamp, ip, enrichment) VALUES (?, ?, ?, ?, ?)`
			).run(
				snapshot.id,
				snapshot.deviceId,
				snapshot.timestamp.toISOString(),
				snapshot.ip,
				JSON.stringify(snapshot.enrichment)
			);
			return snapshot;
		},

		// deno-lint-ignore require-await
		async getHistory(deviceId, limit) {
			const rows = limit !== undefined
				? db.prepare(`SELECT * FROM ip_snapshots WHERE deviceId = ? ORDER BY timestamp DESC LIMIT ?`).all(deviceId, limit)
				: db.prepare(`SELECT * FROM ip_snapshots WHERE deviceId = ? ORDER BY timestamp DESC`).all(deviceId);
			return rows.map(row => ({
				id: row.id,
				deviceId: row.deviceId,
				timestamp: new Date(row.timestamp),
				ip: row.ip,
				enrichment: JSON.parse(row.enrichment),
			}));
		},

		async getLatest(deviceId): Promise<ipDevicer.IpSnapshot | null> {
			const row = await db.prepare(
				`SELECT * FROM ip_snapshots WHERE deviceId = ? ORDER BY timestamp DESC LIMIT 1`
			).get(deviceId);
			return row ? {
				id: row.id,
				deviceId: row.deviceId,
				timestamp: new Date(row.timestamp),
				ip: row.ip,
				enrichment: JSON.parse(row.enrichment),
			} : null;
		},

		async clear(deviceId) {
			if (deviceId !== undefined) {
				await db.prepare(`DELETE FROM ip_snapshots WHERE deviceId = ?`).run(deviceId);
			} else {
				await db.prepare(`DELETE FROM ip_snapshots`).run();
			}
		},

		async size() {
			const row = await db.prepare(`SELECT COUNT(DISTINCT deviceId) as count FROM ip_snapshots`).get();
			return row ? row.count : 0;
		},

		async close() {
			await db.close();
		},
	};
}