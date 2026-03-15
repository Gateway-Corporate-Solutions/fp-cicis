import { Database } from "sqlite";
import { randomUUID } from "node:crypto";
import { devicer, ipDevicer, tlsDevicer } from "devicer-suite"; 

// --- DeviceManager storage --------------------------------------------------------------

export function createDevManagerSqliteAdapter(dbPath: string): devicer.StorageAdapter {
	let db: Database;

	return {
		// deno-lint-ignore require-await
		async init() {
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
				// Add more pre-filtering conditions as needed based on your fingerprint structure
				// The goal is to reduce the number of candidates before doing the full confidence calculation
				// while still keeping potential matches. This is a balance between recall and performance.
				// In production, you might want to implement a more sophisticated pre-filtering strategy.
			});

			const pool = prelim.length > 0 ? prelim : rows; // Fall back to full set if no biometric signals matched

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
			// This method would require an additional table to store device-user associations.
			// For simplicity, it's not implemented here. In a real implementation, you'd want to create a separate "device_users" table and insert/update records there.
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