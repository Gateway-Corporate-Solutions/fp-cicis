import { Database } from "sqlite";
import { randomUUID } from "node:crypto";
import { devicer } from "devicer-suite"; 

export function createSqliteAdapter(dbPath: string): devicer.StorageAdapter {
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

/**
 * Example usage:
 * ```
 * const adapter = createSqliteAdapter('./fp.db');
 * await adapter.init();
 * await adapter.save({ deviceId: 'dev123', fingerprint: { ... }, timestamp: new Date() });
 * const history = await adapter.getHistory('dev123');
 * const candidates = await adapter.findCandidates({ query }, 50);
 * ```
 */