import { Database } from 'sqlite';

export interface FingerPrint {
  hash: string;
  data: string;
}

export class FPDB {
  private db: Database;

  constructor() {
    this.db = new Database('fp.db');

    this.db.prepare(`
      CREATE TABLE IF NOT EXISTS fingerprints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hash TEXT NOT NULL UNIQUE,
        data TEXT NOT NULL
      );
    `).run();
  }

  public insertFingerPrint(fp: FingerPrint): void {
    this.db.prepare(
      `INSERT INTO fingerprints (hash, data) VALUES (?, ?)
       ON CONFLICT(hash) DO UPDATE SET data = excluded.data;`
    ).run(fp.hash, fp.data);
  }

  public getFingerPrintByHash(hash: string): FingerPrint | null {
    const result = this.db.prepare(
      `SELECT hash, data FROM fingerprints WHERE hash = ?;`
    ).get(hash) as FingerPrint | undefined;

    if (result) {
      return { hash: result.hash, data: result.data };
    }
    return null;
  }

  public getAllFingerprints(): FingerPrint[] {
    const results = this.db.prepare(`SELECT hash, data FROM fingerprints;`).all() as FingerPrint[];
    return results.map(row => ({ hash: row.hash, data: row.data }));
  }

  public deleteFingerPrintByHash(hash: string): void {
    this.db.prepare(`DELETE FROM fingerprints WHERE hash = ?;`).run(hash);
  }
}