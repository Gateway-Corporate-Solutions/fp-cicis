import { devicer } from "devicer-suite";

// Copied from fp-devicer/src/libs/tlsh.ts — produces a stable, key-sorted JSON
// string so that two semantically identical objects always hash identically.
// Remove and import directly if fp-devicer ever exports this function.
type JsonValue = string | number | boolean | null | undefined | JsonValue[] | { [key: string]: JsonValue };

function canonicalizedStringify(obj: JsonValue): string {
    if (obj === null || obj === undefined) return '';
    if (typeof obj !== 'object') return String(obj);
    if (Array.isArray(obj)) return `[${obj.map(canonicalizedStringify).join(',')}]`;
    const keys = Object.keys(obj).sort();
    return `{${keys.map(key => `${key}:${canonicalizedStringify((obj as { [key: string]: JsonValue })[key])}`).join(',')}}`;
}

// Mirror fp-devicer confidence defaults. Update if devicer-suite defaults change.
const TLSH_WEIGHT = 0.30;
const TLSH_MAX_DISTANCE = 300;

export async function clusterFingerprints(adapter: devicer.StorageAdapter, eps: number, minPts: number): Promise<[devicer.StoredFingerprint[][], devicer.StoredFingerprint[]]> {
    const fingerprints = await adapter.getAllFingerprints();
    return dbscan(fingerprints, eps, minPts);
}

export function dbscan(data: devicer.StoredFingerprint[], eps: number, minPts: number): [devicer.StoredFingerprint[][], devicer.StoredFingerprint[]] {
    const n = data.length;
    const clusterAssignments: number[] = new Array(n).fill(-1);
    let clusterId = 0;
    const parsedData = data.map(fp => fp.fingerprint);

    // Pre-compute one TLSH hash per fingerprint — avoids re-serialising inside
    // every pairwise comparison (now O(n)).
    const hashes: string[] = parsedData.map(fp => devicer.getHash(canonicalizedStringify(fp as unknown as JsonValue)));

    // Structural-only calculator: TLSH component blended manually below so that
    // the pre-computed hashes can be reused across all pairs.
    const structCalc = devicer.createConfidenceCalculator({ tlshWeight: 0 });

    // Build the full n×n distance matrix computing only the upper triangle
    // (n*(n-1)/2 pairs) and mirroring into the lower half.
    const distMatrix = new Float64Array(n * n);
    for (let i = 0; i < n; i++) {
        for (let j = i + 1; j < n; j++) {
            const tlshDiff = devicer.compareHashes(hashes[i], hashes[j]);
            const tlshScore = Math.max(0, (TLSH_MAX_DISTANCE - tlshDiff) / TLSH_MAX_DISTANCE);

            // Upper-bound pre-filter: if the best possible combined confidence
            // (assuming perfect structural match) still falls below the neighbour
            // threshold, skip the expensive recursive structural walk entirely.
            let d: number;
            if (1 * (1 - TLSH_WEIGHT) + tlshScore * TLSH_WEIGHT < (1 - eps)) {
                d = 1.0;
            } else {
                const structScore = structCalc.calculateConfidence(parsedData[i], parsedData[j]) / 100;
                d = 1 - (structScore * (1 - TLSH_WEIGHT) + tlshScore * TLSH_WEIGHT);
            }

            distMatrix[i * n + j] = d;
            distMatrix[j * n + i] = d;
        }
    }

    function regionQuery(pointIndex: number): number[] {
        const neighbors: number[] = [];
        const row = pointIndex * n;
        for (let i = 0; i < n; i++) {
            if (i !== pointIndex && distMatrix[row + i] <= eps) {
                neighbors.push(i);
            }
        }
        return neighbors;
    }

    function expandCluster(pointIndex: number, neighbors: number[], clusterId: number) {
        clusterAssignments[pointIndex] = clusterId;
        // Track queued indices to avoid processing the same point twice when
        // multiple density-reachable paths lead to the same neighbour.
        const visited = new Set<number>(neighbors);
        let i = 0;
        while (i < neighbors.length) {
            const neighborIndex = neighbors[i];
            if (clusterAssignments[neighborIndex] === -1) {
                clusterAssignments[neighborIndex] = clusterId;
                const neighborNeighbors = regionQuery(neighborIndex);
                if (neighborNeighbors.length >= minPts) {
                    for (const nn of neighborNeighbors) {
                        if (!visited.has(nn)) {
                            visited.add(nn);
                            neighbors.push(nn);
                        }
                    }
                }
            }
            i++;
        }
    }

    for (let i = 0; i < n; i++) {
        if (clusterAssignments[i] === -1) {
            const neighbors = regionQuery(i);
            if (neighbors.length >= minPts) {
                expandCluster(i, neighbors, clusterId);
                clusterId++;
            }
        }
    }

    const clusters: devicer.StoredFingerprint[][] = Array.from({ length: clusterId }, () => []);
    for (let i = 0; i < n; i++) {
        const assignment = clusterAssignments[i];
        if (assignment >= 0) {
            clusters[assignment].push(data[i]);
        }
    }

    const uniques: devicer.StoredFingerprint[] = [];
    for (let i = 0; i < n; i++) {
        if (clusterAssignments[i] === -1) {
            uniques.push(data[i]);
        }
    }

    return [clusters, uniques];
}