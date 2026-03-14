import { devicer } from "devicer-suite";

export async function clusterFingerprints(adapter: devicer.StorageAdapter, eps: number, minPts: number): Promise<[devicer.StoredFingerprint[][], devicer.StoredFingerprint[]]> {
    const fingerprints = await adapter.getAllFingerprints();
    return dbscan(fingerprints, eps, minPts);
}

export function dbscan(data: devicer.StoredFingerprint[], eps: number, minPts: number): [devicer.StoredFingerprint[][], devicer.StoredFingerprint[]] {
    const clusterAssignments: number[] = new Array(data.length).fill(-1);
    let clusterId = 0;
    const parsedData = data.map(fp => fp.fingerprint);
    
    function regionQuery(pointIndex: number): number[] {
        const neighbors: number[] = [];
        for (let i = 0; i < data.length; i++) {
            if (i !== pointIndex && distance(parsedData[pointIndex], parsedData[i]) <= eps) {
                neighbors.push(i);
            }
        }
        return neighbors;
    }

    function expandCluster(pointIndex: number, neighbors: number[], clusterId: number) {
        clusterAssignments[pointIndex] = clusterId;
        let i = 0;
        while (i < neighbors.length) {
            const neighborIndex = neighbors[i];
            if (clusterAssignments[neighborIndex] === -1) {
                clusterAssignments[neighborIndex] = clusterId;
                const neighborNeighbors = regionQuery(neighborIndex);
                if (neighborNeighbors.length >= minPts) {
                    neighbors = neighbors.concat(neighborNeighbors);
                }
            }
            i++;
        }
    }

    for (let i = 0; i < data.length; i++) {
        if (clusterAssignments[i] === -1) {
            const neighbors = regionQuery(i);
            if (neighbors.length >= minPts) {
                expandCluster(i, neighbors, clusterId);
                clusterId++;
            }
        }
    }

    const clusters: devicer.StoredFingerprint[][] = Array.from({ length: clusterId }, () => []);
    for (let i = 0; i < data.length; i++) {
        const assignment = clusterAssignments[i];
        if (assignment >= 0) {
            clusters[assignment].push(data[i]);
        }
    }

    const uniques: devicer.StoredFingerprint[] = [];
    for (let i = 0; i < data.length; i++) {
        if (clusterAssignments[i] === -1) {
            uniques.push(data[i]);
        }
    }

    return [clusters, uniques];
}

function distance(fp1: devicer.FPDataSet, fp2: devicer.FPDataSet): number {
    return 1 - (devicer.calculateConfidence(fp1, fp2) / 100);
}