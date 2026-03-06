import { FPDB, FingerPrint } from './db.ts';
import { calculateConfidence, FPDataSet } from "devicer";

export function clusterFingerprints(fpdb: FPDB, eps: number, minPts: number): FingerPrint[][] {
    const fingerprints = fpdb.getAllFingerprints();
    return dbscan(fingerprints, eps, minPts);
}

export function dbscan(data: FingerPrint[], eps: number, minPts: number): FingerPrint[][] {
    const clusterAssignments: number[] = new Array(data.length).fill(-1);
    let clusterId = 0;
    const parsedData = data.map(fp => JSON.parse(fp.data) as FPDataSet);
    
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

    const clusters: FingerPrint[][] = Array.from({ length: clusterId }, () => []);
    for (let i = 0; i < data.length; i++) {
        const assignment = clusterAssignments[i];
        if (assignment >= 0) {
            clusters[assignment].push(data[i]);
        }
    }

    return clusters;
}

function distance(fp1: FPDataSet, fp2: FPDataSet): number {
    return 1 - (calculateConfidence(fp1, fp2) / 100);
}