import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  AUDIT_GENESIS_HASH,
  buildAuditBatch,
  hashAuditEvent,
  verifyArchiveReceipt,
  type AuditBatchWire,
  type SignedArchiveReceipt,
} from "@platform/audit-protocol";
import { createAuditArchive } from "./archive.js";

const directories: string[] = [];
const servers: Awaited<ReturnType<typeof createAuditArchive>>[] = [];
const token = "test-only-ingest-token-with-at-least-256-bits-of-entropy";
const streamId = "00000000-0000-0000-0000-000000000001";

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

async function storage(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "dbp-audit-archive-"));
  directories.push(directory);
  return directory;
}

async function startArchive(destinationId: string, directory: string, keys = generateKeyPairSync("ed25519")) {
  const app = await createAuditArchive({
    destinationId,
    receiptKeyId: `${destinationId}-test-key-1`,
    signingPrivateKey: keys.privateKey,
    ingestToken: token,
    storageDirectory: directory,
    now: () => new Date("2026-11-17T12:00:00.000Z"),
  });
  const address = await app.listen({ host: "127.0.0.1", port: 0 });
  servers.push(app);
  return { app, address, keys };
}

function makeBatch(): AuditBatchWire {
  const canonicalPayload = '{"eventType": "integration-test"}';
  const eventHash = hashAuditEvent({
    streamId,
    sequence: "1",
    previousHash: AUDIT_GENESIS_HASH,
    canonicalPayload,
  });
  return buildAuditBatch(streamId, [{
    sequence: "1",
    canonicalPayload,
    previousHash: AUDIT_GENESIS_HASH,
    eventHash,
  }]);
}

async function postBatch(address: string, batch: AuditBatchWire) {
  return fetch(`${address}/v1/audit/batches`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify(batch),
  });
}

describe("independent local archive receiver integration", () => {
  it("lets each archive independently accept the same batch and issue its own receipt", async () => {
    const batch = makeBatch();
    const physical = await startArchive("physical", await storage());
    const hosted = await startArchive("hosted", await storage());

    const physicalResponse = await postBatch(physical.address, batch);
    const hostedResponse = await postBatch(hosted.address, batch);
    expect(physicalResponse.status).toBe(201);
    expect(hostedResponse.status).toBe(201);

    const physicalReceipt = await physicalResponse.json() as SignedArchiveReceipt;
    const hostedReceipt = await hostedResponse.json() as SignedArchiveReceipt;
    verifyArchiveReceipt(physicalReceipt, {
      destinationId: "physical", batchHash: batch.batchHash, firstSequence: "1", lastSequence: "1",
      terminalEventHash: batch.terminalEventHash,
    }, physical.keys.publicKey);
    verifyArchiveReceipt(hostedReceipt, {
      destinationId: "hosted", batchHash: batch.batchHash, firstSequence: "1", lastSequence: "1",
      terminalEventHash: batch.terminalEventHash,
    }, hosted.keys.publicKey);
    expect(physicalReceipt.signature).not.toBe(hostedReceipt.signature);
  });

  it("accepts at one destination while the other destination is unavailable", async () => {
    const batch = makeBatch();
    const hosted = await startArchive("hosted", await storage());
    const response = await postBatch(hosted.address, batch);
    expect(response.status).toBe(201);
    const receipt = await response.json() as SignedArchiveReceipt;
    verifyArchiveReceipt(receipt, {
      destinationId: "hosted", batchHash: batch.batchHash, firstSequence: "1", lastSequence: "1",
      terminalEventHash: batch.terminalEventHash,
    }, hosted.keys.publicKey);
  });

  it("lets the physical archive accept while the hosted archive is unavailable", async () => {
    const batch = makeBatch();
    const physical = await startArchive("physical", await storage());
    const response = await postBatch(physical.address, batch);
    expect(response.status).toBe(201);
    const receipt = await response.json() as SignedArchiveReceipt;
    verifyArchiveReceipt(receipt, {
      destinationId: "physical", batchHash: batch.batchHash, firstSequence: "1", lastSequence: "1",
      terminalEventHash: batch.terminalEventHash,
    }, physical.keys.publicKey);
  });

  it("persists accepted batches and returns the same receipt after restart", async () => {
    const directory = await storage();
    const batch = makeBatch();
    const first = await startArchive("physical", directory);
    const initialResponse = await postBatch(first.address, batch);
    const initialReceipt = await initialResponse.json() as SignedArchiveReceipt;
    await first.app.close();
    servers.splice(servers.indexOf(first.app), 1);

    const restarted = await startArchive("physical", directory, first.keys);
    const duplicate = await postBatch(restarted.address, batch);
    expect(duplicate.status).toBe(200);
    expect(await duplicate.json()).toEqual(initialReceipt);
    expect((await readdir(directory)).filter((name) => name.endsWith(".json"))).toHaveLength(1);
  });

  it("rejects unauthorized, altered, and non-contiguous batches", async () => {
    const archive = await startArchive("physical", await storage());
    const batch = makeBatch();
    const unauthorized = await fetch(`${archive.address}/v1/audit/batches`, {
      method: "POST", headers: { authorization: "Bearer wrong", "content-type": "application/json" }, body: JSON.stringify(batch),
    });
    expect(unauthorized.status).toBe(401);

    const altered = await postBatch(archive.address, { ...batch, batchHash: "ff".repeat(32) });
    expect(altered.status).toBe(400);

    const gap = buildAuditBatch(streamId, [{
      sequence: "3", canonicalPayload: '{"eventType": "gap"}', previousHash: batch.terminalEventHash,
      eventHash: hashAuditEvent({ streamId, sequence: "3", previousHash: batch.terminalEventHash, canonicalPayload: '{"eventType": "gap"}' }),
    }]);
    const nonContiguous = await postBatch(archive.address, gap);
    expect(nonContiguous.status).toBe(409);
  });
});
