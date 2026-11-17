import { createHash, createPublicKey, timingSafeEqual, type KeyObject } from "node:crypto";
import { mkdir, open, readFile, readdir, rename } from "node:fs/promises";
import { dirname, join } from "node:path";
import Fastify, { type FastifyInstance } from "fastify";
import {
  buildAuditBatch,
  signArchiveReceipt,
  verifyArchiveReceipt,
  verifyAuditBatch,
  type AuditBatchWire,
  type SignedArchiveReceipt,
} from "@platform/audit-protocol";

interface AcceptedBatch {
  readonly batch: AuditBatchWire;
  readonly receipt: SignedArchiveReceipt;
}

export interface AuditArchiveOptions {
  readonly destinationId: string;
  readonly receiptKeyId: string;
  readonly signingPrivateKey: KeyObject;
  readonly trustedReceiptPublicKeys?: ReadonlyMap<string, KeyObject>;
  readonly ingestToken: string;
  readonly storageDirectory: string;
  readonly now?: () => Date;
}

function constantTimeSecretEqual(left: string, right: string): boolean {
  const leftDigest = createHash("sha256").update(left).digest();
  const rightDigest = createHash("sha256").update(right).digest();
  return timingSafeEqual(leftDigest, rightDigest);
}

function batchFileName(batch: AuditBatchWire): string {
  return `${batch.streamId}-${batch.firstSequence}-${batch.lastSequence}-${batch.batchHash}.json`;
}

export async function createAuditArchive(options: AuditArchiveOptions): Promise<FastifyInstance> {
  if (!options.destinationId || !options.receiptKeyId || options.ingestToken.length < 32) {
    throw new Error("Archive destination, key ID, and high-entropy ingest token are required");
  }
  await mkdir(options.storageDirectory, { recursive: true, mode: 0o700 });
  const accepted = new Map<string, Map<bigint, AcceptedBatch>>();
  const streamLocks = new Map<string, Promise<void>>();
  const receiptKeys = options.trustedReceiptPublicKeys ?? new Map([
    [options.receiptKeyId, createPublicKey(options.signingPrivateKey)],
  ]);

  for (const name of await readdir(options.storageDirectory)) {
    if (!name.endsWith(".json")) continue;
    const stored = JSON.parse(await readFile(join(options.storageDirectory, name), "utf8")) as AcceptedBatch;
    verifyAuditBatch(stored.batch);
    const receiptKey = receiptKeys.get(stored.receipt.payload.keyId);
    if (!receiptKey) throw new Error(`Unknown archived receipt key: ${stored.receipt.payload.keyId}`);
    verifyArchiveReceipt(stored.receipt, {
      destinationId: options.destinationId,
      batchHash: stored.batch.batchHash,
      firstSequence: stored.batch.firstSequence,
      lastSequence: stored.batch.lastSequence,
      terminalEventHash: stored.batch.terminalEventHash,
    }, receiptKey);
    const streamEntries = accepted.get(stored.batch.streamId) ?? new Map<bigint, AcceptedBatch>();
    streamEntries.set(BigInt(stored.batch.firstSequence), stored);
    accepted.set(stored.batch.streamId, streamEntries);
  }

  for (const [streamId, batches] of accepted) {
    let expectedSequence = 1n;
    let previousHash = "00".repeat(32);
    for (const [firstSequence, stored] of [...batches.entries()].sort(([a], [b]) => a < b ? -1 : 1)) {
      if (firstSequence !== expectedSequence || stored.batch.previousHash !== previousHash) {
        throw new Error(`Archive storage has a sequence or hash-chain gap for stream ${streamId}`);
      }
      expectedSequence = BigInt(stored.batch.lastSequence) + 1n;
      previousHash = stored.batch.terminalEventHash;
    }
  }

  const app = Fastify({ logger: false, bodyLimit: 5 * 1024 * 1024 });
  app.post<{ Body: AuditBatchWire }>("/v1/audit/batches", async (request, reply) => {
    const authorization = request.headers.authorization;
    if (!authorization?.startsWith("Bearer ") || !constantTimeSecretEqual(authorization.slice(7), options.ingestToken)) {
      return reply.code(401).send({ error: "Archive authentication failed" });
    }

    let batch: AuditBatchWire;
    try {
      batch = request.body;
      verifyAuditBatch(batch);
    } catch {
      return reply.code(400).send({ error: "Audit batch verification failed" });
    }

    const prior = streamLocks.get(batch.streamId) ?? Promise.resolve();
    let release!: () => void;
    const current = new Promise<void>((resolve) => { release = resolve; });
    const lock = prior.then(() => current);
    streamLocks.set(batch.streamId, lock);
    await prior;
    try {
      const streamBatches = accepted.get(batch.streamId) ?? new Map<bigint, AcceptedBatch>();
      const existing = streamBatches.get(BigInt(batch.firstSequence));
      if (existing) {
        if (existing.batch.batchHash !== batch.batchHash || existing.batch.lastSequence !== batch.lastSequence) {
          return reply.code(409).send({ error: "Conflicting batch for accepted sequence range" });
        }
        return reply.code(200).send(existing.receipt);
      }

      const last = [...streamBatches.values()].sort((a, b) => BigInt(a.batch.lastSequence) < BigInt(b.batch.lastSequence) ? 1 : -1)[0];
      const expectedSequence = last ? BigInt(last.batch.lastSequence) + 1n : 1n;
      const expectedHash = last?.batch.terminalEventHash ?? "00".repeat(32);
      if (BigInt(batch.firstSequence) !== expectedSequence || batch.previousHash !== expectedHash) {
        return reply.code(409).send({ error: "Batch is not contiguous with the archive checkpoint" });
      }

      const acceptedAt = (options.now ?? (() => new Date()))().toISOString();
      const receipt = signArchiveReceipt({
        version: 1,
        destinationId: options.destinationId,
        batchHash: batch.batchHash,
        firstSequence: batch.firstSequence,
        lastSequence: batch.lastSequence,
        terminalEventHash: batch.terminalEventHash,
        acceptedAt,
        keyId: options.receiptKeyId,
      }, options.signingPrivateKey);
      const stored = { batch, receipt } satisfies AcceptedBatch;
      const target = join(options.storageDirectory, batchFileName(batch));
      const temporary = `${target}.${process.pid}.${Date.now()}.tmp`;
      const file = await open(temporary, "wx", 0o600);
      try {
        await file.writeFile(`${JSON.stringify(stored)}\n`, "utf8");
        await file.sync();
      } finally {
        await file.close();
      }
      await rename(temporary, target);
      const directory = await open(dirname(target), "r");
      try { await directory.sync(); } finally { await directory.close(); }
      streamBatches.set(BigInt(batch.firstSequence), stored);
      accepted.set(batch.streamId, streamBatches);
      return reply.code(201).send(receipt);
    } finally {
      release();
      if (streamLocks.get(batch.streamId) === lock) streamLocks.delete(batch.streamId);
    }
  });

  return app;
}
