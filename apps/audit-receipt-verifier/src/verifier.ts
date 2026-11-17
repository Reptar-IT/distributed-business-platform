import { createHash, timingSafeEqual, type KeyObject } from "node:crypto";
import Fastify, { type FastifyInstance } from "fastify";
import { Pool, type PoolClient } from "pg";
import {
  verifyArchiveReceipt,
  type SignedArchiveReceipt,
} from "@platform/audit-protocol";

export interface AuditReceiptVerifierOptions {
  readonly databaseUrl: string;
  readonly serviceToken: string;
  readonly trustedReceiptKeys: ReadonlyMap<string, ReadonlyMap<string, KeyObject>>;
}

interface ReceiptSubmission {
  readonly batchId: string;
  readonly destinationId: string;
  readonly receipt: SignedArchiveReceipt;
}

function equalSecret(received: string, expected: string): boolean {
  return timingSafeEqual(
    createHash("sha256").update(received).digest(),
    createHash("sha256").update(expected).digest(),
  );
}

async function inTransaction<T>(client: PoolClient, task: () => Promise<T>): Promise<T> {
  await client.query("BEGIN");
  try {
    const result = await task();
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  }
}

export async function createAuditReceiptVerifier(options: AuditReceiptVerifierOptions): Promise<FastifyInstance> {
  if (options.serviceToken.length < 32) throw new Error("Receipt verifier service token is too short");
  const pool = new Pool({ connectionString: options.databaseUrl, application_name: "dbp-audit-receipt-verifier" });
  const app = Fastify({ logger: false, bodyLimit: 64 * 1024 });

  app.post<{ Body: ReceiptSubmission }>("/v1/audit/receipts", async (request, reply) => {
    const authorization = request.headers.authorization;
    if (!authorization?.startsWith("Bearer ") || !equalSecret(authorization.slice(7), options.serviceToken)) {
      return reply.code(401).send({ error: "Receipt verifier authentication failed" });
    }

    const submission = request.body;
    if (!submission?.batchId || !submission.destinationId || !submission.receipt?.payload || !submission.receipt?.signature) {
      return reply.code(400).send({ error: "Malformed archive receipt submission" });
    }
    const publicKey = options.trustedReceiptKeys
      .get(submission.destinationId)
      ?.get(submission.receipt.payload.keyId);
    if (!publicKey) return reply.code(400).send({ error: "Untrusted archive receipt key" });

    const client = await pool.connect();
    try {
      await inTransaction(client, async () => {
        const expected = await client.query<{
          batch_hash: string;
          first_sequence: string;
          last_sequence: string;
          terminal_hash: string;
        }>(
          `SELECT encode(b."batchHash", 'hex') AS batch_hash,
                  b."firstSequence"::text AS first_sequence,
                  b."lastSequence"::text AS last_sequence,
                  encode(b."terminalEventHash", 'hex') AS terminal_hash
             FROM public.audit_export_batches b
             JOIN public.audit_export_deliveries d ON d."batchId" = b."id"
            WHERE b."id" = $1 AND d."destinationId" = $2`,
          [submission.batchId, submission.destinationId],
        );
        if (!expected.rowCount) throw new Error("UNKNOWN_SOURCE_BATCH");
        const batch = expected.rows[0]!;
        verifyArchiveReceipt(submission.receipt, {
          destinationId: submission.destinationId,
          batchHash: batch.batch_hash,
          firstSequence: batch.first_sequence,
          lastSequence: batch.last_sequence,
          terminalEventHash: batch.terminal_hash,
        }, publicKey);
        await client.query(
          `SELECT public.record_verified_audit_receipt($1, $2, $3, $4)`,
          [submission.batchId, submission.destinationId, JSON.stringify(submission.receipt.payload),
            Buffer.from(submission.receipt.signature, "base64url")],
        );
      });
      return reply.code(204).send();
    } catch (error) {
      if (error instanceof Error && error.message === "UNKNOWN_SOURCE_BATCH") {
        return reply.code(404).send({ error: "Unknown archive receipt batch" });
      }
      if (typeof error === "object" && error !== null && "code" in error) {
        return reply.code(503).send({ error: "Archive receipt verification service is unavailable" });
      }
      return reply.code(400).send({ error: "Archive receipt verification or recording failed" });
    } finally {
      client.release();
    }
  });

  app.addHook("onClose", async () => { await pool.end(); });
  return app;
}
