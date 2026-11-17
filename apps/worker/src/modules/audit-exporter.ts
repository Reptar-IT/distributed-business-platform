import { Pool, type PoolClient } from "pg";
interface DestinationConfig {
  readonly id: "physical" | "hosted";
  readonly url: string;
  readonly ingestToken: string;
}

export interface AuditExporterOptions {
  readonly exporterDatabaseUrl: string;
  readonly receiptVerifierUrl: string;
  readonly receiptVerifierServiceToken: string;
  readonly destinations: readonly DestinationConfig[];
  readonly maxBatchEvents?: number;
  readonly requestTimeoutMs?: number;
}

export interface AuditDestinationHealth {
  readonly destinationId: string;
  readonly lastSucceededAt: string | null;
  readonly consecutiveFailures: number;
  readonly lastErrorCategory: string | null;
}

export interface AuditExportRunReport {
  readonly destinations: readonly AuditDestinationHealth[];
  readonly retryMetadataFailures: readonly string[];
  readonly processingFailures: readonly string[];
}

interface StoredBatch {
  readonly id: string;
  readonly streamId: string;
  readonly firstSequence: string;
  readonly lastSequence: string;
  readonly previousHash: string;
  readonly batchHash: string;
  readonly canonicalBatch: string;
}

interface PendingDelivery extends StoredBatch {
  readonly destinationId: string;
  readonly attempts: number;
}

function retryDelaySeconds(attempts: number): number {
  return Math.min(300, 2 ** Math.min(Math.max(attempts, 0), 8));
}

function errorCode(error: unknown): string {
  if (error instanceof TypeError) return "NETWORK_ERROR";
  if (error instanceof Error && error.message === "INVALID_RECEIPT") return "INVALID_RECEIPT";
  if (error instanceof Error && error.message === "ARCHIVE_HTTP_REJECTED") return "ARCHIVE_HTTP_REJECTED";
  if (error instanceof Error && error.message === "VERIFIER_HTTP_REJECTED") return "VERIFIER_HTTP_REJECTED";
  if (error instanceof Error && error.message === "VERIFIER_UNAVAILABLE") return "VERIFIER_UNAVAILABLE";
  const databaseCode = typeof error === "object" && error !== null && "code" in error
    ? String((error as { code: unknown }).code)
    : undefined;
  if (databaseCode === "42501") return "DATABASE_PERMISSION_DENIED";
  if (["23503", "23505", "23514"].includes(databaseCode ?? "")) return "DATABASE_CONSTRAINT_REJECTED";
  if (["P0001", "22P02"].includes(databaseCode ?? "")) return "DATABASE_FUNCTION_REJECTED";
  return "EXPORT_FAILED";
}

async function transaction<T>(client: PoolClient, work: () => Promise<T>): Promise<T> {
  await client.query("BEGIN");
  try {
    const result = await work();
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  }
}

export function createAuditExporter(options: AuditExporterOptions) {
  const exportPool = new Pool({ connectionString: options.exporterDatabaseUrl, application_name: "dbp-audit-exporter" });
  const maxBatchEvents = options.maxBatchEvents ?? 100;

  async function prepareNextBatch(): Promise<void> {
    const client = await exportPool.connect();
    try {
      await transaction(client, async () => {
        const streamId = "00000000-0000-0000-0000-000000000001";
        const previousBatch = await client.query<{ last_sequence: string }>(
          `SELECT "lastSequence"::text AS last_sequence
             FROM public.audit_export_batches WHERE "streamId" = $1
             ORDER BY "lastSequence" DESC LIMIT 1`, [streamId],
        );
        const firstExpected = previousBatch.rowCount
          ? BigInt(previousBatch.rows[0]!.last_sequence) + 1n
          : 1n;
        await client.query(
          `SELECT * FROM public.prepare_authorization_audit_batch($1, $2, $3)`,
          [streamId, firstExpected.toString(), maxBatchEvents],
        );
      });
    } finally {
      client.release();
    }
  }

  async function pendingFor(destinationId: string): Promise<PendingDelivery | null> {
    const result = await exportPool.query<PendingDelivery>(
      `SELECT b."id", b."streamId", b."firstSequence"::text AS "firstSequence",
              b."lastSequence"::text AS "lastSequence", encode(b."previousHash", 'hex') AS "previousHash",
              encode(b."batchHash", 'hex') AS "batchHash", b."canonicalBatch", d."destinationId", d."attempts"
         FROM public.audit_export_batches b
         JOIN public.audit_export_deliveries d ON d."batchId" = b."id"
         JOIN public.audit_export_checkpoints c ON c."streamId" = b."streamId" AND c."destinationId" = d."destinationId"
        WHERE d."destinationId" = $1 AND d."status" = 'PENDING' AND d."nextAttemptAt" <= clock_timestamp()
          AND b."firstSequence" = c."lastAcknowledgedSequence" + 1
          AND b."previousHash" = c."lastAcknowledgedEventHash"
        ORDER BY b."firstSequence" LIMIT 1`, [destinationId],
    );
    return result.rows[0] ?? null;
  }

  async function noteFailure(delivery: PendingDelivery, error: unknown): Promise<void> {
    const code = errorCode(error);
    const client = await exportPool.connect();
    try {
      await transaction(client, async () => {
        await client.query(
          `UPDATE public.audit_export_deliveries
              SET "attempts" = "attempts" + 1,
                  "nextAttemptAt" = clock_timestamp() + ($3::text || ' seconds')::interval,
                  "lastErrorCode" = $4, "updatedAt" = clock_timestamp()
            WHERE "batchId" = $1 AND "destinationId" = $2 AND "status" = 'PENDING'`,
          [delivery.id, delivery.destinationId, retryDelaySeconds(delivery.attempts + 1), code],
        );
        await client.query(
          `UPDATE public.audit_destinations
              SET "consecutiveFailures" = LEAST("consecutiveFailures" + 1, 2147483647),
                  "lastErrorCategory" = $2, "updatedAt" = clock_timestamp()
            WHERE "id" = $1`,
          [delivery.destinationId, code],
        );
      });
    } finally {
      client.release();
    }
  }

  async function deliver(destination: DestinationConfig): Promise<"IDLE" | "DELIVERED" | "FAILED" | "RETRY_METADATA_FAILED" | "PROCESSING_FAILED"> {
    let delivery: PendingDelivery | null;
    try {
      delivery = await pendingFor(destination.id);
    } catch {
      return "PROCESSING_FAILED";
    }
    if (!delivery) return "IDLE";
    try {
      const timeout = AbortSignal.timeout(options.requestTimeoutMs ?? 10_000);
      const response = await fetch(destination.url, {
        method: "POST",
        headers: { authorization: `Bearer ${destination.ingestToken}`, "content-type": "application/json" },
        body: delivery.canonicalBatch,
        signal: timeout,
      });
      if (!response.ok) throw new Error("ARCHIVE_HTTP_REJECTED");
      const receipt = await response.json();
      const verified = await fetch(options.receiptVerifierUrl, {
        method: "POST",
        headers: {
          authorization: `Bearer ${options.receiptVerifierServiceToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ batchId: delivery.id, destinationId: destination.id, receipt }),
        signal: AbortSignal.timeout(options.requestTimeoutMs ?? 10_000),
      });
      if (verified.status >= 500) throw new Error("VERIFIER_UNAVAILABLE");
      if (!verified.ok) throw new Error("VERIFIER_HTTP_REJECTED");
      return "DELIVERED";
    } catch (error) {
      try {
        await noteFailure(delivery, error);
        return "FAILED";
      } catch {
        return "RETRY_METADATA_FAILED";
      }
    }
  }

  async function getHealth(): Promise<AuditDestinationHealth[]> {
    const result = await exportPool.query<{
      destination_id: string;
      last_succeeded_at: Date | null;
      consecutive_failures: number;
      last_error_category: string | null;
    }>(
      `SELECT "id" AS destination_id, "lastSucceededAt" AS last_succeeded_at,
              "consecutiveFailures" AS consecutive_failures, "lastErrorCategory" AS last_error_category
         FROM public.audit_destinations WHERE "id" IN ('physical', 'hosted') ORDER BY "id"`,
    );
    return result.rows.map((row) => ({
      destinationId: row.destination_id,
      lastSucceededAt: row.last_succeeded_at?.toISOString() ?? null,
      consecutiveFailures: row.consecutive_failures,
      lastErrorCategory: row.last_error_category,
    }));
  }

  return {
    async runOnce(): Promise<AuditExportRunReport> {
      await prepareNextBatch();
      const results = await Promise.all(options.destinations.map(async (destination) => ({
        destinationId: destination.id,
        result: await deliver(destination),
      })));
      return {
        destinations: await getHealth(),
        retryMetadataFailures: results.filter((item) => item.result === "RETRY_METADATA_FAILED").map((item) => item.destinationId),
        processingFailures: results.filter((item) => item.result === "PROCESSING_FAILED").map((item) => item.destinationId),
      };
    },
    async close(): Promise<void> {
      await exportPool.end();
    },
  };
}
