import { createHash } from "node:crypto";
import { Pool, type PoolConfig } from "pg";

type SafeRequest = Readonly<Record<string, unknown>>;

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Request values must be finite JSON numbers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const object = value as Record<string, unknown>;
    if (Object.getPrototypeOf(object) !== Object.prototype && Object.getPrototypeOf(object) !== null) {
      throw new TypeError("Request fingerprint input must contain only plain JSON objects");
    }
    return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`).join(",")}}`;
  }
  throw new TypeError("Request fingerprint input must be JSON data");
}

function digest(domain: string, value: string): Buffer {
  return createHash("sha256").update(domain, "utf8").update("\0", "utf8").update(value, "utf8").digest();
}

export function criticalOperationDigests(idempotencyKey: string, canonicalRequest: SafeRequest) {
  if (idempotencyKey.length < 32 || idempotencyKey.length > 512) {
    throw new TypeError("Idempotency key must contain 32 to 512 characters");
  }
  return {
    idempotencyDigest: digest("DBP-CRITICAL-IDEMPOTENCY-v1", idempotencyKey),
    requestFingerprint: digest("DBP-CRITICAL-REQUEST-v1", canonicalJson(canonicalRequest)),
  };
}

export function createCriticalOperationService(config: PoolConfig | string) {
  const pool = new Pool(typeof config === "string" ? { connectionString: config, max: 5, application_name: "dbp-critical-operation-service" } : config);

  async function prepareActivation(input: { operationType: string; targetType: string; targetId: string; idempotencyKey: string; canonicalRequest: SafeRequest }): Promise<string> {
    const digests = criticalOperationDigests(input.idempotencyKey, input.canonicalRequest);
    const result = await pool.query<{ id: string }>(
      "SELECT public.prepare_critical_operation($1,$2,$3,$4,$5) AS id",
      [input.operationType, input.targetType, input.targetId, digests.idempotencyDigest, digests.requestFingerprint],
    );
    return result.rows[0]!.id;
  }

  async function requestRevocation(input: { operationType: string; targetType: string; targetId: string; idempotencyKey: string; canonicalRequest: SafeRequest }): Promise<string> {
    const digests = criticalOperationDigests(input.idempotencyKey, input.canonicalRequest);
    const result = await pool.query<{ id: string }>(
      "SELECT public.request_critical_operation_revocation($1,$2,$3,$4,$5) AS id",
      [input.operationType, input.targetType, input.targetId, digests.idempotencyDigest, digests.requestFingerprint],
    );
    return result.rows[0]!.id;
  }

  async function advance(limit = 100): Promise<number> {
    const result = await pool.query<{ advance_critical_operations: number }>(
      "SELECT public.advance_critical_operations($1)", [limit],
    );
    return result.rows[0]!.advance_critical_operations;
  }

  return { prepareActivation, requestRevocation, advance, close: () => pool.end() };
}

export function createCriticalOperationWorker(databaseUrl: string, intervalMs = 2_000) {
  const pool = new Pool({ connectionString: databaseUrl, max: 3, application_name: "dbp-critical-operation-worker" });
  let timer: NodeJS.Timeout | undefined;
  let running = false;

  const runOnce = async () => {
    if (running) return;
    running = true;
    try {
      await pool.query("SELECT public.advance_critical_operations($1)", [100]);
    } finally {
      running = false;
    }
  };

  return {
    runOnce,
    start() {
      if (timer) return;
      void runOnce().catch(() => console.error(JSON.stringify({ service: "critical-operation-worker", errorCategory: "ADVANCE_FAILED" })));
      timer = setInterval(() => {
        void runOnce().catch(() => console.error(JSON.stringify({ service: "critical-operation-worker", errorCategory: "ADVANCE_FAILED" })));
      }, intervalMs);
    },
    async close() {
      if (timer) clearInterval(timer);
      timer = undefined;
      await pool.end();
    },
  };
}
