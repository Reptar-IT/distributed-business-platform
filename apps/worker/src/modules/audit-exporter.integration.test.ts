import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createAuditArchive } from "@platform/audit-archive";
import { createAuditReceiptVerifier } from "@platform/audit-receipt-verifier";
import { createAuditExporter } from "./audit-exporter.js";

const adminUrl = process.env.DBP_AUDIT_TEST_DATABASE_URL;
const suite = adminUrl ? describe : describe.skip;
if (adminUrl && !/^\/dbp_audit_test(?:_[a-z0-9]+)?$/.test(new URL(adminUrl).pathname)) {
  throw new Error("DBP_AUDIT_TEST_DATABASE_URL must point to a dedicated dbp_audit_test database");
}

suite("audit exporter PostgreSQL and archive integration", () => {
  const admin = new Pool({ connectionString: adminUrl, max: 4, application_name: "dbp-audit-exporter-test-setup" });
  const dirs: string[] = [];
  const servers: Array<Awaited<ReturnType<typeof createAuditArchive>>> = [];
  const physicalKeys = generateKeyPairSync("ed25519");
  const hostedKeys = generateKeyPairSync("ed25519");
  const testIngestToken = "audit-exporter-test-token-with-more-than-256-bits-of-entropy";
  const testVerifierServiceToken = "audit-verifier-service-test-token-with-more-than-256-bits";
  let physical: { app: Awaited<ReturnType<typeof createAuditArchive>>; address: string } | undefined;
  let hosted: { app: Awaited<ReturnType<typeof createAuditArchive>>; address: string };
  let sourceSequence = "";

  async function startArchive(id: "physical" | "hosted", keys: typeof physicalKeys) {
    const dir = await mkdtemp(join(tmpdir(), `dbp-${id}-archive-test-`));
    dirs.push(dir);
    const app = await createAuditArchive({
      destinationId: id,
      receiptKeyId: `${id}-test-key`,
      signingPrivateKey: keys.privateKey,
      ingestToken: testIngestToken,
      storageDirectory: dir,
    });
    servers.push(app);
    return { app, address: await app.listen({ host: "127.0.0.1", port: 0 }) };
  }

  async function loginUrl(role: string): Promise<string> {
    await admin.query(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${role}') THEN CREATE ROLE ${role} LOGIN; END IF; END $$`);
    await admin.query(`GRANT ${role === "dbp_audit_exporter_test" ? "dbp_audit_exporter" : "dbp_audit_receipt_verifier"} TO ${role}`);
    const url = new URL(adminUrl!);
    url.username = role;
    url.password = "";
    return url.toString();
  }

  beforeAll(async () => {
    const exporterUrl = await loginUrl("dbp_audit_exporter_test");
    const verifierUrl = await loginUrl("dbp_audit_receipt_verifier_test");
    hosted = await startArchive("hosted", hostedKeys);
    const verifier = await createAuditReceiptVerifier({
      databaseUrl: verifierUrl,
      serviceToken: testVerifierServiceToken,
      trustedReceiptKeys: new Map([
        ["physical", new Map([["physical-test-key", physicalKeys.publicKey]])],
        ["hosted", new Map([["hosted-test-key", hostedKeys.publicKey]])],
      ]),
    });
    servers.push(verifier);
    const verifierAddress = await verifier.listen({ host: "127.0.0.1", port: 0 });

    const appended = await admin.query<{ sequence: string }>(
      `SELECT * FROM public.append_authorization_audit($1::jsonb)`,
      [JSON.stringify({ eventType: "export-integration", actorType: "SYSTEM", actorId: "export-test", operation: "deliver", outcome: "recorded" })],
    );
    sourceSequence = appended.rows[0]!.sequence;

    // The physical URL intentionally points to a closed local port for the first pass.
    const exporter = createAuditExporter({
      exporterDatabaseUrl: exporterUrl,
      receiptVerifierUrl: `${verifierAddress}/v1/audit/receipts`,
      receiptVerifierServiceToken: testVerifierServiceToken,
      destinations: [
        { id: "physical", url: "http://127.0.0.1:1/v1/audit/batches", ingestToken: testIngestToken },
        { id: "hosted", url: `${hosted.address}/v1/audit/batches`, ingestToken: testIngestToken },
      ],
    });
    try {
      await exporter.runOnce();
    } finally {
      await exporter.close();
    }

    const independent = await admin.query<{ physical_sequence: string; hosted_sequence: string; physical_status: string }>(
      `SELECT
        (SELECT "lastAcknowledgedSequence"::text FROM public.audit_export_checkpoints WHERE "destinationId" = 'physical') AS physical_sequence,
        (SELECT "lastAcknowledgedSequence"::text FROM public.audit_export_checkpoints WHERE "destinationId" = 'hosted') AS hosted_sequence,
        (SELECT "status"::text FROM public.audit_export_deliveries WHERE "destinationId" = 'physical' ORDER BY "createdAt" DESC LIMIT 1) AS physical_status`,
    );
    expect(independent.rows[0]).toEqual({ physical_sequence: "0", hosted_sequence: sourceSequence, physical_status: "PENDING" });
    const firstHealth = await admin.query<{ id: string; consecutiveFailures: number; lastErrorCategory: string | null; lastSucceededAt: Date | null }>(
      `SELECT "id", "consecutiveFailures", "lastErrorCategory", "lastSucceededAt"
         FROM public.audit_destinations ORDER BY "id"`,
    );
    expect(firstHealth.rows.find((row) => row.id === "physical")).toMatchObject({
      consecutiveFailures: 1, lastErrorCategory: "NETWORK_ERROR", lastSucceededAt: null,
    });
    expect(firstHealth.rows.find((row) => row.id === "hosted")).toMatchObject({
      consecutiveFailures: 0, lastErrorCategory: null,
    });
    expect(firstHealth.rows.find((row) => row.id === "hosted")?.lastSucceededAt).toBeInstanceOf(Date);

    const batch = await admin.query<{ id: string; batchHash: Buffer; firstSequence: string; lastSequence: string; terminalEventHash: Buffer }>(
      `SELECT "id", "batchHash", "firstSequence"::text AS "firstSequence",
              "lastSequence"::text AS "lastSequence", "terminalEventHash"
         FROM public.audit_export_batches ORDER BY "firstSequence" LIMIT 1`,
    );
    const sourceBatch = batch.rows[0]!;
    const invalidReceipt = await fetch(`${verifierAddress}/v1/audit/receipts`, {
      method: "POST",
      headers: { authorization: `Bearer ${testVerifierServiceToken}`, "content-type": "application/json" },
      body: JSON.stringify({
        batchId: sourceBatch.id,
        destinationId: "hosted",
        receipt: {
          payload: {
            version: 1, destinationId: "hosted", batchHash: sourceBatch.batchHash.toString("hex"),
            firstSequence: sourceBatch.firstSequence, lastSequence: sourceBatch.lastSequence,
            terminalEventHash: sourceBatch.terminalEventHash.toString("hex"),
            acceptedAt: new Date().toISOString(), keyId: "hosted-test-key",
          },
          signature: Buffer.alloc(64).toString("base64url"),
        },
      }),
    });
    expect(invalidReceipt.status).toBe(400);

    physical = await startArchive("physical", physicalKeys);
    await admin.query(`UPDATE public.audit_export_deliveries SET "nextAttemptAt" = clock_timestamp() WHERE "destinationId" = 'physical' AND "status" = 'PENDING'`);
    const recovered = createAuditExporter({
      exporterDatabaseUrl: exporterUrl,
      receiptVerifierUrl: `${verifierAddress}/v1/audit/receipts`,
      receiptVerifierServiceToken: testVerifierServiceToken,
      destinations: [
        { id: "physical", url: `${physical.address}/v1/audit/batches`, ingestToken: testIngestToken },
        { id: "hosted", url: `${hosted.address}/v1/audit/batches`, ingestToken: testIngestToken },
      ],
    });
    try {
      await recovered.runOnce();
    } finally {
      await recovered.close();
    }
    const finalState = await admin.query<{ physical_sequence: string; hosted_sequence: string; receipt_count: string }>(
      `SELECT
        (SELECT "lastAcknowledgedSequence"::text FROM public.audit_export_checkpoints WHERE "destinationId" = 'physical') AS physical_sequence,
        (SELECT "lastAcknowledgedSequence"::text FROM public.audit_export_checkpoints WHERE "destinationId" = 'hosted') AS hosted_sequence,
        (SELECT count(*)::text FROM public.audit_archive_receipts) AS receipt_count`,
    );
    expect(finalState.rows[0]).toEqual({ physical_sequence: sourceSequence, hosted_sequence: sourceSequence, receipt_count: "2" });
    const finalHealth = await admin.query<{ id: string; consecutiveFailures: number; lastErrorCategory: string | null; lastSucceededAt: Date | null }>(
      `SELECT "id", "consecutiveFailures", "lastErrorCategory", "lastSucceededAt"
         FROM public.audit_destinations ORDER BY "id"`,
    );
    expect(finalHealth.rows.find((row) => row.id === "physical")).toMatchObject({
      consecutiveFailures: 0, lastErrorCategory: null,
    });
    expect(finalHealth.rows.find((row) => row.id === "physical")?.lastSucceededAt).toBeInstanceOf(Date);

    await admin.query(`SELECT * FROM public.append_authorization_audit($1::jsonb)`, [
      JSON.stringify({ eventType: "export-integration", actorType: "SYSTEM", actorId: "metadata-failure-test", operation: "deliver", outcome: "recorded" }),
    ]);
    await admin.query(`REVOKE UPDATE ("consecutiveFailures", "lastErrorCategory", "updatedAt") ON public.audit_destinations FROM dbp_audit_exporter`);
    try {
      const unableToReport = createAuditExporter({
        exporterDatabaseUrl: exporterUrl,
        receiptVerifierUrl: `${verifierAddress}/v1/audit/receipts`,
        receiptVerifierServiceToken: testVerifierServiceToken,
        destinations: [
          { id: "physical", url: "http://127.0.0.1:1/v1/audit/batches", ingestToken: testIngestToken },
          { id: "hosted", url: `${hosted.address}/v1/audit/batches`, ingestToken: testIngestToken },
        ],
      });
      try {
        const report = await unableToReport.runOnce();
        expect(report.retryMetadataFailures).toContain("physical");
      } finally {
        await unableToReport.close();
      }
    } finally {
      await admin.query(`GRANT UPDATE ("consecutiveFailures", "lastErrorCategory", "updatedAt") ON public.audit_destinations TO dbp_audit_exporter`);
    }
  }, 30_000);

  afterAll(async () => {
    await Promise.all(servers.map((server) => server.close()));
    await Promise.all(dirs.map((dir) => rm(dir, { recursive: true, force: true })));
    await admin.end();
  });

  it("uses an explicitly isolated database URL", () => {
    expect(new URL(adminUrl!).pathname).toMatch(/^\/dbp_audit_test(?:_[a-z0-9]+)?$/);
  });
});
