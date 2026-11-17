import { Pool } from "pg";
import { afterAll, describe, expect, it } from "vitest";

const databaseUrl = process.env.DBP_AUDIT_TEST_DATABASE_URL;
const suite = databaseUrl ? describe : describe.skip;
const authorizationStreamId = "00000000-0000-0000-0000-000000000001";

if (databaseUrl && !/^\/dbp_audit_test(?:_[a-z0-9]+)?$/.test(new URL(databaseUrl).pathname)) {
  throw new Error("DBP_AUDIT_TEST_DATABASE_URL must point to a dedicated dbp_audit_test database");
}

suite("PostgreSQL audit foundation integration", () => {
  const pool = new Pool({ connectionString: databaseUrl, max: 12, application_name: "dbp-audit-integration-test" });

  afterAll(async () => { await pool.end(); });

  it("serializes concurrent appends and denies runtime direct mutation", async () => {
    const results = await Promise.all(Array.from({ length: 12 }, async (_, index) => {
      const client = await pool.connect();
      try {
        await client.query("SET ROLE dbp_runtime");
        const appended = await client.query<{ sequence: string; event_hash: Buffer }>(
          `SELECT "sequence"::text AS sequence, "eventHash" AS event_hash
             FROM public.append_authorization_audit($1::jsonb)`,
          [JSON.stringify({ eventType: "integration", actorType: "SYSTEM", actorId: `test-${index}`, operation: "test", outcome: "success" })],
        );
        expect(appended.rowCount).toBe(1);
        await expect(client.query('UPDATE public.authorization_audit_events SET "outcome" = \'tampered\'')).rejects.toThrow();
        await expect(client.query('DELETE FROM public.authorization_audit_events')).rejects.toThrow();
        await expect(client.query('UPDATE public.authorization_audit_heads SET "lastSequence" = 0')).rejects.toThrow();
        return appended.rows[0]!.sequence;
      } finally {
        await client.query("RESET ROLE");
        client.release();
      }
    }));
    expect(results.map(BigInt).sort((a, b) => a < b ? -1 : 1)).toEqual(
      Array.from({ length: 12 }, (_, index) => BigInt(index + 1)),
    );

    const verified = await pool.query<{ last_sequence: string; event_count: string }>(
      `SELECT h."lastSequence"::text AS last_sequence,
              (SELECT count(*)::text FROM public.authorization_audit_events e WHERE e."streamId" = h."streamId") AS event_count
         FROM public.authorization_audit_heads h WHERE h."streamId" = $1`, [authorizationStreamId],
    );
    expect(verified.rows[0]).toEqual({ last_sequence: "12", event_count: "12" });
    const serialized = await pool.query<{ payload: string }>(
      `SELECT "canonicalPayload" AS payload FROM public.authorization_audit_events ORDER BY "sequence" LIMIT 1`,
    );
    const payload = JSON.parse(serialized.rows[0]!.payload) as Record<string, unknown>;
    expect(payload.delegatingHumanId).toBeNull();
    expect(payload.callingClientId).toBeNull();
    expect(payload.permissionCode).toBeNull();
    expect(payload.occurredAt).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$/);
  });

  it("rolls back event and chain-head advancement if insertion fails", async () => {
    await pool.query(`CREATE FUNCTION public.audit_test_fail_after_insert() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION 'injected audit integration failure'; END $$`);
    await pool.query(`CREATE TRIGGER audit_test_fail_after_insert AFTER INSERT ON public.authorization_audit_events
      FOR EACH ROW EXECUTE FUNCTION public.audit_test_fail_after_insert()`);
    try {
      const before = await pool.query<{ last_sequence: string; event_count: string }>(
        `SELECT h."lastSequence"::text AS last_sequence,
                (SELECT count(*)::text FROM public.authorization_audit_events e WHERE e."streamId" = h."streamId") AS event_count
           FROM public.authorization_audit_heads h WHERE h."streamId" = $1`, [authorizationStreamId],
      );
      const client = await pool.connect();
      try {
        await client.query("SET ROLE dbp_runtime");
        await expect(client.query(
          `SELECT * FROM public.append_authorization_audit($1::jsonb)`,
          [JSON.stringify({ eventType: "integration", actorType: "SYSTEM", actorId: "rollback", operation: "test", outcome: "failure" })],
        )).rejects.toThrow(/injected audit integration failure/);
      } finally {
        await client.query("RESET ROLE");
        client.release();
      }
      const after = await pool.query<{ last_sequence: string; event_count: string }>(
        `SELECT h."lastSequence"::text AS last_sequence,
                (SELECT count(*)::text FROM public.authorization_audit_events e WHERE e."streamId" = h."streamId") AS event_count
           FROM public.authorization_audit_heads h WHERE h."streamId" = $1`, [authorizationStreamId],
      );
      expect(after.rows).toEqual(before.rows);
    } finally {
      await pool.query("DROP TRIGGER audit_test_fail_after_insert ON public.authorization_audit_events");
      await pool.query("DROP FUNCTION public.audit_test_fail_after_insert()");
    }
  });

  it("prepares an exact, idempotent source batch and denies exporter batch writes", async () => {
    const exporter = await pool.connect();
    let prepared: { batch_id: string; first_sequence: string; last_sequence: string; event_count: number; canonical_batch: string };
    try {
      await exporter.query("SET ROLE dbp_audit_exporter");
      const result = await exporter.query<typeof prepared>(
        `SELECT batch_id, first_sequence::text AS first_sequence, last_sequence::text AS last_sequence,
                event_count, canonical_batch
           FROM public.prepare_authorization_audit_batch($1, 1, 100)`,
        [authorizationStreamId],
      );
      expect(result.rowCount).toBe(1);
      prepared = result.rows[0]!;
      const repeated = await exporter.query<{ batch_id: string; canonical_batch: string }>(
        `SELECT batch_id, canonical_batch FROM public.prepare_authorization_audit_batch($1, 1, 1)`,
        [authorizationStreamId],
      );
      expect(repeated.rows[0]).toEqual({ batch_id: prepared.batch_id, canonical_batch: prepared.canonical_batch });

      const wire = JSON.parse(prepared.canonical_batch) as {
        streamId: string; firstSequence: string; lastSequence: string; eventCount: number;
        previousHash: string; terminalEventHash: string; batchHash: string;
        events: Array<{ sequence: string; canonicalPayload: string; previousHash: string; eventHash: string }>;
      };
      const actual = await pool.query<{ sequence: string; canonicalPayload: string; previousHash: Buffer; eventHash: Buffer }>(
        `SELECT "sequence"::text AS sequence, "canonicalPayload", "previousHash", "eventHash"
           FROM public.authorization_audit_events e WHERE e."streamId" = $1
            AND e."sequence" BETWEEN $2::bigint AND $3::bigint ORDER BY e."sequence"`,
        [authorizationStreamId, prepared.first_sequence, prepared.last_sequence],
      );
      expect(wire.streamId).toBe(authorizationStreamId);
      expect(wire.firstSequence).toBe(prepared.first_sequence);
      expect(wire.lastSequence).toBe(prepared.last_sequence);
      expect(wire.eventCount).toBe(prepared.event_count);
      expect(wire.events).toEqual(actual.rows.map((event) => ({
        sequence: event.sequence,
        canonicalPayload: event.canonicalPayload,
        previousHash: event.previousHash.toString("hex"),
        eventHash: event.eventHash.toString("hex"),
      })));
      expect(wire.terminalEventHash).toBe(actual.rows.at(-1)!.eventHash.toString("hex"));
      expect(wire.previousHash).toBe(actual.rows[0]!.previousHash.toString("hex"));

      await expect(exporter.query(
        `INSERT INTO public.audit_export_batches
          ("id", "streamId", "firstSequence", "lastSequence", "eventCount", "previousHash", "terminalEventHash", "batchHash", "canonicalBatch")
         VALUES (gen_random_uuid(), $1, 90, 90, 1, decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'), '{}')`,
        [authorizationStreamId],
      )).rejects.toThrow(/permission denied/);
      await expect(exporter.query(
        `INSERT INTO public.audit_export_deliveries ("batchId", "destinationId") VALUES ($1, 'physical')`,
        [prepared.batch_id],
      )).rejects.toThrow(/permission denied/);
      await expect(exporter.query(
        `UPDATE public.audit_export_batches SET "terminalEventHash" = decode(repeat('ff', 32), 'hex') WHERE "id" = $1`,
        [prepared.batch_id],
      )).rejects.toThrow(/permission denied/);
      await expect(exporter.query(
        `DELETE FROM public.audit_export_batches WHERE "id" = $1`, [prepared.batch_id],
      )).rejects.toThrow(/permission denied/);
      await expect(exporter.query(
        `INSERT INTO public.audit_export_deliveries ("batchId", "destinationId", "status") VALUES ($1, 'physical', 'ACKNOWLEDGED')`,
        [prepared.batch_id],
      )).rejects.toThrow(/permission denied/);
      await expect(exporter.query(
        `SELECT * FROM public.prepare_authorization_audit_batch($1, 99, 100)`, [authorizationStreamId],
      )).rejects.toThrow(/not the next source range|does not immediately follow/);
      await expect(exporter.query(
        `SELECT * FROM public.prepare_authorization_audit_batch($1, 1, NULL::integer)`, [authorizationStreamId],
      )).rejects.toThrow(/Batch event limit must be between 1 and 1000/);
      await expect(exporter.query(
        `SELECT public.record_verified_audit_receipt(gen_random_uuid(), 'physical', '{}', decode(repeat('00', 64), 'hex'))`,
      )).rejects.toThrow(/permission denied/);
    } finally {
      await exporter.query("RESET ROLE");
      exporter.release();
    }

    const runtime = await pool.connect();
    try {
      await runtime.query("SET ROLE dbp_runtime");
      await expect(runtime.query(
        `SELECT * FROM public.prepare_authorization_audit_batch($1, 1, 100)`, [authorizationStreamId],
      )).rejects.toThrow(/permission denied/);
      await expect(runtime.query(
        `SELECT public.record_verified_audit_receipt(gen_random_uuid(), 'physical', '{}', decode(repeat('00', 64), 'hex'))`,
      )).rejects.toThrow(/permission denied/);
    } finally {
      await runtime.query("RESET ROLE");
      runtime.release();
    }

    const verifier = await pool.connect();
    try {
      await verifier.query("SET ROLE dbp_audit_receipt_verifier");
      const privileges = await verifier.query<{
        can_record: boolean;
        can_insert_batches: boolean;
        can_insert_receipts: boolean;
        can_update_deliveries: boolean;
        can_update_checkpoints: boolean;
      }>(
        `SELECT has_function_privilege(current_user, 'public.record_verified_audit_receipt(uuid,text,text,bytea)', 'EXECUTE') AS can_record,
                has_table_privilege(current_user, 'public.audit_export_batches', 'INSERT') AS can_insert_batches,
                has_table_privilege(current_user, 'public.audit_archive_receipts', 'INSERT') AS can_insert_receipts,
                has_table_privilege(current_user, 'public.audit_export_deliveries', 'UPDATE') AS can_update_deliveries,
                has_table_privilege(current_user, 'public.audit_export_checkpoints', 'UPDATE') AS can_update_checkpoints`,
      );
      expect(privileges.rows[0]).toEqual({
        can_record: true,
        can_insert_batches: false,
        can_insert_receipts: false,
        can_update_deliveries: false,
        can_update_checkpoints: false,
      });
    } finally {
      await verifier.query("RESET ROLE");
      verifier.release();
    }
  });

  it("rejects invalid stored hashes and sequence gaps before preparing a batch", async () => {
    const streamId = "00000000-0000-0000-0000-000000000002";
    await pool.query(`INSERT INTO public.authorization_audit_streams ("id", "name") VALUES ($1, 'audit-provenance-test')`, [streamId]);
    await pool.query(
      `INSERT INTO public.authorization_audit_heads ("streamId", "lastSequence", "lastEventHash") VALUES ($1, 0, decode(repeat('00', 32), 'hex'))`,
      [streamId],
    );
    await pool.query(
      `INSERT INTO public.audit_export_checkpoints ("streamId", "destinationId", "lastAcknowledgedSequence", "lastAcknowledgedEventHash")
       SELECT $1, "id", 0, decode(repeat('00', 32), 'hex') FROM public.audit_destinations`,
      [streamId],
    );
    const runtime = await pool.connect();
    try {
      await runtime.query("SET ROLE dbp_runtime");
      for (let index = 1; index <= 3; index += 1) {
        await runtime.query(
          `SELECT public.append_authorization_audit($1::jsonb, $2::uuid)`,
          [JSON.stringify({ eventType: "provenance-test", actorType: "SYSTEM", actorId: `gap-${index}`, operation: "test", outcome: "recorded" }), streamId],
        );
      }
    } finally {
      await runtime.query("RESET ROLE");
      runtime.release();
    }
    const original = await pool.query<{ event_hash: Buffer }>(
      `SELECT "eventHash" AS event_hash FROM public.authorization_audit_events WHERE "streamId" = $1 AND "sequence" = 2`,
      [streamId],
    );
    await pool.query(`ALTER TABLE public.authorization_audit_events DISABLE TRIGGER authorization_audit_events_immutable`);
    try {
      await pool.query(
        `UPDATE public.authorization_audit_events SET "eventHash" = decode(repeat('ff', 32), 'hex') WHERE "streamId" = $1 AND "sequence" = 2`,
        [streamId],
      );
      const hashExporter = await pool.connect();
      try {
        await hashExporter.query("SET ROLE dbp_audit_exporter");
        await expect(hashExporter.query(
          `SELECT * FROM public.prepare_authorization_audit_batch($1, 1, 3)`, [streamId],
        )).rejects.toThrow(/Stored audit event hash is invalid/);
      } finally {
        await hashExporter.query("RESET ROLE");
        hashExporter.release();
      }

      await pool.query(
        `UPDATE public.authorization_audit_events SET "eventHash" = $2 WHERE "streamId" = $1 AND "sequence" = 2`,
        [streamId, original.rows[0]!.event_hash],
      );
      await pool.query(
        `UPDATE public.authorization_audit_events SET "sequence" = 22 WHERE "streamId" = $1 AND "sequence" = 2`,
        [streamId],
      );
      const gapExporter = await pool.connect();
      try {
        await gapExporter.query("SET ROLE dbp_audit_exporter");
        await expect(gapExporter.query(
          `SELECT * FROM public.prepare_authorization_audit_batch($1, 1, 3)`, [streamId],
        )).rejects.toThrow(/sequence gap/);
      } finally {
        await gapExporter.query("RESET ROLE");
        gapExporter.release();
      }
    } finally {
      await pool.query(
        `UPDATE public.authorization_audit_events SET "sequence" = 2, "eventHash" = $2 WHERE "streamId" = $1 AND "sequence" IN (2, 22)`,
        [streamId, original.rows[0]!.event_hash],
      );
      await pool.query(`ALTER TABLE public.authorization_audit_events ENABLE TRIGGER authorization_audit_events_immutable`);
    }
    const noFabricatedRows = await pool.query(
      `SELECT count(*)::int AS count FROM public.audit_export_batches WHERE "streamId" = $1`, [streamId],
    );
    expect(noFabricatedRows.rows[0].count).toBe(0);
  });

  it("prepares a consistent range without blocking a concurrent audit append", async () => {
    const streamId = "00000000-0000-0000-0000-000000000003";
    await pool.query(`INSERT INTO public.authorization_audit_streams ("id", "name") VALUES ($1, 'audit-batch-concurrency-test')`, [streamId]);
    await pool.query(
      `INSERT INTO public.authorization_audit_heads ("streamId", "lastSequence", "lastEventHash") VALUES ($1, 0, decode(repeat('00', 32), 'hex'))`,
      [streamId],
    );
    await pool.query(
      `INSERT INTO public.audit_export_checkpoints ("streamId", "destinationId", "lastAcknowledgedSequence", "lastAcknowledgedEventHash")
       SELECT $1, "id", 0, decode(repeat('00', 32), 'hex') FROM public.audit_destinations`,
      [streamId],
    );
    const runtime = await pool.connect();
    try {
      await runtime.query("SET ROLE dbp_runtime");
      await runtime.query(
        `SELECT public.append_authorization_audit($1::jsonb, $2::uuid)`,
        [JSON.stringify({ eventType: "batch-race", actorType: "SYSTEM", actorId: "before", operation: "test", outcome: "recorded" }), streamId],
      );
    } finally {
      await runtime.query("RESET ROLE");
      runtime.release();
    }
    const exporter = await pool.connect();
    try {
      await exporter.query("SET ROLE dbp_audit_exporter");
      await exporter.query(`SELECT * FROM public.prepare_authorization_audit_batch($1, 1, 10)`, [streamId]);
    } finally {
      await exporter.query("RESET ROLE");
      exporter.release();
    }

    const appender = await pool.connect();
    let preparation: Promise<{ rowCount: number | null }> | undefined;
    try {
      await appender.query("BEGIN");
      await appender.query("SET ROLE dbp_runtime");
      await appender.query(
        `SELECT public.append_authorization_audit($1::jsonb, $2::uuid)`,
        [JSON.stringify({ eventType: "batch-race", actorType: "SYSTEM", actorId: "uncommitted", operation: "test", outcome: "recorded" }), streamId],
      );

      const concurrent = await pool.connect();
      try {
        await concurrent.query("SET ROLE dbp_audit_exporter");
        preparation = concurrent.query(
          `SELECT * FROM public.prepare_authorization_audit_batch($1, 2, 10)`, [streamId],
        ).finally(() => concurrent.release());
        const completed = await Promise.race([
          preparation.then(() => true),
          new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 1000)),
        ]);
        if (!completed) throw new Error("Batch preparation blocked on an uncommitted append");
      } finally {
        if (!preparation) concurrent.release();
      }
      await appender.query("COMMIT");
    } catch (error) {
      await appender.query("ROLLBACK");
      if (preparation) await preparation;
      throw error;
    } finally {
      await appender.query("RESET ROLE");
      appender.release();
    }

    const exporterAfterCommit = await pool.connect();
    try {
      await exporterAfterCommit.query("SET ROLE dbp_audit_exporter");
      const result = await exporterAfterCommit.query<{ canonical_batch: string }>(
        `SELECT canonical_batch FROM public.prepare_authorization_audit_batch($1, 2, 10)`, [streamId],
      );
      const wire = JSON.parse(result.rows[0]!.canonical_batch) as { events: Array<{ sequence: string }> };
      expect(wire.events.map((event) => event.sequence)).toEqual(["2"]);
    } finally {
      await exporterAfterCommit.query("RESET ROLE");
      exporterAfterCommit.release();
    }
  });
});
