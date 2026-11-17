import { createHmac, generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createAuditArchive } from "@platform/audit-archive";
import { createAuditReceiptVerifier } from "@platform/audit-receipt-verifier";
import { createAuditExporter } from "./audit-exporter.js";
import { createCriticalOperationService, createCriticalOperationWorker } from "./critical-operations.js";

const adminUrl = process.env.DBP_AUDIT_TEST_DATABASE_URL;
const suite = adminUrl ? describe : describe.skip;
if (adminUrl && !/^\/dbp_audit_test(?:_[a-z0-9]+)?$/.test(new URL(adminUrl).pathname)) {
  throw new Error("DBP_AUDIT_TEST_DATABASE_URL must point to a dedicated disposable dbp_audit_test database");
}

suite("critical-operation PostgreSQL 17 and archive integration", () => {
  const admin = new Pool({ connectionString: adminUrl, max: 8, application_name: "dbp-critical-operation-test-admin" });
  const keys = generateKeyPairSync("ed25519");
  const ingestToken = "critical-operation-test-ingest-token-with-256-bits-entropy";
  const verifierToken = "critical-operation-test-verifier-token-with-256-bits-entropy";
  const dirs: string[] = [];
  const closeables: Array<{ close: () => Promise<void> }> = [];
  let archiveAddress = "";
  let verifierAddress = "";
  let service: ReturnType<typeof createCriticalOperationService>;
  let runtime: Pool;
  let reconciler: Pool;
  let exporterUrl = "";
  let runtimeUrl = "";
  let criticalUrl = "";

  async function roleUrl(role: string, parent: string): Promise<string> {
    await admin.query(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${role}') THEN CREATE ROLE ${role} LOGIN; END IF; END $$`);
    await admin.query(`GRANT ${parent} TO ${role}`);
    const url = new URL(adminUrl!);
    url.username = role;
    url.password = "";
    return url.toString();
  }

  async function deliverPhysical() {
    const exporter = createAuditExporter({
      exporterDatabaseUrl: exporterUrl,
      receiptVerifierUrl: `${verifierAddress}/v1/audit/receipts`,
      receiptVerifierServiceToken: verifierToken,
      destinations: [
        { id: "physical", url: `${archiveAddress}/v1/audit/batches`, ingestToken },
        { id: "hosted", url: "http://127.0.0.1:1/v1/audit/batches", ingestToken },
      ],
    });
    try { return await exporter.runOnce(); } finally { await exporter.close(); }
  }

  beforeAll(async () => {
    const version = await admin.query<{ server_version_num: string }>("SHOW server_version_num");
    if (Number(version.rows[0]!.server_version_num) < 170000) throw new Error("Critical-operation integration tests require PostgreSQL 17");
    criticalUrl = await roleUrl("dbp_critical_operation_test", "dbp_critical_operation_service");
    exporterUrl = await roleUrl("dbp_critical_exporter_test", "dbp_audit_exporter");
    runtimeUrl = await roleUrl("dbp_critical_runtime_test", "dbp_runtime");
    const reconcilerUrl = await roleUrl("dbp_critical_reconciler_test", "dbp_critical_operation_reconciler");
    service = createCriticalOperationService(criticalUrl);
    runtime = new Pool({ connectionString: runtimeUrl, max: 2 });
    reconciler = new Pool({ connectionString: reconcilerUrl, max: 2 });

    const archiveDir = await mkdtemp(join(tmpdir(), "dbp-critical-archive-"));
    dirs.push(archiveDir);
    const archive = await createAuditArchive({ destinationId: "physical", receiptKeyId: "physical-critical-test-key", signingPrivateKey: keys.privateKey, ingestToken, storageDirectory: archiveDir });
    closeables.push(archive);
    archiveAddress = await archive.listen({ host: "127.0.0.1", port: 0 });
    const verifier = await createAuditReceiptVerifier({
      databaseUrl: await roleUrl("dbp_critical_verifier_test", "dbp_audit_receipt_verifier"),
      serviceToken: verifierToken,
      trustedReceiptKeys: new Map([["physical", new Map([["physical-critical-test-key", keys.publicKey]])]]),
    });
    closeables.push(verifier);
    verifierAddress = await verifier.listen({ host: "127.0.0.1", port: 0 });
  });

  afterAll(async () => {
    await service?.close();
    await runtime?.end();
    await reconciler?.end();
    await Promise.all(closeables.reverse().map((app) => app.close()));
    await admin.end();
    await Promise.all(dirs.map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it("resumes idempotently, waits for an independent receipt, retries after restart, and activates atomically", async () => {
    const idempotencyKey = "activation-key-".padEnd(40, "x");
    const request = { scope: "integration-test" };
    const input = { operationType: "test.activation", targetType: "test-target", targetId: "activation-one", idempotencyKey, canonicalRequest: request };
    const [first, duplicate, concurrent] = await Promise.all([
      service.prepareActivation(input), service.prepareActivation(input), service.prepareActivation(input),
    ]);
    expect(first).toBe(duplicate);
    expect(first).toBe(concurrent);
    await expect(service.prepareActivation({ ...input, canonicalRequest: { scope: "different" } })).rejects.toThrow(/IDEMPOTENCY_CONFLICT/);
    expect((await runtime.query("SELECT public.critical_operation_target_is_active($1,$2) AS active", ["test-target", "activation-one"])).rows[0]!.active).toBe(false);

    await service.advance(); // durable PREPARED -> AWAITING_ARCHIVE and ready audit event
    const waiting = await admin.query<{ status: string }>("SELECT status FROM public.critical_operations WHERE id=$1", [first]);
    expect(waiting.rows[0]!.status).toBe("AWAITING_ARCHIVE");
    const exporter = new Pool({ connectionString: exporterUrl, max: 1 });
    try {
      await exporter.query("SELECT * FROM public.prepare_authorization_audit_batch($1::uuid,$2::bigint,$3::integer)", ["00000000-0000-0000-0000-000000000001", 1, 100]);
      const delivery = await exporter.query<{ status: string }>("SELECT status FROM public.audit_export_deliveries WHERE \"destinationId\"='physical'");
      expect(delivery.rows[0]!.status).toBe("PENDING");
      await expect(exporter.query("UPDATE public.audit_export_deliveries SET status='ACKNOWLEDGED' WHERE \"destinationId\"='physical'")).rejects.toThrow();
    } finally { await exporter.end(); }
    await expect(service.advance()).resolves.toBeGreaterThanOrEqual(0);
    expect((await admin.query("SELECT public.critical_operation_target_is_active($1,$2) AS active", ["test-target", "activation-one"])).rows[0]!.active).toBe(false);

    await deliverPhysical(); // a real archive accepts and signs; verifier validates and records the receipt
    const receipts = await admin.query<{ count: string }>("SELECT count(*)::text AS count FROM public.audit_archive_receipts WHERE \"destinationId\"='physical'");
    expect(Number(receipts.rows[0]!.count)).toBeGreaterThan(0);

    // A fresh service pool models a restarted worker reading the persisted row.
    await service.close();
    service = createCriticalOperationService(criticalUrl);
    const restartedWorker = createCriticalOperationWorker(criticalUrl);
    const concurrentWorker = createCriticalOperationWorker(criticalUrl);
    try {
      await restartedWorker.runOnce();
      const ready = await admin.query<{ status: string }>("SELECT status FROM public.critical_operations WHERE id=$1", [first]);
      expect(ready.rows[0]!.status).toBe("READY_TO_ACTIVATE");
      await Promise.all([restartedWorker.runOnce(), concurrentWorker.runOnce()]);
    } finally {
      await Promise.all([restartedWorker.close(), concurrentWorker.close()]);
    }
    const completed = await admin.query<{ status: string; receipt: string | null; seq: string | null }>(
      "SELECT status, \"qualifyingDestinationId\" AS receipt, \"completionSequence\"::text AS seq FROM public.critical_operations WHERE id=$1", [first],
    );
    expect(completed.rows[0]).toMatchObject({ status: "COMPLETED", receipt: "physical" });
    expect(completed.rows[0]!.seq).not.toBeNull();
    expect((await runtime.query("SELECT public.critical_operation_target_is_active($1,$2) AS active", ["test-target", "activation-one"])).rows[0]!.active).toBe(true);
    await expect(service.prepareActivation(input)).resolves.toBe(first);
    await service.advance();
    const completionEvents = await admin.query<{ count: string }>("SELECT count(*)::text AS count FROM public.authorization_audit_events WHERE \"eventType\"='critical-operation-completed' AND \"correlationId\"=$1", [first]);
    expect(completionEvents.rows[0]!.count).toBe("1");
  });

  it("enforces one open operation per target even with different concurrent idempotency keys", async () => {
    const results = await Promise.allSettled([
      service.prepareActivation({ operationType: "test.activation", targetType: "test-target", targetId: "single-open", idempotencyKey: "open-a-".padEnd(40, "a"), canonicalRequest: { v: 1 } }),
      service.prepareActivation({ operationType: "test.activation", targetType: "test-target", targetId: "single-open", idempotencyKey: "open-b-".padEnd(40, "b"), canonicalRequest: { v: 1 } }),
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    const rows = await admin.query<{ count: string }>("SELECT count(*)::text AS count FROM public.critical_operations WHERE \"targetType\"='test-target' AND \"targetId\"='single-open'");
    expect(rows.rows[0]!.count).toBe("1");
  });

  it("rolls back activation and completion audit together and makes revocation immediate", async () => {
    const activation = await service.prepareActivation({ operationType: "test.activation", targetType: "test-target", targetId: "rollback-one", idempotencyKey: "rollback-key-".padEnd(40, "x"), canonicalRequest: { v: 1 } });
    await service.advance();
    await deliverPhysical();
    await service.advance(); // independently durable READY_TO_ACTIVATE checkpoint
    await admin.query(`CREATE FUNCTION public.test_fail_critical_completion() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW."eventType"='critical-operation-completed' THEN RAISE EXCEPTION 'injected test failure'; END IF; RETURN NEW; END $$`);
    await admin.query(`CREATE TRIGGER test_fail_critical_completion BEFORE INSERT ON public.authorization_audit_events FOR EACH ROW EXECUTE FUNCTION public.test_fail_critical_completion()`);
    await expect(service.advance()).rejects.toThrow(/injected test failure/);
    await admin.query("DROP TRIGGER test_fail_critical_completion ON public.authorization_audit_events");
    await admin.query("DROP FUNCTION public.test_fail_critical_completion()");
    const rolledBack = await admin.query<{ status: string; state: string }>("SELECT o.status,g.state FROM public.critical_operations o JOIN public.critical_operation_gates g USING (\"targetType\",\"targetId\") WHERE o.id=$1", [activation]);
    expect(rolledBack.rows[0]).toEqual({ status: "READY_TO_ACTIVATE", state: "PROPOSED" });
    await service.advance();
    expect((await runtime.query("SELECT public.critical_operation_target_is_active($1,$2) AS active", ["test-target", "rollback-one"])).rows[0]!.active).toBe(true);

    const revoke = await service.requestRevocation({ operationType: "test.revocation", targetType: "test-target", targetId: "activation-one", idempotencyKey: "revoke-key-".padEnd(40, "x"), canonicalRequest: { reasonCode: "test" } });
    expect((await runtime.query("SELECT public.critical_operation_target_is_active($1,$2) AS active", ["test-target", "activation-one"])).rows[0]!.active).toBe(false);
    await expect(service.requestRevocation({ operationType: "test.revocation", targetType: "test-target", targetId: "activation-one", idempotencyKey: "revoke-key-".padEnd(40, "x"), canonicalRequest: { reasonCode: "test" } })).resolves.toBe(revoke);
    await service.advance();
    const pending = await admin.query<{ status: string; state: string }>("SELECT o.status,g.state FROM public.critical_operations o JOIN public.critical_operation_gates g USING (\"targetType\",\"targetId\") WHERE o.id=$1", [revoke]);
    expect(pending.rows[0]).toEqual({ status: "REVOCATION_PENDING_ARCHIVE", state: "REVOKED" });
    await deliverPhysical();
    await service.advance();
    const final = await admin.query<{ status: string; state: string }>("SELECT o.status,g.state FROM public.critical_operations o JOIN public.critical_operation_gates g USING (\"targetType\",\"targetId\") WHERE o.id=$1", [revoke]);
    expect(final.rows[0]).toEqual({ status: "COMPLETED", state: "REVOKED" });
  });

  it("serializes sensitive use against revocation and denies direct runtime writes", async () => {
    const id = await service.prepareActivation({ operationType: "test.activation", targetType: "test-target", targetId: "locking-one", idempotencyKey: "locking-key-".padEnd(40, "x"), canonicalRequest: { v: 1 } });
    await service.advance();
    await deliverPhysical();
    await service.advance();
    await service.advance();
    expect((await runtime.query("SELECT public.critical_operation_target_is_active($1,$2) AS active", ["test-target", "locking-one"])).rows[0]!.active).toBe(true);

    const transaction = await runtime.connect();
    try {
      await transaction.query("BEGIN");
      expect((await transaction.query("SELECT public.critical_operation_target_is_active($1,$2) AS active", ["test-target", "locking-one"])).rows[0]!.active).toBe(true);
      await transaction.query("SELECT * FROM public.append_authorization_audit($1::jsonb)", [JSON.stringify({ eventType: "critical-use-test", actorType: "SYSTEM", actorId: "test-runtime", targetType: "test-target", targetId: "locking-one", operation: "use", outcome: "allowed" })]);
      const revokePromise = service.requestRevocation({ operationType: "test.revocation", targetType: "test-target", targetId: "locking-one", idempotencyKey: "locking-revoke-".padEnd(40, "x"), canonicalRequest: { reasonCode: "test" } });
      let resolved = false;
      void revokePromise.then(() => { resolved = true; });
      await new Promise((resolve) => setTimeout(resolve, 75));
      expect(resolved).toBe(false);
      await transaction.query("COMMIT");
      await expect(revokePromise).resolves.toBeTruthy();
    } finally { transaction.release(); }
    expect((await runtime.query("SELECT public.critical_operation_target_is_active($1,$2) AS active", ["test-target", "locking-one"])).rows[0]!.active).toBe(false);
    await expect(runtime.query("UPDATE public.critical_operation_gates SET state='ACTIVE' WHERE \"targetType\"='test-target' AND \"targetId\"='locking-one'")).rejects.toThrow();
    await expect(runtime.query("SELECT public.finalize_critical_operation($1)", [id])).rejects.toThrow();
    await expect(runtime.query("SELECT public.mark_critical_operation_reconciliation($1,'manual_review',$2::jsonb)", [id, JSON.stringify({ reasonCode: "review" })])).rejects.toThrow();
    const servicePrivileges = await admin.query<{ update_operations: boolean; finalize: boolean; reconcile: boolean }>(
      `SELECT has_table_privilege('dbp_critical_operation_service','public.critical_operations','UPDATE') AS update_operations,
              has_function_privilege('dbp_critical_operation_service','public.finalize_critical_operation(uuid)','EXECUTE') AS finalize,
              has_function_privilege('dbp_critical_operation_service','public.mark_critical_operation_reconciliation(uuid,text,jsonb)','EXECUTE') AS reconcile`,
    );
    expect(servicePrivileges.rows[0]).toEqual({ update_operations: false, finalize: true, reconcile: false });
  });

  it("reconciles inconsistencies explicitly and can only close them without activation", async () => {
    const id = await service.prepareActivation({ operationType: "test.activation", targetType: "test-target", targetId: "reconcile-one", idempotencyKey: "reconcile-key-".padEnd(40, "x"), canonicalRequest: { v: 1 } });
    await expect(reconciler.query("SELECT public.mark_critical_operation_reconciliation($1,'manual_review',$2::jsonb)", [id, JSON.stringify({ password: "must-not-persist" })])).rejects.toThrow();
    await reconciler.query("SELECT public.mark_critical_operation_reconciliation($1,'manual_review',$2::jsonb)", [id, JSON.stringify({ reasonCode: "operator_review" })]);
    await expect(reconciler.query("SELECT public.mark_critical_operation_reconciliation($1,'manual_review',$2::jsonb)", [id, JSON.stringify({ reasonCode: "operator_review" })])).resolves.toBeTruthy();
    await expect(reconciler.query("SELECT public.mark_critical_operation_reconciliation($1,'different_reason',$2::jsonb)", [id, JSON.stringify({ reasonCode: "operator_review" })])).rejects.toThrow(/RECONCILIATION_CONFLICT/);
    const pending = await admin.query<{ status: string; state: string }>("SELECT o.status,g.state FROM public.critical_operations o JOIN public.critical_operation_gates g USING (\"targetType\",\"targetId\") WHERE o.id=$1", [id]);
    expect(pending.rows[0]).toEqual({ status: "RECONCILIATION_REQUIRED", state: "PROPOSED" });
    expect((await runtime.query("SELECT public.critical_operation_target_is_active($1,$2) AS active", ["test-target", "reconcile-one"])).rows[0]!.active).toBe(false);
    await reconciler.query("SELECT public.resolve_critical_operation_reconciliation($1,'operator_reviewed_failed')", [id]);
    await expect(reconciler.query("SELECT public.resolve_critical_operation_reconciliation($1,'operator_reviewed_failed')", [id])).resolves.toBeTruthy();
    const resolved = await admin.query<{ status: string; state: string }>("SELECT o.status,g.state FROM public.critical_operations o JOIN public.critical_operation_gates g USING (\"targetType\",\"targetId\") WHERE o.id=$1", [id]);
    expect(resolved.rows[0]).toEqual({ status: "FAILED", state: "INACTIVE" });
    const audit = await admin.query<{ count: string }>("SELECT count(*)::text AS count FROM public.authorization_audit_events WHERE \"correlationId\"=$1 AND \"eventType\" IN ('critical-operation-reconciliation-required','critical-operation-reconciliation-resolved')", [id]);
    expect(audit.rows[0]!.count).toBe("2");
  });

  it("rejects missing, inactive, unverified, wrong-issuer, and differently-owned bootstrap identities", async () => {
    const operatorUrl=await roleUrl("dbp_owner_bootstrap_operator_test","dbp_platform_owner_operator");
    const identityOperatorUrl=await roleUrl("dbp_identity_link_operator_test","dbp_identity_link_operator");
    const identityCallbackUrl=await roleUrl("dbp_identity_link_callback_test","dbp_identity_link_callback");
    const operator=new Pool({connectionString:operatorUrl,max:1});
    const identityOperator=new Pool({connectionString:identityOperatorUrl,max:1});
    const identityCallback=new Pool({connectionString:identityCallbackUrl,max:1});
    const verifier=Buffer.alloc(32,0x24);
    const issue=async(userId:string,issuer="https://issuer.example.test/realm")=>operator.query(
      "SELECT public.issue_platform_owner_bootstrap_credential($1::uuid,$2::uuid,$3,$4,$5)",
      [randomUUID(),userId,issuer,"test-key-v1",verifier],
    );
    const createUser=async(status="ACTIVE")=>{
      const id=randomUUID();
      await admin.query(`INSERT INTO public.platform_users(id,"displayName",status,"createdAt","updatedAt") VALUES($1,'Test owner',$2,clock_timestamp(),clock_timestamp())`,[id,status]);
      return id;
    };
    try{
      const authority=await admin.query<{owner_operator_login:boolean;critical_service_is_operator:boolean;critical_service_can_issue:boolean;runtime_can_prepare:boolean;operator_can_finalize:boolean}>(
        `SELECT (SELECT rolcanlogin FROM pg_roles WHERE rolname='dbp_platform_owner_operator') AS owner_operator_login,
                pg_has_role('dbp_critical_operation_service','dbp_platform_owner_operator','member') AS critical_service_is_operator,
                has_function_privilege('dbp_critical_operation_service','public.issue_platform_owner_bootstrap_credential(uuid,uuid,text,text,bytea)','EXECUTE') AS critical_service_can_issue,
                has_function_privilege('dbp_runtime','public.prepare_platform_owner_bootstrap(uuid,uuid,bytea)','EXECUTE') AS runtime_can_prepare,
                has_function_privilege('dbp_owner_bootstrap_operator_test','public.finalize_critical_operation(uuid)','EXECUTE') AS operator_can_finalize`,
      );
      expect(authority.rows[0]).toEqual({owner_operator_login:false,critical_service_is_operator:false,critical_service_can_issue:false,runtime_can_prepare:false,operator_can_finalize:false});
      await expect(issue(randomUUID())).rejects.toThrow(/ACTIVE_PLATFORM_USER_REQUIRED/);
      const suspended=await createUser("SUSPENDED");
      await expect(issue(suspended)).rejects.toThrow(/ACTIVE_PLATFORM_USER_REQUIRED/);
      const unverified=await createUser();
      await admin.query("SET session_replication_role=replica");
      try{
        await admin.query(`INSERT INTO public.user_identities(id,"userId",issuer,subject,email,"emailVerified","createdAt","updatedAt")
          VALUES($1,$2,'https://issuer.example.test/realm','email-only-subject','owner@example.test',true,clock_timestamp(),clock_timestamp())`,[randomUUID(),unverified]);
      }finally{await admin.query("SET session_replication_role=origin");}
      await expect(issue(unverified)).rejects.toThrow(/VERIFIED_IDENTITY_REQUIRED/);

      const identityOwner=await createUser();
      const otherUser=await createUser();
      const challenge=(await identityOperator.query<{id:string}>(
        "SELECT public.begin_platform_identity_link($1::uuid,$2) AS id",[identityOwner,"https://issuer.example.test/realm"],
      )).rows[0]!.id;
      await identityCallback.query("SELECT public.complete_platform_identity_link($1::uuid,$2::uuid,$3,$4,$5)",
        [challenge,identityOwner,"https://issuer.example.test/realm","owned-by-someone-else",new Date()]);
      await expect(issue(otherUser)).rejects.toThrow(/VERIFIED_IDENTITY_REQUIRED/);
      await expect(issue(identityOwner,"https://wrong.example.test/issuer")).rejects.toThrow(/VERIFIED_IDENTITY_REQUIRED/);
    }finally{
      await Promise.all([operator.end(),identityOperator.end(),identityCallback.end()]);
    }
  });

  it("activates an initial owner only through the receipt-gated critical finalizer", async () => {
    const operatorUrl=await roleUrl("dbp_owner_bootstrap_operator_test","dbp_platform_owner_operator");
    const identityOperatorUrl=await roleUrl("dbp_identity_link_operator_test","dbp_identity_link_operator");
    const identityCallbackUrl=await roleUrl("dbp_identity_link_callback_test","dbp_identity_link_callback");
    const userId=randomUUID();
    await admin.query(`INSERT INTO public.platform_users(id,"displayName","createdAt","updatedAt") VALUES($1,'Bootstrap owner',clock_timestamp(),clock_timestamp())`,[userId]);
    const identityOperator=new Pool({connectionString:identityOperatorUrl,max:1});
    const identityCallback=new Pool({connectionString:identityCallbackUrl,max:1});
    const ownerOperator=new Pool({connectionString:operatorUrl,max:2});
    try{
      const challenge=(await identityOperator.query<{id:string}>(
        "SELECT public.begin_platform_identity_link($1::uuid,$2) AS id",
        [userId,"https://issuer.example.test/realm"],
      )).rows[0]!.id;
      await expect(identityCallback.query("SELECT * FROM public.get_platform_identity_link_confirmation($1::uuid)",[challenge]))
        .resolves.toMatchObject({rows:[{platform_user_id:userId}]});
      await expect(identityCallback.query(
        "SELECT public.complete_platform_identity_link($1::uuid,$2::uuid,$3,$4,$5)",
        [challenge,userId,"https://issuer.example.test/realm","bootstrap-owner-subject",new Date()],
      )).resolves.toBeTruthy();
      const credentialId=randomUUID();
      const verifier=Buffer.alloc(32,0x42);
      await ownerOperator.query(
        "SELECT public.issue_platform_owner_bootstrap_credential($1::uuid,$2::uuid,$3,$4,$5)",
        [credentialId,userId,"https://issuer.example.test/realm","test-key-v1",verifier],
      );
      const issuedBy=await admin.query<{issued_by:string}>("SELECT \"issuedBy\" AS issued_by FROM public.owner_bootstrap_credentials WHERE id=$1",[credentialId]);
      expect(issuedBy.rows[0]!.issued_by).toBe("dbp_owner_bootstrap_operator_test");
      const requests=await Promise.allSettled([
        ownerOperator.query<{id:string}>("SELECT public.prepare_platform_owner_bootstrap($1::uuid,$2::uuid,$3) AS id",[credentialId,userId,verifier]),
        ownerOperator.query<{id:string}>("SELECT public.prepare_platform_owner_bootstrap($1::uuid,$2::uuid,$3) AS id",[credentialId,userId,verifier]),
      ]);
      expect(requests.filter((request)=>request.status==='fulfilled')).toHaveLength(1);
      expect(requests.filter((request)=>request.status==='rejected')).toHaveLength(1);
      const operationId=requests.find((request)=>request.status==='fulfilled')!.status==='fulfilled'
        ? requests.find((request)=>request.status==='fulfilled')!.value.rows[0]!.id
        : "";

      const pending=await admin.query<{operation:string;designation:string;initialization:string}>(
        `SELECT op.status::text AS operation,d.status::text AS designation,i.state::text AS initialization
           FROM public.critical_operations op JOIN public.platform_owner_designations d ON d."criticalOperationId"=op.id
           CROSS JOIN public.platform_initialization i WHERE op.id=$1`,[operationId],
      );
      expect(pending.rows[0]).toEqual({operation:"PREPARED",designation:"PENDING",initialization:"UNINITIALIZED"});
      expect((await runtime.query("SELECT public.resolve_active_platform_owner($1::uuid) AS designation",[userId])).rows[0]!.designation).toBeNull();

      await service.advance();
      await service.advance();
      const waiting=await admin.query<{status:string;gate:string}>(
        `SELECT op.status::text AS status,g.state AS gate FROM public.critical_operations op
         JOIN public.critical_operation_gates g ON g."operationId"=op.id WHERE op.id=$1`,[operationId],
      );
      expect(waiting.rows[0]).toEqual({status:"AWAITING_ARCHIVE",gate:"PROPOSED"});
      expect((await admin.query("SELECT state::text FROM public.platform_initialization WHERE id=1")).rows[0]!.state).toBe("UNINITIALIZED");

      await deliverPhysical();
      await service.advance();
      await admin.query(`CREATE FUNCTION public.test_fail_owner_activation_audit() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW."eventType"='platform-owner-designation-activated' THEN RAISE EXCEPTION 'injected owner activation audit failure'; END IF; RETURN NEW; END $$`);
      await admin.query(`CREATE TRIGGER test_fail_owner_activation_audit BEFORE INSERT ON public.authorization_audit_events FOR EACH ROW EXECUTE FUNCTION public.test_fail_owner_activation_audit()`);
      await expect(service.advance()).rejects.toThrow(/injected owner activation audit failure/);
      await admin.query("DROP TRIGGER test_fail_owner_activation_audit ON public.authorization_audit_events");
      await admin.query("DROP FUNCTION public.test_fail_owner_activation_audit()");
      const rolledBack=await admin.query<{operation:string;designation:string;initialization:string}>(
        `SELECT op.status::text AS operation,d.status::text AS designation,i.state::text AS initialization
           FROM public.critical_operations op JOIN public.platform_owner_designations d ON d."criticalOperationId"=op.id
           CROSS JOIN public.platform_initialization i WHERE op.id=$1`,[operationId],
      );
      expect(rolledBack.rows[0]).toEqual({operation:"READY_TO_ACTIVATE",designation:"PENDING",initialization:"UNINITIALIZED"});
      await service.advance();
      const completed=await admin.query<{operation:string;designation:string;initialization:string}>(
        `SELECT op.status::text AS operation,d.status::text AS designation,i.state::text AS initialization
           FROM public.critical_operations op JOIN public.platform_owner_designations d ON d."criticalOperationId"=op.id
           CROSS JOIN public.platform_initialization i WHERE op.id=$1`,[operationId],
      );
      expect(completed.rows[0]).toEqual({operation:"COMPLETED",designation:"ACTIVE",initialization:"INITIALIZED"});
      expect((await runtime.query("SELECT public.resolve_active_platform_owner($1::uuid) AS designation",[userId])).rows[0]!.designation)
        .toBe((await admin.query<{id:string}>("SELECT id FROM public.platform_owner_designations WHERE \"criticalOperationId\"=$1",[operationId])).rows[0]!.id);
      await expect(runtime.query("UPDATE public.platform_initialization SET state='UNINITIALIZED' WHERE id=1")).rejects.toThrow();
      await expect(runtime.query("UPDATE public.platform_owner_designations SET status='ACTIVE'")).rejects.toThrow();
      await expect(ownerOperator.query("SELECT public.prepare_platform_owner_bootstrap($1::uuid,$2::uuid,$3)",[credentialId,userId,verifier]))
        .rejects.toThrow(/BOOTSTRAP_CREDENTIAL_ALREADY_USED/);
      const audit=await admin.query<{count:string}>(
        `SELECT count(*)::text AS count FROM public.authorization_audit_events WHERE "eventType"='platform-owner-designation-activated' AND "correlationId"=$1`,[operationId],
      );
      expect(audit.rows[0]!.count).toBe("1");

      const recoveryOperatorUrl=await roleUrl("dbp_owner_recovery_operator_test","dbp_owner_recovery_operator");
      const recoveryCallbackUrl=await roleUrl("dbp_owner_recovery_callback_test","dbp_owner_recovery_callback");
      const recoveryOperator=new Pool({connectionString:recoveryOperatorUrl,max:2});
      const recoveryCallback=new Pool({connectionString:recoveryCallbackUrl,max:1});
      const verifierKey=Buffer.alloc(32,0x6d);
      const makeKit=()=>{
        const codes=Array.from({length:10},()=>`dbp-rc-v1.${randomBytes(32).toString("base64url")}`);
        return {
          codes,
          kitId:randomUUID(),
          records:codes.map((code)=>({
            id:randomUUID(),keyId:"recovery-test-v1",
            verifier:createHmac("sha256",verifierKey).update("DBP-OWNER-RECOVERY-CODE-v1\0","utf8").update(code,"utf8").digest("hex"),
          })),
        };
      };
      const issueKit=async(material:ReturnType<typeof makeKit>)=>runtime.query(
        "SELECT * FROM public.issue_or_replace_owner_recovery_kit($1::uuid,$2,$3,$4::uuid,$5::jsonb)",
        [userId,"https://issuer.example.test/realm","bootstrap-owner-subject",material.kitId,JSON.stringify(material.records)],
      );
      try{
        const originalKit=makeKit();
        const originalIssue=await issueKit(originalKit);
        expect(originalIssue.rows[0]).toMatchObject({generation:1,replaced:false});
        expect((await admin.query<{count:string}>(`SELECT count(*)::text AS count FROM public.owner_recovery_codes WHERE "kitId"=$1`,[originalKit.kitId])).rows[0]!.count).toBe("10");

        const replacement=makeKit();
        await admin.query(`CREATE FUNCTION public.test_fail_owner_recovery_kit_audit() RETURNS trigger LANGUAGE plpgsql AS $$
          BEGIN IF NEW.\"eventType\"='owner-recovery-kit-replaced' THEN RAISE EXCEPTION 'injected recovery-kit audit failure'; END IF; RETURN NEW; END $$`);
        await admin.query(`CREATE TRIGGER test_fail_owner_recovery_kit_audit BEFORE INSERT ON public.authorization_audit_events FOR EACH ROW EXECUTE FUNCTION public.test_fail_owner_recovery_kit_audit()`);
        try{await expect(issueKit(replacement)).rejects.toThrow(/injected recovery-kit audit failure/);}
        finally{
          await admin.query("DROP TRIGGER test_fail_owner_recovery_kit_audit ON public.authorization_audit_events");
          await admin.query("DROP FUNCTION public.test_fail_owner_recovery_kit_audit()");
        }
        const afterFailedReplacement=await admin.query<{active:string;unused:string}>(
          `SELECT (SELECT count(*)::text FROM public.owner_recovery_kits WHERE status='ACTIVE') AS active,
                  (SELECT count(*)::text FROM public.owner_recovery_codes WHERE \"kitId\"=$1 AND status='UNUSED') AS unused`,[originalKit.kitId]);
        expect(afterFailedReplacement.rows[0]).toEqual({active:"1",unused:"10"});

        const replacementIssue=await issueKit(replacement);
        expect(replacementIssue.rows[0]).toMatchObject({generation:2,replaced:true});
        expect((await admin.query<{count:string}>(`SELECT count(*)::text AS count FROM public.owner_recovery_codes WHERE "kitId"=$1 AND status='REVOKED'`,[originalKit.kitId])).rows[0]!.count).toBe("10");
        expect((await admin.query("SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='owner_recovery_codes' AND column_name IN ('code','plaintext')")).rowCount).toBe(0);

        const recoveryOperationId=randomUUID();
        const candidate=(code:string)=>JSON.stringify([{keyId:"recovery-test-v1",verifier:createHmac("sha256",verifierKey)
          .update("DBP-OWNER-RECOVERY-CODE-v1\0","utf8").update(code,"utf8").digest("hex")}]);
        const invalid=await recoveryOperator.query<{begin_platform_owner_recovery:string|null}>(
          "SELECT public.begin_platform_owner_recovery($1::uuid,$2,$3::jsonb) AS begin_platform_owner_recovery",
          [randomUUID(),"https://issuer.example.test/realm",candidate(`dbp-rc-v1.${randomBytes(32).toString("base64url")}`)],
        );
        expect(invalid.rows[0]!.begin_platform_owner_recovery).toBeNull();

        const validCandidates=candidate(replacement.codes[0]!);
        const started=await Promise.all([
          recoveryOperator.query<{begin_platform_owner_recovery:string|null}>("SELECT public.begin_platform_owner_recovery($1::uuid,$2,$3::jsonb) AS begin_platform_owner_recovery",[recoveryOperationId,"https://issuer.example.test/realm",validCandidates]),
          recoveryOperator.query<{begin_platform_owner_recovery:string|null}>("SELECT public.begin_platform_owner_recovery($1::uuid,$2,$3::jsonb) AS begin_platform_owner_recovery",[randomUUID(),"https://issuer.example.test/realm",validCandidates]),
        ]);
        const acceptedOperation=started.map((result)=>result.rows[0]!.begin_platform_owner_recovery);
        expect(acceptedOperation).toEqual([recoveryOperationId,recoveryOperationId]);
        await recoveryOperator.query("SELECT public.mark_platform_owner_recovery_challenge_prepared($1::uuid)",[recoveryOperationId]);
        await expect(recoveryOperator.query("SELECT 1 FROM public.owner_recovery_codes")).rejects.toThrow();
        const operatorPrivilege=await admin.query<{can_inspect_codes:boolean;can_issue_kit:boolean}>(
          `SELECT has_table_privilege('dbp_owner_recovery_operator_test','public.owner_recovery_codes','SELECT') AS can_inspect_codes,
                  has_function_privilege('dbp_owner_recovery_operator_test','public.issue_or_replace_owner_recovery_kit(uuid,text,text,uuid,jsonb)','EXECUTE') AS can_issue_kit`);
        expect(operatorPrivilege.rows[0]).toEqual({can_inspect_codes:false,can_issue_kit:false});
        await expect(runtime.query("SELECT 1 FROM public.owner_recovery_codes")).rejects.toThrow();
        const helperPrivilege=await admin.query<{runtime_can_lock_owner:boolean;operator_can_lock_owner:boolean;callback_can_inspect_codes:boolean}>(
          `SELECT has_function_privilege('dbp_critical_runtime_test','public.lock_active_platform_owner()','EXECUTE') AS runtime_can_lock_owner,
                  has_function_privilege('dbp_owner_recovery_operator_test','public.lock_active_platform_owner()','EXECUTE') AS operator_can_lock_owner,
                  has_table_privilege('dbp_owner_recovery_callback_test','public.owner_recovery_codes','SELECT') AS callback_can_inspect_codes`);
        expect(helperPrivilege.rows[0]).toEqual({runtime_can_lock_owner:false,operator_can_lock_owner:false,callback_can_inspect_codes:false});

        const newSubject="owner-recovery-subject";
        const verifiedAt=new Date();
        await admin.query(`CREATE FUNCTION public.test_fail_owner_recovery_pending_audit() RETURNS trigger LANGUAGE plpgsql AS $$
          BEGIN IF NEW.\"eventType\"='owner-recovery-pending-identity-created' THEN RAISE EXCEPTION 'injected pending-identity audit failure'; END IF; RETURN NEW; END $$`);
        await admin.query(`CREATE TRIGGER test_fail_owner_recovery_pending_audit BEFORE INSERT ON public.authorization_audit_events FOR EACH ROW EXECUTE FUNCTION public.test_fail_owner_recovery_pending_audit()`);
        try{
          await expect(recoveryCallback.query("SELECT public.complete_platform_owner_recovery($1::uuid,$2,$3,$4::timestamptz,$5::uuid)",
            [recoveryOperationId,"https://issuer.example.test/realm",newSubject,verifiedAt,randomUUID()])).rejects.toThrow(/injected pending-identity audit failure/);
        }finally{
          await admin.query("DROP TRIGGER test_fail_owner_recovery_pending_audit ON public.authorization_audit_events");
          await admin.query("DROP FUNCTION public.test_fail_owner_recovery_pending_audit()");
        }
        expect((await admin.query("SELECT 1 FROM public.user_identities WHERE subject=$1",[newSubject])).rowCount).toBe(0);
        expect((await admin.query<{status:string}>("SELECT status::text FROM public.owner_recovery_operations WHERE id=$1",[recoveryOperationId])).rows[0]!.status).toBe("CHALLENGE_PREPARED");
        await recoveryCallback.query("SELECT public.complete_platform_owner_recovery($1::uuid,$2,$3,$4::timestamptz,$5::uuid)",
          [recoveryOperationId,"https://issuer.example.test/realm",newSubject,verifiedAt,randomUUID()]);
        const pendingIdentity=await admin.query<{status:string;email:string|null;user_id:string;recovery_operation:string}> (
          `SELECT status::text,email,\"userId\" AS user_id,\"ownerRecoveryOperationId\" AS recovery_operation FROM public.user_identities WHERE subject=$1`,[newSubject]);
        expect(pendingIdentity.rows[0]).toEqual({status:"PENDING_OWNER_RECOVERY",email:null,user_id:userId,recovery_operation:recoveryOperationId});
        expect((await admin.query("SELECT 1 FROM public.user_identity_verifications WHERE subject=$1",[newSubject])).rowCount).toBe(0);
        expect((await admin.query("SELECT status::text FROM public.owner_recovery_codes WHERE id=$1",[replacement.records[0]!.id])).rows[0]!.status).toBe("CONSUMED");
        await expect(recoveryCallback.query("SELECT public.complete_platform_owner_recovery($1::uuid,$2,$3,$4::timestamptz,$5::uuid)",
          [recoveryOperationId,"https://issuer.example.test/realm",newSubject,verifiedAt,randomUUID()])).resolves.toBeTruthy();

        await service.advance();
        await service.advance();
        const awaiting=await admin.query<{status:string;recovery_status:string;identity_status:string}>(
          `SELECT op.status::text AS status,r.status::text AS recovery_status,u.status::text AS identity_status
             FROM public.critical_operations op JOIN public.owner_recovery_operations r ON r.\"criticalOperationId\"=op.id
             JOIN public.user_identities u ON u.\"ownerRecoveryOperationId\"=r.id WHERE r.id=$1`,[recoveryOperationId]);
        expect(awaiting.rows[0]).toEqual({status:"AWAITING_ARCHIVE",recovery_status:"AWAITING_ARCHIVE",identity_status:"PENDING_OWNER_RECOVERY"});
        expect((await runtime.query("SELECT public.resolve_active_platform_owner($1::uuid) AS designation",[userId])).rows[0]!.designation)
          .toBe((await admin.query<{id:string}>("SELECT id FROM public.platform_owner_designations WHERE status='ACTIVE'")).rows[0]!.id);

        await deliverPhysical();
        await service.advance();
        const ready=await admin.query<{recovery_status:string;identity_status:string;critical_status:string}>(
          `SELECT r.status::text AS recovery_status,u.status::text AS identity_status,op.status::text AS critical_status
             FROM public.owner_recovery_operations r JOIN public.user_identities u ON u.\"ownerRecoveryOperationId\"=r.id
             JOIN public.critical_operations op ON op.id=r.\"criticalOperationId\" WHERE r.id=$1`,[recoveryOperationId]);
        expect(ready.rows[0]).toEqual({recovery_status:"READY_TO_FINALIZE",identity_status:"PENDING_OWNER_RECOVERY",critical_status:"READY_TO_ACTIVATE"});
        await admin.query(`CREATE FUNCTION public.test_fail_owner_recovery_final_audit() RETURNS trigger LANGUAGE plpgsql AS $$
          BEGIN IF NEW.\"eventType\"='owner-recovery-finalized' THEN RAISE EXCEPTION 'injected recovery-finalization audit failure'; END IF; RETURN NEW; END $$`);
        await admin.query(`CREATE TRIGGER test_fail_owner_recovery_final_audit BEFORE INSERT ON public.authorization_audit_events FOR EACH ROW EXECUTE FUNCTION public.test_fail_owner_recovery_final_audit()`);
        try{await expect(service.advance()).rejects.toThrow(/injected recovery-finalization audit failure/);}
        finally{
          await admin.query("DROP TRIGGER test_fail_owner_recovery_final_audit ON public.authorization_audit_events");
          await admin.query("DROP FUNCTION public.test_fail_owner_recovery_final_audit()");
        }
        const finalRollback=await admin.query<{recovery_status:string;identity_status:string;critical_status:string}>(
          `SELECT r.status::text AS recovery_status,u.status::text AS identity_status,op.status::text AS critical_status
             FROM public.owner_recovery_operations r JOIN public.user_identities u ON u.\"ownerRecoveryOperationId\"=r.id
             JOIN public.critical_operations op ON op.id=r.\"criticalOperationId\" WHERE r.id=$1`,[recoveryOperationId]);
        expect(finalRollback.rows[0]).toEqual({recovery_status:"READY_TO_FINALIZE",identity_status:"PENDING_OWNER_RECOVERY",critical_status:"READY_TO_ACTIVATE"});
        await service.advance();
        const finalized=await admin.query<{recovery_status:string;identity_status:string;critical_status:string;activated:boolean}>(
          `SELECT r.status::text AS recovery_status,u.status::text AS identity_status,op.status::text AS critical_status,(v.\"activatedAt\" IS NOT NULL) AS activated
             FROM public.owner_recovery_operations r JOIN public.user_identities u ON u.\"ownerRecoveryOperationId\"=r.id
             JOIN public.critical_operations op ON op.id=r.\"criticalOperationId\"
             JOIN public.owner_recovery_verifications v ON v.\"recoveryOperationId\"=r.id WHERE r.id=$1`,[recoveryOperationId]);
        expect(finalized.rows[0]).toEqual({recovery_status:"FINALIZED",identity_status:"ACTIVE",critical_status:"COMPLETED",activated:true});
        expect((await runtime.query("SELECT public.resolve_active_platform_owner($1::uuid) AS designation",[userId])).rows[0]!.designation)
          .toBe((await admin.query<{id:string}>("SELECT id FROM public.platform_owner_designations WHERE status='ACTIVE'")).rows[0]!.id);
        const recoveryAudit=await admin.query<{events:string}>(
          `SELECT count(*)::text AS events FROM public.authorization_audit_events WHERE \"correlationId\" IN ($1::text,(SELECT \"criticalOperationId\"::text FROM public.owner_recovery_operations WHERE id=$1::uuid)) AND \"eventType\" IN ('owner-recovery-initiated','owner-recovery-code-consumed','owner-recovery-challenge-prepared','owner-recovery-oidc-proof','owner-recovery-pending-identity-created','owner-recovery-critical-operation-prepared','owner-recovery-awaiting-archive','owner-recovery-archive-qualified','owner-recovery-finalized')`,[recoveryOperationId]);
        expect(Number(recoveryAudit.rows[0]!.events)).toBeGreaterThanOrEqual(9);

        const expiredOperationId=randomUUID();
        const expiredStart=await recoveryOperator.query<{begin_platform_owner_recovery:string|null}>(
          "SELECT public.begin_platform_owner_recovery($1::uuid,$2,$3::jsonb) AS begin_platform_owner_recovery",
          [expiredOperationId,"https://issuer.example.test/realm",candidate(replacement.codes[1]!)],
        );
        expect(expiredStart.rows[0]!.begin_platform_owner_recovery).toBe(expiredOperationId);
        await recoveryOperator.query("SELECT public.mark_platform_owner_recovery_challenge_prepared($1::uuid)",[expiredOperationId]);
        await admin.query("ALTER TABLE public.owner_recovery_operations DISABLE TRIGGER owner_recovery_operations_restricted_write");
        try{await admin.query("UPDATE public.owner_recovery_operations SET \"expiresAt\"=clock_timestamp()-interval '1 second' WHERE id=$1",[expiredOperationId]);}
        finally{await admin.query("ALTER TABLE public.owner_recovery_operations ENABLE TRIGGER owner_recovery_operations_restricted_write");}
        const expiryWorker=new Pool({connectionString:criticalUrl,max:1});
        try{expect((await expiryWorker.query("SELECT public.expire_platform_owner_recoveries(100) AS count")).rows[0]!.count).toBe(1);}
        finally{await expiryWorker.end();}
        expect((await recoveryOperator.query("SELECT * FROM public.get_platform_owner_recovery_status($1::uuid)",[expiredOperationId])).rows[0]!.recovery_status).toBe("EXPIRED");
        expect((await admin.query("SELECT status::text FROM public.owner_recovery_codes WHERE id=$1",[replacement.records[1]!.id])).rows[0]!.status).toBe("CONSUMED");
        const replay=await recoveryOperator.query<{begin_platform_owner_recovery:string|null}>(
          "SELECT public.begin_platform_owner_recovery($1::uuid,$2,$3::jsonb) AS begin_platform_owner_recovery",
          [randomUUID(),"https://issuer.example.test/realm",candidate(replacement.codes[1]!)],
        );
        expect(replay.rows[0]!.begin_platform_owner_recovery).toBeNull();
      }finally{
        verifierKey.fill(0);
        await Promise.all([recoveryOperator.end(),recoveryCallback.end()]);
      }
    }finally{
      await Promise.all([ownerOperator.end(),identityOperator.end(),identityCallback.end()]);
    }
  });
});
