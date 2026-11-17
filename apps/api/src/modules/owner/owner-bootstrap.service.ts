import { Pool, type PoolConfig, type PoolClient } from "pg";

function createPool(config: PoolConfig | string, applicationName: string): Pool {
  return new Pool(typeof config === "string"
    ? { connectionString: config, max: 2, application_name: applicationName }
    : { ...config, max: 2, application_name: applicationName });
}

export function createPlatformOwnerOperatorService(config: PoolConfig | string) {
  const pool = createPool(config, "dbp-platform-owner-operator");
  return {
    async issueCredential(input: { credentialId: string; platformUserId: string; issuer: string; keyId: string; verifier: Buffer }): Promise<Date> {
      const result = await pool.query<{ issue_platform_owner_bootstrap_credential: Date }>(
        "SELECT public.issue_platform_owner_bootstrap_credential($1::uuid,$2::uuid,$3,$4,$5) AS issue_platform_owner_bootstrap_credential",
        [input.credentialId,input.platformUserId,input.issuer,input.keyId,input.verifier],
      );
      return result.rows[0]!.issue_platform_owner_bootstrap_credential;
    },
    async prepare(input: { credentialId: string; platformUserId: string; verifier: Buffer }): Promise<string> {
      const result = await pool.query<{ prepare_platform_owner_bootstrap: string }>(
        "SELECT public.prepare_platform_owner_bootstrap($1::uuid,$2::uuid,$3) AS prepare_platform_owner_bootstrap",
        [input.credentialId,input.platformUserId,input.verifier],
      );
      return result.rows[0]!.prepare_platform_owner_bootstrap;
    },
    async recordRejection(platformUserId: string, outcomeCode: string): Promise<void> {
      await pool.query("SELECT public.record_platform_owner_bootstrap_rejection($1::uuid,$2)",[platformUserId,outcomeCode]);
    },
    async status(credentialId: string): Promise<{
      credentialStatus: string; operationId: string | null; operationStatus: string | null;
      designationStatus: string | null; initializationState: string;
    } | null> {
      const result = await pool.query<{
        credential_status: string; operation_id: string | null; operation_status: string | null;
        designation_status: string | null; initialization_state: string;
      }>("SELECT * FROM public.get_platform_owner_bootstrap_status($1::uuid)",[credentialId]);
      const row=result.rows[0];
      return row ? {
        credentialStatus: row.credential_status,
        operationId: row.operation_id,
        operationStatus: row.operation_status,
        designationStatus: row.designation_status,
        initializationState: row.initialization_state,
      } : null;
    },
    async close(): Promise<void> { await pool.end(); },
  };
}

/** Use this inside the same transaction as any sensitive owner-only database action. */
export async function resolveActivePlatformOwner(
  transaction: Pick<PoolClient,"query">,
  platformUserId: string,
): Promise<string | null> {
  const result = await transaction.query<{ resolve_active_platform_owner: string | null }>(
    "SELECT public.resolve_active_platform_owner($1::uuid) AS resolve_active_platform_owner",
    [platformUserId],
  );
  return result.rows[0]?.resolve_active_platform_owner ?? null;
}

/** Keeps the authoritative owner check and caller's protected work in one PostgreSQL transaction. */
export async function withActivePlatformOwner<T>(
  config: PoolConfig | string,
  platformUserId: string,
  work: (transaction: PoolClient, designationId: string) => Promise<T>,
): Promise<T | null> {
  const pool=createPool(config,"dbp-platform-owner-authorization");
  const transaction=await pool.connect();
  try {
    await transaction.query("BEGIN");
    const designationId=await resolveActivePlatformOwner(transaction,platformUserId);
    if (!designationId) {
      await transaction.query("ROLLBACK");
      return null;
    }
    const result=await work(transaction,designationId);
    await transaction.query("COMMIT");
    return result;
  } catch (error) {
    await transaction.query("ROLLBACK");
    throw error;
  } finally {
    transaction.release();
    await pool.end();
  }
}
