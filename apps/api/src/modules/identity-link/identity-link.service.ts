import { Pool, type PoolConfig } from "pg";

function createPool(config: PoolConfig | string, applicationName: string): Pool {
  return new Pool(typeof config === "string"
    ? { connectionString: config, max: 2, application_name: applicationName }
    : { ...config, max: 2, application_name: applicationName });
}

/** Connection intended only for a login explicitly granted dbp_identity_link_operator. */
export function createIdentityLinkOperatorService(config: PoolConfig | string) {
  const pool = createPool(config, "dbp-identity-link-operator");
  return {
    async begin(platformUserId: string, issuer: string): Promise<string> {
      const result = await pool.query<{ begin_platform_identity_link: string }>(
        "SELECT public.begin_platform_identity_link($1::uuid, $2) AS begin_platform_identity_link",
        [platformUserId, issuer],
      );
      return result.rows[0]!.begin_platform_identity_link;
    },
    async close(): Promise<void> { await pool.end(); },
  };
}

/** Connection intended only for the API callback's restricted completion functions. */
export function createIdentityLinkCallbackService(config: PoolConfig | string) {
  const pool = createPool(config, "dbp-identity-link-callback");
  return {
    async complete(input: { challengeId: string; issuer: string; subject: string; verifiedAt: Date }): Promise<string> {
      const result = await pool.query<{ complete_platform_identity_link: string }>(
        "SELECT public.complete_platform_identity_link($1::uuid, $2, $3, $4::timestamptz) AS complete_platform_identity_link",
        [input.challengeId, input.issuer, input.subject, input.verifiedAt],
      );
      return result.rows[0]!.complete_platform_identity_link;
    },
    async reject(challengeId: string, outcomeCode: string): Promise<void> {
      await pool.query("SELECT public.reject_platform_identity_link($1::uuid, $2)", [challengeId, outcomeCode]);
    },
    async close(): Promise<void> { await pool.end(); },
  };
}
