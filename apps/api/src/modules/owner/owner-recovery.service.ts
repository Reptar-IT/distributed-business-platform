import { randomUUID } from "node:crypto";
import { Pool, type PoolConfig } from "pg";
import type { PrismaClient } from "@platform/database";
import {
  createRecoveryKitMaterial,
  recoveryVerifierCandidates,
  type RecoveryVerifierKeyring,
} from "./recovery-codes.js";

function createPool(config: PoolConfig | string, applicationName: string): Pool {
  return new Pool(typeof config === "string"
    ? { connectionString: config, max: 2, application_name: applicationName }
    : { ...config, max: 2, application_name: applicationName });
}

export function createOwnerRecoveryKitService(prisma: PrismaClient, keyring: RecoveryVerifierKeyring) {
  return {
    async isActiveOwner(platformUserId: string): Promise<boolean> {
      const rows = await prisma.$queryRaw<Array<{ is_owner: boolean }>>`
        SELECT public.resolve_active_platform_owner(${platformUserId}::uuid) IS NOT NULL AS is_owner
      `;
      return rows[0]?.is_owner === true;
    },

    async issueOrReplace(input: { platformUserId: string; issuer: string; subject: string }) {
      const material = createRecoveryKitMaterial(keyring);
      const rows = await prisma.$queryRaw<Array<{ kit_id: string; generation: number; replaced: boolean }>>`
        SELECT * FROM public.issue_or_replace_owner_recovery_kit(
          ${input.platformUserId}::uuid, ${input.issuer}, ${input.subject}, ${material.kitId}::uuid, ${JSON.stringify(material.records)}::jsonb
        )
      `;
      const result = rows[0];
      if (!result || result.kit_id !== material.kitId) throw new Error("Recovery kit could not be issued");
      return { ...result, codes: material.codes };
    },
  };
}

export function createOwnerRecoveryOperatorService(config: PoolConfig | string, keyring: RecoveryVerifierKeyring) {
  const pool = createPool(config, "dbp-owner-recovery-operator");
  return {
    async begin(input: { code: string; issuer: string }): Promise<string> {
      const operationId = randomUUID();
      const candidates = recoveryVerifierCandidates(input.code, keyring);
      const result = await pool.query<{ begin_platform_owner_recovery: string | null }>(
        "SELECT public.begin_platform_owner_recovery($1::uuid,$2,$3::jsonb) AS begin_platform_owner_recovery",
        [operationId, input.issuer, JSON.stringify(candidates)],
      );
      const acceptedId = result.rows[0]?.begin_platform_owner_recovery;
      if (!acceptedId) throw new Error("Recovery was rejected or another recovery is already open");
      return acceptedId;
    },
    async markChallengePrepared(operationId: string): Promise<void> {
      await pool.query("SELECT public.mark_platform_owner_recovery_challenge_prepared($1::uuid)", [operationId]);
    },
    async status(operationId: string): Promise<{
      recoveryStatus: string;
      criticalStatus: string | null;
      outcomeCode: string | null;
      criticalOperationId: string | null;
    } | null> {
      const result = await pool.query<{
        recovery_status: string;
        critical_status: string | null;
        outcome_code: string | null;
        critical_operation_id: string | null;
      }>("SELECT * FROM public.get_platform_owner_recovery_status($1::uuid)", [operationId]);
      const row = result.rows[0];
      return row ? {
        recoveryStatus: row.recovery_status,
        criticalStatus: row.critical_status,
        outcomeCode: row.outcome_code,
        criticalOperationId: row.critical_operation_id,
      } : null;
    },
    close: () => pool.end(),
  };
}

export function createOwnerRecoveryCallbackService(config: PoolConfig | string) {
  const pool = createPool(config, "dbp-owner-recovery-callback");
  return {
    async complete(input: { operationId: string; issuer: string; subject: string; verifiedAt: Date }): Promise<string> {
      const result = await pool.query<{ complete_platform_owner_recovery: string }>(
        "SELECT public.complete_platform_owner_recovery($1::uuid,$2,$3,$4::timestamptz,$5::uuid) AS complete_platform_owner_recovery",
        [input.operationId, input.issuer, input.subject, input.verifiedAt, randomUUID()],
      );
      return result.rows[0]!.complete_platform_owner_recovery;
    },
    async reject(operationId: string, outcomeCode: string): Promise<void> {
      await pool.query("SELECT public.reject_platform_owner_recovery($1::uuid,$2)", [operationId, outcomeCode]);
    },
    close: () => pool.end(),
  };
}
