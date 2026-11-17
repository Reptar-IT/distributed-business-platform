import type { PrismaClient } from "./generated/prisma/client.js";

export type AuditActorType = "HUMAN" | "MACHINE" | "SYSTEM" | "BOOTSTRAP";
export type AuditDecision = "ALLOW" | "DENY" | "NOT_APPLICABLE";

export interface AuthorizationAuditInput {
  readonly eventType: string;
  readonly actorType: AuditActorType;
  readonly actorId: string;
  readonly delegatingHumanId?: string | null;
  readonly callingClientId?: string | null;
  readonly permissionCode?: string | null;
  readonly decision?: AuditDecision;
  readonly decisionReasonCode?: string | null;
  readonly targetType?: string | null;
  readonly targetId?: string | null;
  readonly ventureId?: string | null;
  readonly delegationId?: string | null;
  readonly approvalId?: string | null;
  readonly policyVersion?: string | null;
  readonly operation: string;
  readonly outcome: string;
  readonly requestId?: string | null;
  readonly jobId?: string | null;
  readonly correlationId?: string | null;
}

export interface AppendedAuditEvent {
  readonly eventId: string;
  readonly sequence: bigint;
  readonly canonicalPayload: string;
  readonly eventHash: Uint8Array;
}

/**
 * Calls the restricted PostgreSQL function. Trusted canonicalization and hashing
 * happen in that function, in the caller's current transaction.
 */
export async function appendAuthorizationAudit(
  prisma: PrismaClient,
  event: AuthorizationAuditInput,
): Promise<AppendedAuditEvent> {
  const result = await prisma.$queryRaw<AppendedAuditEvent[]>`
    SELECT * FROM public.append_authorization_audit(${JSON.stringify(event)}::jsonb)
  `;
  const appended = result[0];
  if (!appended) throw new Error("Audit append function returned no event");
  return appended;
}
