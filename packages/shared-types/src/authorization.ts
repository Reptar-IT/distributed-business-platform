/** Stable internal identifier for an existing DBP platform user. */
export type PlatformUserId = string & { readonly __brand: "PlatformUserId" };

/** Stable identifier for a non-human DBP machine actor. */
export type MachinePrincipalId = string & { readonly __brand: "MachinePrincipalId" };

/** Stable identifier for an authenticated calling client. */
export type CallingClientId = string & { readonly __brand: "CallingClientId" };

/** Opaque reference to an authorization delegation. */
export type DelegationId = string & { readonly __brand: "DelegationId" };

/** Opaque reference to the protected current-owner designation. */
export type OwnerDesignationId = string & { readonly __brand: "OwnerDesignationId" };

/** Human identity is the internal platform user, with federated identity evidence retained separately. */
export interface HumanPrincipal {
  readonly kind: "human";
  readonly platformUserId: PlatformUserId;
  readonly identity: {
    readonly issuer: string;
    readonly subject: string;
  };
}

export const MACHINE_ACTOR_TYPES = ["AI_AGENT", "AUTOMATION", "SERVICE"] as const;
export type MachineActorType = (typeof MACHINE_ACTOR_TYPES)[number];

/** Shared non-human identity. Actor-specific configuration belongs in separate contracts. */
export interface MachinePrincipal {
  readonly kind: "machine";
  readonly machinePrincipalId: MachinePrincipalId;
  readonly actorType: MachineActorType;
}

/** A distinct authenticated client; it is never interchangeable with the human actor. */
export interface CallingClientPrincipal {
  readonly kind: "calling_client";
  readonly clientId: CallingClientId;
  readonly clientType: "FIRST_PARTY" | "EXTERNAL";
}

/**
 * A verified owner designation can only be issued by a trusted authorization boundary.
 * This opaque type is a compile-time guard, not a substitute for authoritative runtime checks.
 */
declare const verifiedOwnerDesignation: unique symbol;
export interface VerifiedPlatformOwnerDesignation {
  readonly [verifiedOwnerDesignation]: true;
  readonly designationId: OwnerDesignationId;
  readonly platformUserId: PlatformUserId;
}

export interface DirectHumanContext {
  readonly kind: "direct_human";
  readonly principal: HumanPrincipal;
}

export interface PlatformOwnerContext {
  readonly kind: "platform_owner";
  readonly principal: HumanPrincipal;
  readonly designation: VerifiedPlatformOwnerDesignation;
}

export interface DirectMachineContext {
  readonly kind: "direct_machine";
  readonly principal: MachinePrincipal;
}

export interface DelegatedHumanClientContext {
  readonly kind: "delegated_human_client";
  readonly human: HumanPrincipal;
  readonly client: CallingClientPrincipal;
  readonly delegationId: DelegationId;
}

/** Authorization context preserves the actor, owner proof, and client identities as distinct cases. */
export type AuthorizationContext =
  | DirectHumanContext
  | PlatformOwnerContext
  | DirectMachineContext
  | DelegatedHumanClientContext;

/** A bounded time interval used by future grants and delegations. */
export interface ValidityWindow {
  readonly startsAt: Date;
  readonly expiresAt: Date;
}
