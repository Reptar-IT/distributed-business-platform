import type {
  AuthorizationContext,
  DelegationId,
  ValidityWindow,
} from "@platform/shared-types";
import type { PermissionCode } from "@platform/permissions";

export type ResourceScope =
  | { readonly kind: "platform" }
  | { readonly kind: "venture"; readonly ventureId: string }
  | {
      readonly kind: "resource";
      readonly resourceType: string;
      readonly resourceId: string;
      readonly ventureId?: string;
    };

export interface DelegationConstraints {
  readonly delegationId: DelegationId;
  readonly purpose: string;
  readonly taskReference?: string;
  readonly allowedPermissions: readonly PermissionCode[];
  readonly scopes: readonly ResourceScope[];
  readonly prohibitedPermissions: readonly PermissionCode[];
  readonly validity: ValidityWindow;
}

/** Inputs are facts loaded by a trusted boundary; these contracts do not perform evaluation. */
export interface AuthorizationEvaluationInput {
  readonly context: AuthorizationContext;
  readonly permission: PermissionCode;
  readonly resource: ResourceScope;
  readonly now: Date;
  readonly delegation?: DelegationConstraints;
  readonly approvalReference?: string;
  readonly policyVersion: string;
}

export type AuthorizationDecision =
  | { readonly allowed: true; readonly reason: "AUTHORIZED"; readonly policyVersion: string }
  | {
      readonly allowed: false;
      readonly reason:
        | "UNKNOWN_PRINCIPAL"
        | "INACTIVE_PRINCIPAL"
        | "MISSING_PERMISSION"
        | "OUT_OF_SCOPE"
        | "DELEGATION_INVALID"
        | "APPROVAL_REQUIRED"
        | "POLICY_DENIED";
      readonly policyVersion: string;
    };
