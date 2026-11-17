export const AUTHORITY_CLASSES = [
  "OWNER_EXCLUSIVE",
  "OWNER_DELEGABLE",
  "POLICY_DELEGABLE",
] as const;

export type AuthorityClass = (typeof AUTHORITY_CLASSES)[number];
export type Sensitivity = "LOW" | "MODERATE" | "HIGH" | "CRITICAL";
export type ScopeType = "PLATFORM" | "VENTURE" | "RESOURCE";

export type ApprovalRequirement =
  | { readonly required: false }
  | {
      readonly required: true;
      readonly approver: "PLATFORM_OWNER";
      readonly stage: "EACH_EXECUTION" | "DELEGATION_GRANT" | "POLICY_CREATION";
      readonly bindsTo: readonly ["ACTION", "SCOPE", "PARAMETERS"];
      readonly singleUse: boolean;
    };

export interface PermissionDefinition {
  readonly code: string;
  readonly description: string;
  readonly domain: string;
  readonly sensitivity: Sensitivity;
  readonly scopeType: ScopeType;
  readonly authorityClass: AuthorityClass;
  readonly approval: ApprovalRequirement;
}

/**
 * Initial representative examples only. They establish metadata shape and are not
 * the complete owner-reserved action catalogue or an approval of all future grants.
 */
const definitions = [
  {
    code: "platform.machine-principal.manage",
    description: "Create, authorize, suspend, or revoke a platform machine principal.",
    domain: "platform.machine-principal",
    sensitivity: "CRITICAL",
    scopeType: "PLATFORM",
    authorityClass: "OWNER_EXCLUSIVE",
    approval: {
      required: true,
      approver: "PLATFORM_OWNER",
      stage: "EACH_EXECUTION",
      bindsTo: ["ACTION", "SCOPE", "PARAMETERS"],
      singleUse: true,
    },
  },
  {
    code: "platform.delegation.manage",
    description: "Create, renew, suspend, or revoke a bounded platform delegation.",
    domain: "platform.authorization",
    sensitivity: "CRITICAL",
    scopeType: "PLATFORM",
    authorityClass: "OWNER_EXCLUSIVE",
    approval: {
      required: true,
      approver: "PLATFORM_OWNER",
      stage: "EACH_EXECUTION",
      bindsTo: ["ACTION", "SCOPE", "PARAMETERS"],
      singleUse: true,
    },
  },
  {
    code: "platform.authorization-policy.manage",
    description: "Create or replace an owner-approved platform authorization policy.",
    domain: "platform.authorization",
    sensitivity: "CRITICAL",
    scopeType: "PLATFORM",
    authorityClass: "OWNER_EXCLUSIVE",
    approval: {
      required: true,
      approver: "PLATFORM_OWNER",
      stage: "EACH_EXECUTION",
      bindsTo: ["ACTION", "SCOPE", "PARAMETERS"],
      singleUse: true,
    },
  },
  {
    code: "platform.authorization-audit.read",
    description: "Read platform authorization audit events within an approved scope.",
    domain: "platform.audit",
    sensitivity: "HIGH",
    scopeType: "PLATFORM",
    authorityClass: "POLICY_DELEGABLE",
    approval: {
      required: true,
      approver: "PLATFORM_OWNER",
      stage: "POLICY_CREATION",
      bindsTo: ["ACTION", "SCOPE", "PARAMETERS"],
      singleUse: false,
    },
  },
] as const satisfies readonly PermissionDefinition[];

function validateCatalog(entries: readonly PermissionDefinition[]): void {
  const codes = new Set<string>();
  const authorityClasses = new Set<string>(AUTHORITY_CLASSES);
  const sensitivities = new Set<Sensitivity>(["LOW", "MODERATE", "HIGH", "CRITICAL"]);
  const scopeTypes = new Set<ScopeType>(["PLATFORM", "VENTURE", "RESOURCE"]);

  for (const entry of entries) {
    if (!/^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/.test(entry.code)) {
      throw new Error(`Invalid permission code: ${entry.code}`);
    }
    if (codes.has(entry.code)) throw new Error(`Duplicate permission code: ${entry.code}`);
    codes.add(entry.code);

    if (!entry.description.trim() || !entry.domain.trim()) {
      throw new Error(`Permission ${entry.code} requires a description and domain`);
    }
    if (!authorityClasses.has(entry.authorityClass)) {
      throw new Error(`Invalid authority class for ${entry.code}`);
    }
    if (!sensitivities.has(entry.sensitivity) || !scopeTypes.has(entry.scopeType)) {
      throw new Error(`Invalid sensitivity or scope metadata for ${entry.code}`);
    }
    if (entry.approval.required) {
      if (entry.approval.approver !== "PLATFORM_OWNER" || entry.approval.bindsTo.length !== 3) {
        throw new Error(`Inconsistent approval requirement for ${entry.code}`);
      }
      if (entry.approval.stage === "POLICY_CREATION" && entry.authorityClass !== "POLICY_DELEGABLE") {
        throw new Error(`Policy-creation approval requires POLICY_DELEGABLE: ${entry.code}`);
      }
      if (entry.authorityClass === "POLICY_DELEGABLE" && entry.approval.stage !== "POLICY_CREATION") {
        throw new Error(`POLICY_DELEGABLE permission requires policy-creation approval: ${entry.code}`);
      }
    } else if (entry.authorityClass === "OWNER_EXCLUSIVE") {
      throw new Error(`OWNER_EXCLUSIVE permission requires owner approval: ${entry.code}`);
    }
  }
}

validateCatalog(definitions);

/** Frozen public definitions prevent runtime mutation of code-owned permission meaning. */
const frozenDefinitions: PermissionDefinition[] = definitions.map((definition) => {
  if (!definition.approval.required) return Object.freeze(definition);

  const approval: ApprovalRequirement = {
    ...definition.approval,
    bindsTo: Object.freeze(["ACTION", "SCOPE", "PARAMETERS"]) as readonly [
      "ACTION",
      "SCOPE",
      "PARAMETERS",
    ],
  };
  return Object.freeze({ ...definition, approval: Object.freeze(approval) });
});

export const PERMISSION_CATALOG: readonly PermissionDefinition[] = Object.freeze(frozenDefinitions);

export type PermissionCode = (typeof definitions)[number]["code"];

const permissionByCode: ReadonlyMap<string, PermissionDefinition> = new Map(
  PERMISSION_CATALOG.map((definition) => [definition.code, definition]),
);

export function isPermissionCode(value: string): value is PermissionCode {
  return permissionByCode.has(value);
}

export function getPermissionDefinition(code: string): PermissionDefinition | undefined {
  return permissionByCode.get(code);
}
