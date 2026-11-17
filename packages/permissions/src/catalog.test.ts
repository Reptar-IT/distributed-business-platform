import { describe, expect, it } from "vitest";
import {
  AUTHORITY_CLASSES,
  PERMISSION_CATALOG,
  getPermissionDefinition,
  isPermissionCode,
} from "./catalog.js";

describe("permission catalogue", () => {
  it("contains unique stable permission codes", () => {
    const codes = PERMISSION_CATALOG.map(({ code }) => code);
    expect(new Set(codes).size).toBe(codes.length);
    codes.forEach((code) => expect(code).toMatch(/^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/));
  });

  it("uses only the approved authority classes and explicit scope metadata", () => {
    expect(AUTHORITY_CLASSES).toEqual(["OWNER_EXCLUSIVE", "OWNER_DELEGABLE", "POLICY_DELEGABLE"]);
    PERMISSION_CATALOG.forEach((definition) => {
      expect(AUTHORITY_CLASSES).toContain(definition.authorityClass);
      expect(["LOW", "MODERATE", "HIGH", "CRITICAL"]).toContain(definition.sensitivity);
      expect(["PLATFORM", "VENTURE", "RESOURCE"]).toContain(definition.scopeType);
      expect(definition.description.length).toBeGreaterThan(0);
    });
  });

  it("includes representative examples without claiming a complete catalogue", () => {
    expect(PERMISSION_CATALOG.map(({ code }) => code)).toEqual([
      "platform.machine-principal.manage",
      "platform.delegation.manage",
      "platform.authorization-policy.manage",
      "platform.authorization-audit.read",
    ]);
    expect(PERMISSION_CATALOG.map(({ authorityClass }) => authorityClass)).toEqual([
      "OWNER_EXCLUSIVE",
      "OWNER_EXCLUSIVE",
      "OWNER_EXCLUSIVE",
      "POLICY_DELEGABLE",
    ]);
  });

  it("binds required approval to the action, scope, and parameters", () => {
    PERMISSION_CATALOG.forEach((definition) => {
      if (definition.approval.required) {
        expect(definition.approval.approver).toBe("PLATFORM_OWNER");
        expect(definition.approval.bindsTo).toEqual(["ACTION", "SCOPE", "PARAMETERS"]);
        expect(typeof definition.approval.singleUse).toBe("boolean");
      }
    });
  });

  it("supports typed lookup and rejects unknown permission codes", () => {
    expect(isPermissionCode("platform.delegation.manage")).toBe(true);
    expect(isPermissionCode("platform.unknown.execute")).toBe(false);
    expect(getPermissionDefinition("platform.authorization-audit.read")?.scopeType).toBe("PLATFORM");
    expect(getPermissionDefinition("platform.unknown.execute")).toBeUndefined();
  });

  it("freezes catalogue entries and approval metadata", () => {
    expect(Object.isFrozen(PERMISSION_CATALOG)).toBe(true);
    expect(Object.isFrozen(PERMISSION_CATALOG[0])).toBe(true);
    expect(Object.isFrozen(PERMISSION_CATALOG[0]?.approval)).toBe(true);
    const ownerApproved = PERMISSION_CATALOG.find(({ approval }) => approval.required);
    if (ownerApproved?.approval.required) {
      expect(Object.isFrozen(ownerApproved.approval.bindsTo)).toBe(true);
    }
  });
});
