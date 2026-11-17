import { describe, expectTypeOf, it } from "vitest";
import type {
  AuthorizationContext,
  CallingClientPrincipal,
  HumanPrincipal,
  MachinePrincipal,
  VerifiedPlatformOwnerDesignation,
} from "@platform/shared-types";
import type { PermissionCode } from "@platform/permissions";
import type { AuthorizationEvaluationInput } from "./contracts.js";

describe("authorization contracts", () => {
  it("keeps human and machine principals discriminated and non-interchangeable", () => {
    expectTypeOf<HumanPrincipal["kind"]>().toEqualTypeOf<"human">();
    expectTypeOf<MachinePrincipal["kind"]>().toEqualTypeOf<"machine">();
    expectTypeOf<HumanPrincipal>().not.toMatchTypeOf<MachinePrincipal>();
    expectTypeOf<MachinePrincipal>().not.toMatchTypeOf<HumanPrincipal>();
  });

  it("keeps owner context separate and requires an opaque verified designation", () => {
    expectTypeOf<Extract<AuthorizationContext, { kind: "platform_owner" }>>().toHaveProperty("designation");
    // @ts-expect-error A caller cannot fabricate the opaque owner designation.
    const forged: VerifiedPlatformOwnerDesignation = { designationId: "d" as never, platformUserId: "u" as never };
    expectTypeOf(forged).toMatchTypeOf<VerifiedPlatformOwnerDesignation>();
  });

  it("preserves the human and calling-client identities independently", () => {
    type Delegated = Extract<AuthorizationContext, { kind: "delegated_human_client" }>;
    expectTypeOf<Delegated["human"]>().toEqualTypeOf<HumanPrincipal>();
    expectTypeOf<Delegated["client"]>().toEqualTypeOf<CallingClientPrincipal>();
    expectTypeOf<Delegated["human"]>().not.toMatchTypeOf<CallingClientPrincipal>();
  });

  it("uses only known permission codes in evaluation input", () => {
    expectTypeOf<AuthorizationEvaluationInput["permission"]>().toEqualTypeOf<PermissionCode>();
    // @ts-expect-error Unknown strings are not valid permission codes.
    const unknownCode: PermissionCode = "platform.unknown.execute";
    expectTypeOf(unknownCode).toMatchTypeOf<PermissionCode>();
  });

  it("supports the three machine types", () => {
    const actors: MachinePrincipal["actorType"][] = ["AI_AGENT", "AUTOMATION", "SERVICE"];
    expectTypeOf(actors).toEqualTypeOf<MachinePrincipal["actorType"][]>();
  });
});
