import { describe, expect, it } from "vitest";
import { criticalOperationDigests } from "./critical-operations.js";

describe("critical-operation request framing", () => {
  it("uses stable key ordering and domain-separated digests", () => {
    const left = criticalOperationDigests("k".repeat(40), { target: "a", flags: [true, 2] });
    const right = criticalOperationDigests("k".repeat(40), { flags: [true, 2], target: "a" });
    expect(left).toEqual(right);
    expect(left.idempotencyDigest).toHaveLength(32);
    expect(left.requestFingerprint).toHaveLength(32);
    expect(left.idempotencyDigest.equals(left.requestFingerprint)).toBe(false);
  });

  it("rejects short or non-JSON idempotency input without storing it", () => {
    expect(() => criticalOperationDigests("short", {})).toThrow();
    expect(() => criticalOperationDigests("k".repeat(40), { missing: undefined })).toThrow();
    const a = criticalOperationDigests("a".repeat(40), { action: "same" });
    const b = criticalOperationDigests("b".repeat(40), { action: "same" });
    expect(a.idempotencyDigest.equals(b.idempotencyDigest)).toBe(false);
    expect(a.requestFingerprint.equals(b.requestFingerprint)).toBe(true);
  });
});
