import { describe, expect, it } from "vitest";
import {
  createRecoveryKitMaterial,
  parseRecoveryVerifierKeyring,
  recoveryCodeVerifier,
  recoveryVerifierCandidates,
} from "./recovery-codes.js";

const firstKey = Buffer.alloc(32, 0x31);
const secondKey = Buffer.alloc(32, 0x72);

describe("owner recovery codes", () => {
  it("generates exactly ten independently random 256-bit codes and returns only keyed verifiers for storage", () => {
    const keyring = { currentKeyId: "key-v1", keys: new Map([["key-v1", firstKey]]) };
    const first = createRecoveryKitMaterial(keyring);
    const second = createRecoveryKitMaterial(keyring);

    expect(first.codes).toHaveLength(10);
    expect(new Set(first.codes).size).toBe(10);
    expect(new Set([...first.codes, ...second.codes]).size).toBe(20);
    expect(first.records).toHaveLength(10);
    expect(first.codes.every((code) => Buffer.from(code.slice("dbp-rc-v1.".length), "base64url").length === 32)).toBe(true);
    expect(first.records.every((record) => record.verifier.length === 64 && !first.codes.includes(record.verifier))).toBe(true);
    expect(first.records.every((record) => record.keyId === "key-v1")).toBe(true);
  });

  it("validates codes with keyed HMAC and retains old key IDs during rotation", () => {
    const oldRing = { currentKeyId: "key-v1", keys: new Map([["key-v1", firstKey]]) };
    const kit = createRecoveryKitMaterial(oldRing);
    const rotatedRing = { currentKeyId: "key-v2", keys: new Map([["key-v1", firstKey], ["key-v2", secondKey]]) };
    const candidates = recoveryVerifierCandidates(kit.codes[0]!, rotatedRing);

    expect(candidates).toHaveLength(2);
    expect(candidates.find((candidate) => candidate.keyId === "key-v1")?.verifier).toBe(kit.records[0]!.verifier);
    expect(candidates.find((candidate) => candidate.keyId === "key-v2")?.verifier).not.toBe(kit.records[0]!.verifier);
    expect(recoveryCodeVerifier(kit.codes[0]!, "key-v1", rotatedRing)).toEqual(Buffer.from(kit.records[0]!.verifier, "hex"));
    expect(() => recoveryCodeVerifier("dbp-rc-v1.invalid", "key-v1", rotatedRing)).toThrow();
  });

  it("rejects weak, malformed, or missing current verifier keys", () => {
    expect(() => parseRecoveryVerifierKeyring(JSON.stringify({ "key-v1": Buffer.alloc(16).toString("base64url") }), "key-v1")).toThrow();
    expect(() => parseRecoveryVerifierKeyring(JSON.stringify({ "key-v1": firstKey.toString("base64url") }), "key-v2")).toThrow();
    expect(() => parseRecoveryVerifierKeyring("not-json", "key-v1")).toThrow();
  });
});
