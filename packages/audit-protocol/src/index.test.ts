import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  AUDIT_GENESIS_HASH,
  buildAuditBatch,
  canonicalizePg17EventV1,
  hashAuditEvent,
  signArchiveReceipt,
  verifyArchiveReceipt,
  type AuditEventWire,
} from "./index.js";

const streamId = "00000000-0000-0000-0000-000000000001";

describe("authorization audit protocol", () => {
  it("serializes PG17 event objects deterministically with explicit nulls", () => {
    expect(canonicalizePg17EventV1({ cc: "y", b: null, a: "x" })).toBe('{"a": "x", "b": null, "cc": "y"}');
    expect(canonicalizePg17EventV1({ a: "x", cc: "y", b: null })).toBe('{"a": "x", "b": null, "cc": "y"}');
    expect(canonicalizePg17EventV1({ z: "é", a: "e\u0301" })).toBe('{"a": "é", "z": "é"}');
    expect(() => canonicalizePg17EventV1({ amount: 1 })).toThrow(/Unsupported canonical event value/);
  });

  it("matches the stable single-event SHA-256 test vector", () => {
    expect(hashAuditEvent({
      streamId,
      sequence: "1",
      previousHash: AUDIT_GENESIS_HASH,
      canonicalPayload: '{"a": "x", "b": null, "cc": "y"}',
    })).toBe("a489b0d9cd4efa50379f87ddad50bf115385b235933e186ea57d1fd1efaa4616");
  });

  it("creates deterministic batches and rejects gaps or altered event payloads", () => {
    const payload1 = '{"eventType": "one"}';
    const hash1 = hashAuditEvent({ streamId, sequence: "1", previousHash: AUDIT_GENESIS_HASH, canonicalPayload: payload1 });
    const payload2 = '{"eventType": "two"}';
    const hash2 = hashAuditEvent({ streamId, sequence: "2", previousHash: hash1, canonicalPayload: payload2 });
    const events: AuditEventWire[] = [
      { sequence: "1", canonicalPayload: payload1, previousHash: AUDIT_GENESIS_HASH, eventHash: hash1 },
      { sequence: "2", canonicalPayload: payload2, previousHash: hash1, eventHash: hash2 },
    ];
    const batch = buildAuditBatch(streamId, events);
    expect(buildAuditBatch(streamId, events)).toEqual(batch);
    expect(batch.batchHash).toBe("b08d4b56b42e3b31fcb63e9bcf577ad80212d747c2bddeae3da051e36ff55f24");
    expect(() => buildAuditBatch(streamId, [events[0]!, { ...events[1]!, sequence: "3" }])).toThrow(/gap/);
    expect(() => buildAuditBatch(streamId, [{ ...events[0]!, canonicalPayload: '{"eventType": "altered"}' }])).toThrow(/hash/);
  });

  it("domain separates event and batch frames", () => {
    const eventHash = hashAuditEvent({ streamId, sequence: "1", previousHash: AUDIT_GENESIS_HASH, canonicalPayload: "{}" });
    const batch = buildAuditBatch(streamId, [{
      sequence: "1", canonicalPayload: "{}", previousHash: AUDIT_GENESIS_HASH, eventHash,
    }]);
    expect(batch.batchHash).not.toBe(eventHash);
  });

  it("signs destination-specific archive receipts and verifies expected batch fields", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const receipt = signArchiveReceipt({
      version: 1,
      destinationId: "physical",
      batchHash: "ab".repeat(32),
      firstSequence: "1",
      lastSequence: "1",
      terminalEventHash: "cd".repeat(32),
      acceptedAt: "2026-11-17T00:00:00.000Z",
      keyId: "physical-test-key-1",
    }, privateKey);
    expect(() => verifyArchiveReceipt(receipt, {
      destinationId: "physical",
      batchHash: "ab".repeat(32),
      firstSequence: "1",
      lastSequence: "1",
      terminalEventHash: "cd".repeat(32),
    }, publicKey)).not.toThrow();
    expect(() => verifyArchiveReceipt(receipt, {
      destinationId: "hosted",
      batchHash: "ab".repeat(32),
      firstSequence: "1",
      lastSequence: "1",
      terminalEventHash: "cd".repeat(32),
    }, publicKey)).toThrow(/mismatch/);
  });

  it("rejects wrong keys, signatures, ranges, hashes, and terminal event hashes", () => {
    const keys = generateKeyPairSync("ed25519");
    const otherKeys = generateKeyPairSync("ed25519");
    const receipt = signArchiveReceipt({
      version: 1,
      destinationId: "physical",
      batchHash: "ab".repeat(32),
      firstSequence: "4",
      lastSequence: "8",
      terminalEventHash: "cd".repeat(32),
      acceptedAt: "2026-11-17T00:00:00.000Z",
      keyId: "physical-key-1",
    }, keys.privateKey);
    const expected = {
      destinationId: "physical",
      batchHash: "ab".repeat(32),
      firstSequence: "4",
      lastSequence: "8",
      terminalEventHash: "cd".repeat(32),
    };
    expect(() => verifyArchiveReceipt(receipt, expected, otherKeys.publicKey)).toThrow(/signature/);
    expect(() => verifyArchiveReceipt({ ...receipt, signature: "AA" }, expected, keys.publicKey)).toThrow(/signature/);
    expect(() => verifyArchiveReceipt(receipt, { ...expected, batchHash: "ef".repeat(32) }, keys.publicKey)).toThrow(/mismatch/);
    expect(() => verifyArchiveReceipt(receipt, { ...expected, firstSequence: "5" }, keys.publicKey)).toThrow(/mismatch/);
    expect(() => verifyArchiveReceipt(receipt, { ...expected, lastSequence: "9" }, keys.publicKey)).toThrow(/mismatch/);
    expect(() => verifyArchiveReceipt(receipt, { ...expected, terminalEventHash: "ef".repeat(32) }, keys.publicKey)).toThrow(/mismatch/);
  });
});
