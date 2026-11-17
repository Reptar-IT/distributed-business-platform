import { createHash, sign, verify, type KeyObject } from "node:crypto";

export const AUDIT_HASH_VERSION = 1;
export const AUDIT_SERIALIZATION_VERSION = 1;
export const AUDIT_BATCH_PROTOCOL_VERSION = 1;

const EVENT_DOMAIN = Buffer.from("DBP-AUTHZ-EVENT\0", "ascii");
const BATCH_DOMAIN = Buffer.from("DBP-AUTHZ-BATCH\0", "ascii");
const RECEIPT_DOMAIN = Buffer.from("DBP-AUTHZ-ARCHIVE-RECEIPT\0", "ascii");
const ZERO_HASH_HEX = "00".repeat(32);

export interface AuditEventWire {
  readonly sequence: string;
  readonly canonicalPayload: string;
  readonly previousHash: string;
  readonly eventHash: string;
}

export interface AuditBatchWire {
  readonly protocolVersion: number;
  readonly serializationVersion: number;
  readonly hashVersion: number;
  readonly streamId: string;
  readonly firstSequence: string;
  readonly lastSequence: string;
  readonly eventCount: number;
  readonly previousHash: string;
  readonly terminalEventHash: string;
  readonly orderedEventHashesDigest: string;
  readonly batchHash: string;
  readonly events: readonly AuditEventWire[];
}

export interface ArchiveReceiptPayload {
  readonly version: 1;
  readonly destinationId: string;
  readonly batchHash: string;
  readonly firstSequence: string;
  readonly lastSequence: string;
  readonly terminalEventHash: string;
  readonly acceptedAt: string;
  readonly keyId: string;
}

export interface SignedArchiveReceipt {
  readonly payload: ArchiveReceiptPayload;
  readonly signature: string;
}

function uint16(value: number): Buffer {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) throw new Error("uint16 out of range");
  const out = Buffer.alloc(2);
  out.writeUInt16BE(value);
  return out;
}

function uint64(value: string | bigint): Buffer {
  const integer = typeof value === "bigint" ? value : BigInt(value);
  if (integer < 0n || integer > 0xffff_ffff_ffff_ffffn) throw new Error("uint64 out of range");
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(integer);
  return out;
}

function uuidBytes(value: string): Buffer {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) {
    throw new Error("Invalid UUID");
  }
  return Buffer.from(value.replaceAll("-", ""), "hex");
}

function hashBytes(value: string): Buffer {
  if (!/^[0-9a-f]{64}$/i.test(value)) throw new Error("Expected a 32-byte hexadecimal hash");
  return Buffer.from(value, "hex");
}

function digest(value: Uint8Array): Buffer {
  return createHash("sha256").update(value).digest();
}

function compareUtf8Keys(left: string, right: string): number {
  const leftBytes = Buffer.from(left, "utf8");
  const rightBytes = Buffer.from(right, "utf8");
  return leftBytes.length - rightBytes.length || Buffer.compare(leftBytes, rightBytes);
}

/** Mirrors PostgreSQL 17 jsonb text output for the flat string/null event schema. */
export function canonicalizePg17EventV1(value: unknown): string {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Audit event payload must be an object");
  }
  const entries = Object.entries(value as Record<string, unknown>);
  const invalidEntry = entries.find(([key, item]) => {
    if (typeof item !== "string" && item !== null) {
      return true;
    }
    if (key.includes("\u0000") || (typeof item === "string" && item.includes("\u0000"))) {
      return true;
    }
    return false;
  });
  if (invalidEntry) {
    const [key, item] = invalidEntry;
    if (typeof item !== "string" && item !== null) {
      throw new Error(`Unsupported canonical event value for ${key}`);
    }
    throw new Error("PostgreSQL text cannot contain a NUL character");
  }
  entries.sort(([left], [right]) => compareUtf8Keys(left, right));
  return `{${entries.map(([key, item]) => `${JSON.stringify(key)}: ${JSON.stringify(item)}`).join(", ")}}`;
}

export function frameAuditEvent(input: {
  readonly streamId: string;
  readonly sequence: string | bigint;
  readonly previousHash: string;
  readonly canonicalPayload: string;
  readonly serializationVersion?: number;
  readonly hashVersion?: number;
}): Buffer {
  if ((input.serializationVersion ?? AUDIT_SERIALIZATION_VERSION) !== AUDIT_SERIALIZATION_VERSION ||
      (input.hashVersion ?? AUDIT_HASH_VERSION) !== AUDIT_HASH_VERSION) {
    throw new Error("Unsupported audit event version");
  }
  const payload = Buffer.from(input.canonicalPayload, "utf8");
  return Buffer.concat([
    EVENT_DOMAIN,
    uint16(input.hashVersion ?? AUDIT_HASH_VERSION),
    uuidBytes(input.streamId),
    uint64(input.sequence),
    hashBytes(input.previousHash),
    uint64(BigInt(payload.length)),
    payload,
  ]);
}

export function hashAuditEvent(input: Parameters<typeof frameAuditEvent>[0]): string {
  return digest(frameAuditEvent(input)).toString("hex");
}

function batchFraming(batch: Omit<AuditBatchWire, "batchHash">): Buffer {
  const orderedHashes = Buffer.concat(batch.events.map((event) => hashBytes(event.eventHash)));
  const orderedHashesDigest = digest(orderedHashes);
  if (orderedHashesDigest.toString("hex") !== batch.orderedEventHashesDigest) {
    throw new Error("Ordered event-hash digest does not match");
  }
  return Buffer.concat([
    BATCH_DOMAIN,
    uint16(batch.protocolVersion),
    uuidBytes(batch.streamId),
    uint64(batch.firstSequence),
    uint64(batch.lastSequence),
    uint64(BigInt(batch.eventCount)),
    hashBytes(batch.previousHash),
    hashBytes(batch.terminalEventHash),
    hashBytes(batch.orderedEventHashesDigest),
  ]);
}

export function serializeAuditBatch(batch: AuditBatchWire): string {
  return JSON.stringify({
    protocolVersion: batch.protocolVersion,
    serializationVersion: batch.serializationVersion,
    hashVersion: batch.hashVersion,
    streamId: batch.streamId,
    firstSequence: batch.firstSequence,
    lastSequence: batch.lastSequence,
    eventCount: batch.eventCount,
    previousHash: batch.previousHash,
    terminalEventHash: batch.terminalEventHash,
    orderedEventHashesDigest: batch.orderedEventHashesDigest,
    batchHash: batch.batchHash,
    events: batch.events.map((event) => ({
      sequence: event.sequence,
      canonicalPayload: event.canonicalPayload,
      previousHash: event.previousHash,
      eventHash: event.eventHash,
    })),
  });
}

export function buildAuditBatch(streamId: string, events: readonly AuditEventWire[]): AuditBatchWire {
  if (events.length === 0) throw new Error("An audit batch cannot be empty");
  const first = BigInt(events[0]!.sequence);
  if (first < 1n) throw new Error("Audit sequences start at one");
  let previousHash = events[0]!.previousHash;
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index]!;
    if (BigInt(event.sequence) !== first + BigInt(index)) {
      throw new Error(`Audit batch has a sequence gap at index ${index}: expected ${first + BigInt(index)}, received ${event.sequence}`);
    }
    if (event.previousHash !== previousHash) throw new Error("Audit event chain is discontinuous");
    const parsed: unknown = JSON.parse(event.canonicalPayload);
    if (canonicalizePg17EventV1(parsed) !== event.canonicalPayload) throw new Error("Event payload is not canonical PG17 JSONB v1");
    const calculated = hashAuditEvent({ streamId, sequence: event.sequence, previousHash, canonicalPayload: event.canonicalPayload });
    if (calculated !== event.eventHash) throw new Error("Audit event hash does not match");
    previousHash = event.eventHash;
  }
  const orderedEventHashesDigest = digest(Buffer.concat(events.map((event) => hashBytes(event.eventHash)))).toString("hex");
  const core = {
    protocolVersion: AUDIT_BATCH_PROTOCOL_VERSION,
    serializationVersion: AUDIT_SERIALIZATION_VERSION,
    hashVersion: AUDIT_HASH_VERSION,
    streamId,
    firstSequence: first.toString(),
    lastSequence: (first + BigInt(events.length) - 1n).toString(),
    eventCount: events.length,
    previousHash: events[0]!.previousHash,
    terminalEventHash: events.at(-1)!.eventHash,
    orderedEventHashesDigest,
    events: [...events],
  } satisfies Omit<AuditBatchWire, "batchHash">;
  const batchHash = digest(batchFraming(core)).toString("hex");
  return { ...core, batchHash };
}

export function verifyAuditBatch(batch: AuditBatchWire): void {
  const rebuilt = buildAuditBatch(batch.streamId, batch.events);
  if (serializeAuditBatch(rebuilt) !== serializeAuditBatch(batch)) throw new Error("Audit batch framing or hash is invalid");
}

export function canonicalReceiptPayload(payload: ArchiveReceiptPayload): Buffer {
  if (payload.version !== 1) throw new Error("Unsupported archive receipt version");
  const ordered = {
    version: payload.version,
    destinationId: payload.destinationId,
    batchHash: payload.batchHash,
    firstSequence: payload.firstSequence,
    lastSequence: payload.lastSequence,
    terminalEventHash: payload.terminalEventHash,
    acceptedAt: payload.acceptedAt,
    keyId: payload.keyId,
  };
  return Buffer.concat([RECEIPT_DOMAIN, Buffer.from(JSON.stringify(ordered), "utf8")]);
}

export function signArchiveReceipt(payload: ArchiveReceiptPayload, privateKey: KeyObject): SignedArchiveReceipt {
  return { payload, signature: sign(null, canonicalReceiptPayload(payload), privateKey).toString("base64url") };
}

export function verifyArchiveReceipt(
  receipt: SignedArchiveReceipt,
  expected: Pick<ArchiveReceiptPayload, "destinationId" | "batchHash" | "firstSequence" | "lastSequence" | "terminalEventHash">,
  publicKey: KeyObject,
): void {
  const mismatchedEntry = Object.entries(expected).find(([key, value]) => receipt.payload[key as keyof typeof expected] !== value);
  if (mismatchedEntry) throw new Error(`Archive receipt mismatch: ${mismatchedEntry[0]}`);
  if (!receipt.payload.keyId || !Number.isFinite(Date.parse(receipt.payload.acceptedAt))) throw new Error("Malformed archive receipt");
  const signature = Buffer.from(receipt.signature, "base64url");
  if (signature.length !== 64 || !verify(null, canonicalReceiptPayload(receipt.payload), publicKey, signature)) {
    throw new Error("Invalid archive receipt signature");
  }
}

export const AUDIT_GENESIS_HASH = ZERO_HASH_HEX;
