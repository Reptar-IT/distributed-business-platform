import { createHmac, randomBytes, randomUUID } from "node:crypto";

const CODE_PREFIX = "dbp-rc-v1.";
const CODE_PATTERN = /^dbp-rc-v1\.([A-Za-z0-9_-]{43})$/;

export interface RecoveryVerifierKeyring {
  currentKeyId: string;
  keys: ReadonlyMap<string, Buffer>;
}

export interface RecoveryCodeRecord {
  id: string;
  keyId: string;
  verifier: string;
}

export interface RecoveryKitMaterial {
  kitId: string;
  codes: string[];
  records: RecoveryCodeRecord[];
}

function validKeyId(value: string): boolean {
  return /^[A-Za-z0-9._-]{1,100}$/.test(value);
}

export function parseRecoveryVerifierKeyring(encodedKeys: string, currentKeyId: string): RecoveryVerifierKeyring {
  let parsed: unknown;
  try {
    parsed = JSON.parse(encodedKeys);
  } catch {
    throw new Error("Owner recovery verifier key configuration is invalid");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || !validKeyId(currentKeyId)) {
    throw new Error("Owner recovery verifier key configuration is invalid");
  }
  const entries = Object.entries(parsed);
  if (entries.length < 1 || entries.length > 16) throw new Error("Owner recovery verifier key configuration is invalid");
  const keys = new Map(entries.map(([keyId, encoded]) => {
    if (!validKeyId(keyId) || typeof encoded !== "string") throw new Error("Owner recovery verifier key configuration is invalid");
    const key = Buffer.from(encoded, "base64url");
    if (key.length < 32 || key.toString("base64url") !== encoded) throw new Error("Owner recovery verifier key configuration is invalid");
    return [keyId, key] as const;
  }));
  if (!keys.has(currentKeyId)) throw new Error("Owner recovery verifier key configuration is invalid");
  return { currentKeyId, keys };
}

export function recoveryCodeVerifier(code: string, keyId: string, keyring: RecoveryVerifierKeyring): Buffer {
  const match = CODE_PATTERN.exec(code);
  const key = keyring.keys.get(keyId);
  if (!match || !key) throw new Error("Recovery code or verifier key is invalid");
  const normalizedCode = `${CODE_PREFIX}${match[1]}`;
  return createHmac("sha256", key)
    .update("DBP-OWNER-RECOVERY-CODE-v1\0", "utf8")
    .update(normalizedCode, "utf8")
    .digest();
}

export function createRecoveryKitMaterial(keyring: RecoveryVerifierKeyring): RecoveryKitMaterial {
  const codes = Array.from({ length: 10 }, () => `${CODE_PREFIX}${randomBytes(32).toString("base64url")}`);
  if (new Set(codes).size !== 10) throw new Error("Could not generate independent recovery codes");
  const records = codes.map((code) => ({
    id: randomUUID(),
    keyId: keyring.currentKeyId,
    verifier: recoveryCodeVerifier(code, keyring.currentKeyId, keyring).toString("hex"),
  }));
  return { kitId: randomUUID(), codes, records };
}

export function recoveryVerifierCandidates(code: string, keyring: RecoveryVerifierKeyring): Array<{ keyId: string; verifier: string }> {
  if (!CODE_PATTERN.test(code)) throw new Error("Recovery code was rejected");
  return [...keyring.keys.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([keyId]) => ({ keyId, verifier: recoveryCodeVerifier(code, keyId, keyring).toString("hex") }));
}
