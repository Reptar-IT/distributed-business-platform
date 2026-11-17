import { readFile } from "node:fs/promises";
import { createPublicKey } from "node:crypto";
import { createAuditReceiptVerifier } from "./verifier.js";

const databaseUrl = process.env.AUDIT_RECEIPT_VERIFIER_DATABASE_URL;
const serviceToken = process.env.AUDIT_RECEIPT_VERIFIER_SERVICE_TOKEN;
const trustedKeysFile = process.env.AUDIT_RECEIPT_VERIFIER_TRUSTED_KEYS_FILE;
if (!databaseUrl || !serviceToken || !trustedKeysFile) {
  throw new Error("Receipt verifier configuration is incomplete");
}

const keyPaths = JSON.parse(await readFile(trustedKeysFile, "utf8")) as Record<string, Record<string, string>>;
const trustedReceiptKeys = new Map<string, Map<string, ReturnType<typeof createPublicKey>>>();
for (const [destinationId, keys] of Object.entries(keyPaths)) {
  const destinationKeys = new Map<string, ReturnType<typeof createPublicKey>>();
  for (const [keyId, path] of Object.entries(keys)) {
    destinationKeys.set(keyId, createPublicKey(await readFile(path)));
  }
  trustedReceiptKeys.set(destinationId, destinationKeys);
}

const app = await createAuditReceiptVerifier({ databaseUrl, serviceToken, trustedReceiptKeys });
const port = Number(process.env.AUDIT_RECEIPT_VERIFIER_PORT ?? 8091);
await app.listen({ host: process.env.AUDIT_RECEIPT_VERIFIER_HOST ?? "127.0.0.1", port });

const shutdown = async () => {
  await app.close();
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
