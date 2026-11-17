import { readFile } from "node:fs/promises";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { createAuditArchive } from "./archive.js";

const storageDirectory = process.env.AUDIT_ARCHIVE_DIRECTORY;
const destinationId = process.env.AUDIT_ARCHIVE_DESTINATION_ID;
const receiptKeyId = process.env.AUDIT_ARCHIVE_RECEIPT_KEY_ID;
const signingKeyPath = process.env.AUDIT_ARCHIVE_SIGNING_PRIVATE_KEY_FILE;
const trustedKeysPath = process.env.AUDIT_ARCHIVE_TRUSTED_RECEIPT_KEYS_FILE;
const ingestToken = process.env.AUDIT_ARCHIVE_INGEST_TOKEN;

if (!storageDirectory || !destinationId || !receiptKeyId || !signingKeyPath || !ingestToken) {
  throw new Error("Audit archive configuration is incomplete");
}

const signingPrivateKey = createPrivateKey(await readFile(signingKeyPath));
if (signingPrivateKey.asymmetricKeyType !== "ed25519") {
  throw new Error("Archive receipt key must be Ed25519");
}
const trustedReceiptPublicKeys = new Map();
if (trustedKeysPath) {
  const keyFiles = JSON.parse(await readFile(trustedKeysPath, "utf8")) as Record<string, string>;
  for (const [keyId, path] of Object.entries(keyFiles)) {
    trustedReceiptPublicKeys.set(keyId, createPublicKey(await readFile(path)));
  }
}
trustedReceiptPublicKeys.set(receiptKeyId, createPublicKey(signingPrivateKey));

const app = await createAuditArchive({
  storageDirectory,
  destinationId,
  receiptKeyId,
  ingestToken,
  signingPrivateKey,
  trustedReceiptPublicKeys,
});
const port = Number(process.env.AUDIT_ARCHIVE_PORT ?? 8090);
await app.listen({ host: "127.0.0.1", port });

const shutdown = async () => {
  await app.close();
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
