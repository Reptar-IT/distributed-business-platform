import { generateKeyPairSync } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { createAuditReceiptVerifier } from "./verifier.js";

describe("audit receipt verifier trust boundary", () => {
  const apps: Array<Awaited<ReturnType<typeof createAuditReceiptVerifier>>> = [];
  const serviceToken = "audit-receipt-verifier-test-token-with-256-bits";

  afterEach(async () => {
    await Promise.all(apps.splice(0).map((app) => app.close()));
  });

  async function createVerifier() {
    const app = await createAuditReceiptVerifier({
      // These requests are rejected before the verifier opens a database connection.
      databaseUrl: "postgresql://unused:unused@127.0.0.1:1/unused",
      serviceToken,
      trustedReceiptKeys: new Map([
        ["physical", new Map([["physical-key-v1", generateKeyPairSync("ed25519").publicKey]])],
      ]),
    });
    apps.push(app);
    return app;
  }

  it("rejects callers without the verifier service token", async () => {
    const app = await createVerifier();
    const missing = await app.inject({ method: "POST", url: "/v1/audit/receipts", payload: {} });
    const invalid = await app.inject({
      method: "POST",
      url: "/v1/audit/receipts",
      headers: { authorization: "Bearer another-service-token-with-enough-length" },
      payload: {},
    });
    expect(missing.statusCode).toBe(401);
    expect(invalid.statusCode).toBe(401);
  });

  it("rejects malformed or unpinned receipts before database access", async () => {
    const app = await createVerifier();
    const malformed = await app.inject({
      method: "POST",
      url: "/v1/audit/receipts",
      headers: { authorization: `Bearer ${serviceToken}` },
      payload: { batchId: "batch", destinationId: "physical" },
    });
    const unpinned = await app.inject({
      method: "POST",
      url: "/v1/audit/receipts",
      headers: { authorization: `Bearer ${serviceToken}` },
      payload: {
        batchId: "batch",
        destinationId: "physical",
        receipt: { payload: { keyId: "unknown-key" }, signature: "invalid" },
      },
    });
    expect(malformed.statusCode).toBe(400);
    expect(unpinned.statusCode).toBe(400);
  });
});
