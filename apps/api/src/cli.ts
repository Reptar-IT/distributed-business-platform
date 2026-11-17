import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import { createHmac, randomBytes } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";
import { Redis } from "ioredis";
import { createIdentityLinkOperatorService } from "./modules/identity-link/identity-link.service.js";
import { createOidcService } from "./modules/auth/oidc.service.js";
import { createPlatformOwnerOperatorService } from "./modules/owner/owner-bootstrap.service.js";
import { readSecretNoEcho } from "./modules/owner/secure-terminal.js";

const USER_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CREDENTIAL_ID_PATTERN = USER_ID_PATTERN;
dotenv.config({ path: resolve(dirname(fileURLToPath(import.meta.url)), "../../../.env") });

async function confirm(prompt: string, expected: string): Promise<void> {
  if (!input.isTTY || !output.isTTY) throw new Error("This command requires an interactive terminal");
  const terminal = createInterface({ input, output });
  const answer = await terminal.question(`${prompt} Type ${expected} to continue: `);
  terminal.close();
  if (answer !== expected) throw new Error("Operation was not confirmed");
}

function credentialConfiguration(): { databaseUrl: string; key: Buffer; keyId: string; issuer: string } {
  const databaseUrl = process.env.PLATFORM_OWNER_OPERATOR_DATABASE_URL;
  const encodedKey = process.env.PLATFORM_OWNER_VERIFIER_KEY;
  const keyId = process.env.PLATFORM_OWNER_VERIFIER_KEY_ID;
  const issuer = process.env.OIDC_ISSUER_URL;
  if (!databaseUrl || !encodedKey || !keyId || !issuer) throw new Error("Platform-owner CLI configuration is incomplete");
  const key = Buffer.from(encodedKey, "base64url");
  if (key.length < 32) throw new Error("Platform-owner verifier key configuration is invalid");
  return { databaseUrl, key, keyId, issuer };
}

function credentialVerifier(token: string, credentialId: string, platformUserId: string, keyId: string, key: Buffer): Buffer {
  return createHmac("sha256", key)
    .update("DBP-PLATFORM-OWNER-BOOTSTRAP-v1\0", "utf8")
    .update(credentialId, "utf8").update("\0", "utf8")
    .update(platformUserId, "utf8").update("\0", "utf8")
    .update(keyId, "utf8").update("\0", "utf8")
    .update(token, "utf8").digest();
}

async function beginIdentityLink(platformUserId: string): Promise<void> {
  if (!USER_ID_PATTERN.test(platformUserId)) throw new Error("A valid existing PlatformUser UUID is required");
  const databaseUrl = process.env.IDENTITY_LINK_OPERATOR_DATABASE_URL;
  const issuer = process.env.OIDC_ISSUER_URL;
  const clientId = process.env.OIDC_CLIENT_ID;
  const clientSecret = process.env.OIDC_CLIENT_SECRET;
  const redirectUri = process.env.OIDC_REDIRECT_URI;
  const redisUrl = process.env.REDIS_URL;
  if (!databaseUrl || !issuer || !clientId || !clientSecret || !redirectUri || !redisUrl) {
    throw new Error("Identity-link CLI configuration is incomplete");
  }
  await confirm(`Begin OIDC identity proof for existing PlatformUser ${platformUserId}?`, "LINK");

  const operator = createIdentityLinkOperatorService(databaseUrl);
  const redis = new Redis(redisUrl, { maxRetriesPerRequest: 1 });
  try {
    const challengeId = await operator.begin(platformUserId, issuer);
    const oidc = createOidcService({
      redis,
      issuer,
      clientId,
      clientSecret,
      redirectUri,
      postLogoutRedirectUri: redirectUri,
    });
    const { authorizationUrl } = await oidc.startIdentityLink(challengeId);
    output.write(`Open this URL in the identity holder's browser within five minutes:\n${authorizationUrl}\n`);
  } finally {
    await redis.quit();
    await operator.close();
  }
}

async function issueOwnerCredential(platformUserId: string): Promise<void> {
  if (!USER_ID_PATTERN.test(platformUserId)) throw new Error("A valid existing PlatformUser UUID is required");
  await confirm(`Issue one-time owner-bootstrap credential bound to PlatformUser ${platformUserId}?`, "ISSUE OWNER CREDENTIAL");
  const configuration = credentialConfiguration();
  const operator = createPlatformOwnerOperatorService(configuration.databaseUrl);
  let token = "";
  try {
    const hex = randomBytes(16).toString("hex");
    const credentialId = `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
    token = `dbp-owner-v1.${credentialId}.${randomBytes(32).toString("base64url")}`;
    const verifier = credentialVerifier(token, credentialId, platformUserId, configuration.keyId, configuration.key);
    const expiresAt = await operator.issueCredential({
      credentialId, platformUserId, issuer: configuration.issuer, keyId: configuration.keyId, verifier,
    });
    output.write(`One-time credential (store securely; displayed once):\n${token}\nExpires at: ${expiresAt.toISOString()}\n`);
  } finally {
    token = "";
    configuration.key.fill(0);
    await operator.close();
  }
}

async function bootstrapOwner(platformUserId: string): Promise<void> {
  if (!USER_ID_PATTERN.test(platformUserId)) throw new Error("A valid existing PlatformUser UUID is required");
  await confirm(`Prepare receipt-gated initial owner designation for PlatformUser ${platformUserId}?`, "BOOTSTRAP OWNER");
  const configuration = credentialConfiguration();
  const operator = createPlatformOwnerOperatorService(configuration.databaseUrl);
  let token = "";
  try {
    token = await readSecretNoEcho(input,output,"Enter one-time bootstrap credential (input hidden): ");
    const match = /^dbp-owner-v1\.([0-9a-f-]{36})\.([A-Za-z0-9_-]{43})$/.exec(token);
    if (!match || !CREDENTIAL_ID_PATTERN.test(match[1]!)) throw new Error("Credential rejected");
    const credentialId = match[1]!;
    const verifier = credentialVerifier(token, credentialId, platformUserId, configuration.keyId, configuration.key);
    const operationId = await operator.prepare({ credentialId, platformUserId, verifier });
    output.write(`Bootstrap prepared as critical operation ${operationId}. Activation remains pending required archive confirmation.\n`);
  } catch {
    try { await operator.recordRejection(platformUserId,"bootstrap_rejected"); } catch { /* Keep secret and database failures out of output. */ }
    throw new Error("Bootstrap credential was rejected or the operation could not be prepared");
  } finally {
    token = "";
    configuration.key.fill(0);
    await operator.close();
  }
}

async function showOwnerBootstrapStatus(credentialId: string): Promise<void> {
  if (!CREDENTIAL_ID_PATTERN.test(credentialId)) throw new Error("A valid credential UUID is required");
  const databaseUrl = process.env.PLATFORM_OWNER_OPERATOR_DATABASE_URL;
  if (!databaseUrl) throw new Error("Platform-owner CLI configuration is incomplete");
  const operator = createPlatformOwnerOperatorService(databaseUrl);
  try {
    const status = await operator.status(credentialId);
    if (!status) throw new Error("Bootstrap credential was not found");
    output.write(`${JSON.stringify(status, null, 2)}\n`);
  } finally {
    await operator.close();
  }
}

try {
  const [command, argument, maybeUserId, ...extra] = process.argv.slice(2);
  if (extra.length > 0) throw new Error("Invalid command arguments");
  if (command === "identity-link" && argument) await beginIdentityLink(argument);
  else if (command === "owner-credential" && argument === "issue" && maybeUserId) await issueOwnerCredential(maybeUserId);
  else if (command === "owner-bootstrap" && argument === "run" && maybeUserId) await bootstrapOwner(maybeUserId);
  else if (command === "owner-bootstrap" && argument === "status" && maybeUserId) await showOwnerBootstrapStatus(maybeUserId);
  else throw new Error("Invalid platform CLI command");
} catch {
  output.write("Operation failed or was rejected. No secret values are displayed.\n");
  process.exitCode = 1;
}
