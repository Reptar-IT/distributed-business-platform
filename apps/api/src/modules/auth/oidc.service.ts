import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { Redis as RedisClient } from "ioredis";
import * as oidc from "openid-client";

export interface OidcSettings {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  postLogoutRedirectUri: string;
}

export interface OidcIdentity {
  issuer: string;
  subject: string;
}

export interface VerifiedIdentityLinkProof {
  challengeId: string;
  identity: OidcIdentity;
  verifiedAt: Date;
}

export interface IdentityLinkConfirmation {
  challengeId: string;
  platformUserId: string;
  issuer: string;
  csrfToken: string;
}

export interface VerifiedOwnerRecoveryProof {
  operationId: string;
  identity: OidcIdentity;
  verifiedAt: Date;
}

export interface OidcService {
  startLogin(browserBinding: string): Promise<{ state: string; authorizationUrl: string }>;
  completeLogin(callbackUrl: URL, state: string, browserBinding: string): Promise<OidcIdentity>;
  startIdentityLink(challengeId: string): Promise<{ authorizationUrl: string }>;
  completeIdentityLink(callbackUrl: URL, state: string): Promise<VerifiedIdentityLinkProof>;
  startOwnerRecovery(operationId: string): Promise<{ authorizationUrl: string }>;
  completeOwnerRecovery(callbackUrl: URL, state: string): Promise<VerifiedOwnerRecoveryProof>;
  createIdentityLinkConfirmation(proof: VerifiedIdentityLinkProof, platformUserId: string): Promise<{ confirmationId: string; browserBinding: string }>;
  getIdentityLinkConfirmation(confirmationId: string, browserBinding: string): Promise<IdentityLinkConfirmation | null>;
  consumeIdentityLinkConfirmation(confirmationId: string, csrfToken: string, browserBinding: string): Promise<(VerifiedIdentityLinkProof & { platformUserId: string }) | null>;
  createLogoutState(): Promise<string>;
  consumeLogoutState(state: string): Promise<boolean>;
  buildLogoutUrl(state: string): Promise<string>;
}

const OIDC_TRANSACTION_TTL_SECONDS = 5 * 60;
const IDENTITY_LINK_TTL_SECONDS = 5 * 60;
const IDENTITY_LINK_CONFIRMATION_TTL_SECONDS = 5 * 60;
const MAX_IDENTITY_LINK_AUTH_AGE_SECONDS = 5 * 60;
const OIDC_LOGOUT_STATE_TTL_SECONDS = 5 * 60;

function safeEqual(left: string, right: string): boolean {
  const leftDigest = createHmac("sha256", "dbp-oidc-binding").update(left).digest();
  const rightDigest = createHmac("sha256", "dbp-oidc-binding").update(right).digest();
  return timingSafeEqual(leftDigest, rightDigest);
}

export function createOidcService(
  options: OidcSettings & { redis: RedisClient },
): OidcService {
  let configPromise: Promise<oidc.Configuration> | undefined;

  function getConfig(): Promise<oidc.Configuration> {
    if (!configPromise) {
      const issuerUrl = new URL(options.issuer);
      const discoveryOptions = issuerUrl.protocol === "http:" && issuerUrl.hostname === "localhost"
        ? { execute: [oidc.allowInsecureRequests] }
        : undefined;

      configPromise = oidc.discovery(
        issuerUrl,
        options.clientId,
        options.clientSecret,
        oidc.ClientSecretBasic(options.clientSecret),
        discoveryOptions,
      );
    }
    return configPromise;
  }

  return {
    async startLogin(browserBinding) {
      const config = await getConfig();
      const state = oidc.randomState();
      const nonce = oidc.randomNonce();
      const codeVerifier = oidc.randomPKCECodeVerifier();
      const codeChallenge = await oidc.calculatePKCECodeChallenge(codeVerifier);
      const transaction = JSON.stringify({ nonce, codeVerifier, browserBinding });
      const stored = await options.redis.set(
        `dbp:oidc:transaction:${state}`,
        transaction,
        "EX",
        OIDC_TRANSACTION_TTL_SECONDS,
        "NX",
      );
      if (stored !== "OK") throw new Error("Could not store OIDC transaction");

      const authorizationUrl = oidc.buildAuthorizationUrl(config, {
        client_id: options.clientId,
        redirect_uri: options.redirectUri,
        response_type: "code",
        scope: "openid",
        state,
        nonce,
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
      });

      return { state, authorizationUrl: authorizationUrl.href };
    },

    async completeLogin(callbackUrl, state, browserBinding) {
      if (!/^[A-Za-z0-9_-]{20,}$/.test(state)) throw new Error("Invalid OIDC state");
      const serialized = await options.redis.getdel(`dbp:oidc:transaction:${state}`);
      if (!serialized) throw new Error("Expired OIDC transaction");

      let transaction: { nonce: string; codeVerifier: string; browserBinding: string };
      try {
        transaction = JSON.parse(serialized) as typeof transaction;
      } catch {
        throw new Error("Invalid OIDC transaction");
      }
      if (!safeEqual(transaction.browserBinding, browserBinding)) {
        throw new Error("OIDC transaction browser mismatch");
      }

      const config = await getConfig();
      const tokens = await oidc.authorizationCodeGrant(config, callbackUrl, {
        pkceCodeVerifier: transaction.codeVerifier,
        expectedState: state,
        expectedNonce: transaction.nonce,
      });
      const claims = tokens.claims();
      if (!claims || claims.iss !== options.issuer || typeof claims.sub !== "string" || claims.sub.length === 0 ||
          (claims.azp !== undefined && claims.azp !== options.clientId)) {
        throw new Error("OIDC identity claims are invalid");
      }

      return { issuer: claims.iss, subject: claims.sub };
    },

    async startIdentityLink(challengeId) {
      if (!/^[0-9a-f-]{36}$/i.test(challengeId)) throw new Error("Invalid identity-link challenge");
      const config = await getConfig();
      const state = `il_${oidc.randomState()}`;
      const nonce = oidc.randomNonce();
      const codeVerifier = oidc.randomPKCECodeVerifier();
      const codeChallenge = await oidc.calculatePKCECodeChallenge(codeVerifier);
      const stored = await options.redis.set(
        `dbp:oidc:identity-link:${state}`,
        JSON.stringify({ challengeId, nonce, codeVerifier }),
        "EX",
        IDENTITY_LINK_TTL_SECONDS,
        "NX",
      );
      if (stored !== "OK") throw new Error("Could not store identity-link transaction");

      const authorizationUrl = oidc.buildAuthorizationUrl(config, {
        client_id: options.clientId,
        redirect_uri: options.redirectUri,
        response_type: "code",
        scope: "openid",
        state,
        nonce,
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        prompt: "login",
        max_age: "0",
      });
      return { authorizationUrl: authorizationUrl.href };
    },

    async startOwnerRecovery(operationId) {
      if (!/^[0-9a-f-]{36}$/i.test(operationId)) throw new Error("Invalid owner-recovery operation");
      const config = await getConfig();
      const state = `or_${oidc.randomState()}`;
      const nonce = oidc.randomNonce();
      const codeVerifier = oidc.randomPKCECodeVerifier();
      const codeChallenge = await oidc.calculatePKCECodeChallenge(codeVerifier);
      const stored = await options.redis.set(
        `dbp:oidc:owner-recovery:${state}`,
        JSON.stringify({ operationId, nonce, codeVerifier }),
        "EX",
        OIDC_TRANSACTION_TTL_SECONDS,
        "NX",
      );
      if (stored !== "OK") throw new Error("Could not store owner-recovery transaction");
      const authorizationUrl = oidc.buildAuthorizationUrl(config, {
        client_id: options.clientId,
        redirect_uri: options.redirectUri,
        response_type: "code",
        scope: "openid",
        state,
        nonce,
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        prompt: "login",
        max_age: "0",
      });
      return { authorizationUrl: authorizationUrl.href };
    },

    async completeOwnerRecovery(callbackUrl, state) {
      if (!/^or_[A-Za-z0-9_-]{20,}$/.test(state)) throw new Error("Invalid owner-recovery state");
      const serialized = await options.redis.getdel(`dbp:oidc:owner-recovery:${state}`);
      if (!serialized) throw new Error("Expired owner-recovery transaction");
      let transaction: { operationId: string; nonce: string; codeVerifier: string };
      try {
        transaction = JSON.parse(serialized) as typeof transaction;
        if (!/^[0-9a-f-]{36}$/i.test(transaction.operationId)) throw new Error("Invalid operation binding");
      } catch {
        throw new Error("Invalid owner-recovery transaction");
      }
      try {
        const config = await getConfig();
        const tokens = await oidc.authorizationCodeGrant(config, callbackUrl, {
          pkceCodeVerifier: transaction.codeVerifier,
          expectedState: state,
          expectedNonce: transaction.nonce,
        });
        const claims = tokens.claims();
        const nowSeconds = Math.floor(Date.now() / 1000);
        const authTime = claims?.auth_time;
        if (!claims || claims.iss !== options.issuer || typeof claims.sub !== "string" || claims.sub.length === 0 ||
            (claims.azp !== undefined && claims.azp !== options.clientId) ||
            typeof authTime !== "number" || !Number.isInteger(authTime) || authTime > nowSeconds + 60 ||
            nowSeconds - authTime > MAX_IDENTITY_LINK_AUTH_AGE_SECONDS) {
          throw new Error("OIDC recovery proof is invalid or stale");
        }
        return {
          operationId: transaction.operationId,
          identity: { issuer: claims.iss, subject: claims.sub },
          verifiedAt: new Date(authTime * 1000),
        };
      } catch {
        throw new OwnerRecoveryVerificationError(transaction.operationId, "oidc_proof_rejected");
      }
    },

    async completeIdentityLink(callbackUrl, state) {
      if (!/^il_[A-Za-z0-9_-]{20,}$/.test(state)) throw new Error("Invalid identity-link state");
      const serialized = await options.redis.getdel(`dbp:oidc:identity-link:${state}`);
      if (!serialized) throw new Error("Expired identity-link transaction");
      let transaction: { challengeId: string; nonce: string; codeVerifier: string };
      try {
        transaction = JSON.parse(serialized) as typeof transaction;
      } catch {
        throw new Error("Invalid identity-link transaction");
      }

      try {
        const config = await getConfig();
        const tokens = await oidc.authorizationCodeGrant(config, callbackUrl, {
          pkceCodeVerifier: transaction.codeVerifier,
          expectedState: state,
          expectedNonce: transaction.nonce,
        });
        const claims = tokens.claims();
        const nowSeconds = Math.floor(Date.now() / 1000);
        const authTime = claims?.auth_time;
        if (
          !claims || claims.iss !== options.issuer || typeof claims.sub !== "string" || claims.sub.length === 0 ||
          (claims.azp !== undefined && claims.azp !== options.clientId) ||
          typeof authTime !== "number" || !Number.isInteger(authTime) ||
          authTime > nowSeconds + 60 || nowSeconds - authTime > MAX_IDENTITY_LINK_AUTH_AGE_SECONDS
        ) {
          throw new Error("OIDC proof is not fresh or does not identify the configured issuer");
        }
        return {
          challengeId: transaction.challengeId,
          identity: { issuer: claims.iss, subject: claims.sub },
          verifiedAt: new Date(authTime * 1000),
        };
      } catch {
        throw new IdentityLinkVerificationError(transaction.challengeId, "oidc_proof_rejected");
      }
    },

    async createIdentityLinkConfirmation(proof, platformUserId) {
      const confirmationId = randomBytes(32).toString("base64url");
      const browserBinding = randomBytes(32).toString("base64url");
      const csrfToken = randomBytes(32).toString("base64url");
      const stored = await options.redis.set(
        `dbp:oidc:identity-link-confirmation:${confirmationId}`,
        JSON.stringify({ ...proof, platformUserId, csrfToken, browserBinding }),
        "EX",
        IDENTITY_LINK_CONFIRMATION_TTL_SECONDS,
        "NX",
      );
      if (stored !== "OK") throw new Error("Could not store identity-link confirmation");
      return { confirmationId, browserBinding };
    },

    async getIdentityLinkConfirmation(confirmationId, browserBinding) {
      if (!/^[A-Za-z0-9_-]{43}$/.test(confirmationId) || !browserBinding) return null;
      const serialized = await options.redis.get(`dbp:oidc:identity-link-confirmation:${confirmationId}`);
      const confirmation = readIdentityLinkConfirmation(serialized);
      if (!confirmation || !safeEqual(confirmation.browserBinding, browserBinding)) return null;
      return {
        challengeId: confirmation.challengeId,
        platformUserId: confirmation.platformUserId,
        issuer: confirmation.identity.issuer,
        csrfToken: confirmation.csrfToken,
      };
    },

    async consumeIdentityLinkConfirmation(confirmationId, csrfToken, browserBinding) {
      if (!/^[A-Za-z0-9_-]{43}$/.test(confirmationId) || !csrfToken || !browserBinding) return null;
      const serialized = await options.redis.getdel(`dbp:oidc:identity-link-confirmation:${confirmationId}`);
      const confirmation = readIdentityLinkConfirmation(serialized);
      if (!confirmation || !safeEqual(confirmation.csrfToken, csrfToken) ||
          !safeEqual(confirmation.browserBinding, browserBinding)) return null;
      return {
        challengeId: confirmation.challengeId,
        identity: confirmation.identity,
        verifiedAt: confirmation.verifiedAt,
        platformUserId: confirmation.platformUserId,
      };
    },

    async buildLogoutUrl(state) {
      const config = await getConfig();
      const endSessionEndpoint = config.serverMetadata().end_session_endpoint;
      if (!endSessionEndpoint) throw new Error("OIDC provider does not publish an end-session endpoint");
      const logoutUrl = new URL(endSessionEndpoint);
      logoutUrl.searchParams.set("client_id", options.clientId);
      logoutUrl.searchParams.set("post_logout_redirect_uri", options.postLogoutRedirectUri);
      logoutUrl.searchParams.set("state", state);
      return logoutUrl.href;
    },

    async createLogoutState() {
      const state = oidc.randomState();
      const stored = await options.redis.set(
        `dbp:oidc:logout:${state}`,
        "1",
        "EX",
        OIDC_LOGOUT_STATE_TTL_SECONDS,
        "NX",
      );
      if (stored !== "OK") throw new Error("Could not store OIDC logout state");
      return state;
    },

    async consumeLogoutState(state) {
      if (!/^[A-Za-z0-9_-]{20,}$/.test(state)) return false;
      return (await options.redis.getdel(`dbp:oidc:logout:${state}`)) === "1";
    },
  };
}

interface StoredIdentityLinkConfirmation extends VerifiedIdentityLinkProof {
  platformUserId: string;
  csrfToken: string;
  browserBinding: string;
}

function readIdentityLinkConfirmation(serialized: string | null): StoredIdentityLinkConfirmation | null {
  if (!serialized) return null;
  try {
    const value = JSON.parse(serialized) as Partial<StoredIdentityLinkConfirmation>;
    if (typeof value.challengeId !== "string" || typeof value.platformUserId !== "string" ||
        typeof value.csrfToken !== "string" || typeof value.browserBinding !== "string" ||
        typeof value.identity?.issuer !== "string" || typeof value.identity?.subject !== "string" ||
        typeof value.verifiedAt !== "string") return null;
    const verifiedAt = new Date(value.verifiedAt);
    if (Number.isNaN(verifiedAt.getTime())) return null;
    return { ...(value as StoredIdentityLinkConfirmation), verifiedAt };
  } catch {
    return null;
  }
}

export class IdentityLinkVerificationError extends Error {
  constructor(readonly challengeId: string, readonly outcomeCode: string) {
    super("Identity-link proof could not be verified");
    this.name = "IdentityLinkVerificationError";
  }
}

export class OwnerRecoveryVerificationError extends Error {
  constructor(readonly operationId: string, readonly outcomeCode: string) {
    super("Owner-recovery proof could not be verified");
    this.name = "OwnerRecoveryVerificationError";
  }
}

export function createBrowserBinding(): string {
  return randomBytes(32).toString("base64url");
}
