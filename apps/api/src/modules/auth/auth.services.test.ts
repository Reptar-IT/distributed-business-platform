import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Redis } from "ioredis";
import type { PrismaClient } from "@platform/database";
import { createIdentityService } from "./identity.service.js";
import { createOidcService } from "./oidc.service.js";

const oidcMocks = vi.hoisted(() => ({
  discovery: vi.fn(),
  clientSecretBasic: vi.fn(() => ({ method: "client_secret_basic" })),
  allowInsecureRequests: vi.fn(),
  randomState: vi.fn(() => "state_value_012345678901234567890"),
  randomNonce: vi.fn(() => "nonce_value_012345678901234567890"),
  randomPKCECodeVerifier: vi.fn(() => "a-long-pkce-code-verifier-value"),
  calculatePKCECodeChallenge: vi.fn(async () => "pkce-challenge-value"),
  buildAuthorizationUrl: vi.fn(),
  authorizationCodeGrant: vi.fn(),
}));

vi.mock("openid-client", () => ({
  discovery: oidcMocks.discovery,
  ClientSecretBasic: oidcMocks.clientSecretBasic,
  allowInsecureRequests: oidcMocks.allowInsecureRequests,
  randomState: oidcMocks.randomState,
  randomNonce: oidcMocks.randomNonce,
  randomPKCECodeVerifier: oidcMocks.randomPKCECodeVerifier,
  calculatePKCECodeChallenge: oidcMocks.calculatePKCECodeChallenge,
  buildAuthorizationUrl: oidcMocks.buildAuthorizationUrl,
  authorizationCodeGrant: oidcMocks.authorizationCodeGrant,
}));

class MemoryRedis {
  values = new Map<string, string>();

  async set(key: string, value: string): Promise<"OK"> {
    this.values.set(key, value);
    return "OK";
  }

  async getdel(key: string): Promise<string | null> {
    const value = this.values.get(key) ?? null;
    this.values.delete(key);
    return value;
  }

  async get(key: string): Promise<string | null> {
    return this.values.get(key) ?? null;
  }
}

describe("identity and OIDC services", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    oidcMocks.buildAuthorizationUrl.mockReturnValue(new URL("http://keycloak.test/auth"));
    oidcMocks.authorizationCodeGrant.mockResolvedValue({
      claims: () => ({
        iss: "http://localhost:8080/realms/distributed-business-platform",
        sub: "external-subject",
        auth_time: Math.floor(Date.now() / 1000),
      }),
    });
    oidcMocks.discovery.mockResolvedValue({
      serverMetadata: () => ({
        end_session_endpoint: "http://localhost:8080/realms/distributed-business-platform/protocol/openid-connect/logout",
      }),
    });
  });

  it("resolves only by issuer plus subject and rejects non-active platform users", async () => {
    const findUnique = vi.fn()
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce({
        user: { id: "user-2", displayName: "Suspended", status: "SUSPENDED" },
        verification: { id: "verified-link-2" },
      })
      .mockResolvedValueOnce({
        user: { id: "user-3", displayName: "Active", status: "ACTIVE" },
        verification: { id: "verified-link-3" },
      })
      .mockResolvedValueOnce({
        user: { id: "user-4", displayName: "Unverified", status: "ACTIVE" },
        verification: null,
      });
    const prisma = {
      userIdentity: { findUnique },
      platformUser: { findUnique: vi.fn() },
    } as unknown as PrismaClient;
    const identities = createIdentityService(prisma);

    expect(await identities.resolveActiveIdentity("issuer", "unknown")).toBeNull();
    expect(await identities.resolveActiveIdentity("issuer", "suspended-sub")).toBeNull();
    expect(await identities.resolveActiveIdentity("issuer", "active-sub")).toEqual({
      id: "user-3",
      displayName: "Active",
    });
    expect(await identities.resolveActiveIdentity("issuer", "unverified-sub")).toBeNull();
    expect(findUnique).toHaveBeenCalledWith({
      where: { issuer_subject: { issuer: "issuer", subject: "active-sub" } },
      include: { user: true, verification: true },
    });
  });

  it("starts code flow with S256 PKCE, state and nonce, then validates them at exchange", async () => {
    const redis = new MemoryRedis();
    const service = createOidcService({
      redis: redis as unknown as Redis,
      issuer: "http://localhost:8080/realms/distributed-business-platform",
      clientId: "distributed-business-platform-web",
      clientSecret: "synthetic-test-secret",
      redirectUri: "http://localhost:3001/api/v1/auth/callback",
      postLogoutRedirectUri: "http://localhost:5174/",
    });

    const { state, authorizationUrl } = await service.startLogin("browser-binding");
    const storedTransaction = JSON.parse(redis.values.get(`dbp:oidc:transaction:${state}`)!);
    const authorizationParameters = oidcMocks.buildAuthorizationUrl.mock.calls[0]![1] as Record<string, string>;
    expect(authorizationParameters).toMatchObject({
      response_type: "code",
      state,
      nonce: "nonce_value_012345678901234567890",
      code_challenge: "pkce-challenge-value",
      code_challenge_method: "S256",
    });
    expect(storedTransaction).toEqual({
      nonce: "nonce_value_012345678901234567890",
      codeVerifier: "a-long-pkce-code-verifier-value",
      browserBinding: "browser-binding",
    });
    expect(authorizationUrl).toBe("http://keycloak.test/auth");

    const result = await service.completeLogin(
      new URL(`http://localhost:3001/api/v1/auth/callback?code=one-time-code&state=${state}`),
      state,
      "browser-binding",
    );
    expect(result).toEqual({
      issuer: "http://localhost:8080/realms/distributed-business-platform",
      subject: "external-subject",
    });
    expect(oidcMocks.authorizationCodeGrant).toHaveBeenCalledWith(
      expect.anything(),
      expect.any(URL),
      {
        pkceCodeVerifier: "a-long-pkce-code-verifier-value",
        expectedState: state,
        expectedNonce: "nonce_value_012345678901234567890",
      },
    );
  });

  it("consumes OIDC transactions once and rejects a different browser binding", async () => {
    const redis = new MemoryRedis();
    const service = createOidcService({
      redis: redis as unknown as Redis,
      issuer: "https://idp.example.test/realm",
      clientId: "dbp-web",
      clientSecret: "synthetic-test-secret",
      redirectUri: "https://api.example.test/api/v1/auth/callback",
      postLogoutRedirectUri: "https://app.example.test/",
    });
    const { state } = await service.startLogin("browser-one");

    await expect(service.completeLogin(new URL(`https://api.example.test/callback?state=${state}`), state, "browser-two"))
      .rejects.toThrow("OIDC transaction browser mismatch");
    await expect(service.completeLogin(new URL(`https://api.example.test/callback?state=${state}`), state, "browser-one"))
      .rejects.toThrow("Expired OIDC transaction");
    expect(oidcMocks.authorizationCodeGrant).not.toHaveBeenCalled();
  });

  it("requires fresh OIDC proof with state, nonce and S256 PKCE for identity linking", async () => {
    const redis = new MemoryRedis();
    const service = createOidcService({
      redis: redis as unknown as Redis,
      issuer: "https://idp.example.test/realm",
      clientId: "dbp-web",
      clientSecret: "synthetic-test-secret",
      redirectUri: "https://api.example.test/api/v1/auth/callback",
      postLogoutRedirectUri: "https://app.example.test/",
    });
    const challengeId = "00000000-0000-4000-8000-000000000001";
    const { authorizationUrl } = await service.startIdentityLink(challengeId);
    const state = "il_state_value_012345678901234567890";
    const stored = JSON.parse(redis.values.get(`dbp:oidc:identity-link:${state}`)!);
    const parameters = oidcMocks.buildAuthorizationUrl.mock.calls[0]![1] as Record<string, string>;
    expect(authorizationUrl).toBe("http://keycloak.test/auth");
    expect(parameters).toMatchObject({
      state,
      nonce: "nonce_value_012345678901234567890",
      code_challenge: "pkce-challenge-value",
      code_challenge_method: "S256",
      prompt: "login",
      max_age: "0",
    });
    expect(stored).toEqual({
      challengeId,
      nonce: "nonce_value_012345678901234567890",
      codeVerifier: "a-long-pkce-code-verifier-value",
    });
    oidcMocks.authorizationCodeGrant.mockResolvedValueOnce({ claims: () => ({
      iss: "https://idp.example.test/realm",
      sub: "external-subject",
      auth_time: Math.floor(Date.now() / 1000),
    }) });

    const proof = await service.completeIdentityLink(
      new URL(`https://api.example.test/api/v1/auth/callback?code=opaque&state=${state}`),
      state,
    );
    expect(proof.challengeId).toBe(challengeId);
    expect(proof.identity).toEqual({ issuer: "https://idp.example.test/realm", subject: "external-subject" });
    expect(oidcMocks.authorizationCodeGrant).toHaveBeenCalledWith(expect.anything(), expect.any(URL), {
      pkceCodeVerifier: "a-long-pkce-code-verifier-value",
      expectedState: state,
      expectedNonce: "nonce_value_012345678901234567890",
    });
    await expect(service.completeIdentityLink(new URL("https://api.example.test/callback"), state)).rejects.toThrow("Expired identity-link transaction");
  });

  it("rejects identity-link proof without recent auth_time", async () => {
    const redis = new MemoryRedis();
    const service = createOidcService({
      redis: redis as unknown as Redis,
      issuer: "https://idp.example.test/realm",
      clientId: "dbp-web",
      clientSecret: "synthetic-test-secret",
      redirectUri: "https://api.example.test/api/v1/auth/callback",
      postLogoutRedirectUri: "https://app.example.test/",
    });
    await service.startIdentityLink("00000000-0000-4000-8000-000000000001");
    const state = "il_state_value_012345678901234567890";
    oidcMocks.authorizationCodeGrant.mockResolvedValueOnce({ claims: () => ({
      iss: "https://idp.example.test/realm",
      sub: "external-subject",
      auth_time: Math.floor(Date.now() / 1000) - 600,
    }) });
    await expect(service.completeIdentityLink(
      new URL(`https://api.example.test/api/v1/auth/callback?code=opaque&state=${state}`),
      state,
    )).rejects.toMatchObject({ challengeId: "00000000-0000-4000-8000-000000000001", outcomeCode: "oidc_proof_rejected" });
  });

  it("rejects an ID token whose authorized party names another client", async () => {
    const service = createOidcService({
      redis: new MemoryRedis() as unknown as Redis,
      issuer: "https://idp.example.test/realm",
      clientId: "dbp-web",
      clientSecret: "synthetic-test-secret",
      redirectUri: "https://api.example.test/api/v1/auth/callback",
      postLogoutRedirectUri: "https://app.example.test/",
    });
    const { state } = await service.startLogin("browser-binding");
    oidcMocks.authorizationCodeGrant.mockResolvedValueOnce({ claims: () => ({
      iss: "https://idp.example.test/realm",
      sub: "external-subject",
      azp: "another-client",
    }) });
    await expect(service.completeLogin(
      new URL(`https://api.example.test/api/v1/auth/callback?code=opaque&state=${state}`), state, "browser-binding",
    )).rejects.toThrow("OIDC identity claims are invalid");
  });

  it("rejects a mismatched authorized party during identity proof", async () => {
    const service = createOidcService({
      redis: new MemoryRedis() as unknown as Redis,
      issuer: "https://idp.example.test/realm",
      clientId: "dbp-web",
      clientSecret: "synthetic-test-secret",
      redirectUri: "https://api.example.test/api/v1/auth/callback",
      postLogoutRedirectUri: "https://app.example.test/",
    });
    await service.startIdentityLink("00000000-0000-4000-8000-000000000001");
    const state = "il_state_value_012345678901234567890";
    oidcMocks.authorizationCodeGrant.mockResolvedValueOnce({ claims: () => ({
      iss: "https://idp.example.test/realm",
      sub: "external-subject",
      azp: "another-client",
      auth_time: Math.floor(Date.now() / 1000),
    }) });
    await expect(service.completeIdentityLink(
      new URL(`https://api.example.test/api/v1/auth/callback?code=opaque&state=${state}`), state,
    )).rejects.toMatchObject({ outcomeCode: "oidc_proof_rejected" });
  });

  it("binds confirmation data to the selected user and consumes it once with browser and CSRF proof", async () => {
    const redis = new MemoryRedis();
    const service = createOidcService({
      redis: redis as unknown as Redis,
      issuer: "https://idp.example.test/realm",
      clientId: "dbp-web",
      clientSecret: "synthetic-test-secret",
      redirectUri: "https://api.example.test/api/v1/auth/callback",
      postLogoutRedirectUri: "https://app.example.test/",
    });
    const proof = {
      challengeId: "00000000-0000-4000-8000-000000000001",
      identity: { issuer: "https://idp.example.test/realm", subject: "external-subject" },
      verifiedAt: new Date("2026-11-17T12:00:00Z"),
    };
    const { confirmationId, browserBinding } = await service.createIdentityLinkConfirmation(proof, "selected-platform-user");
    const key = `dbp:oidc:identity-link-confirmation:${confirmationId}`;
    expect(JSON.parse(redis.values.get(key)!)).toMatchObject({
      challengeId: proof.challengeId,
      platformUserId: "selected-platform-user",
      identity: proof.identity,
    });
    expect(await service.getIdentityLinkConfirmation(confirmationId, "wrong-browser")).toBeNull();
    const view = await service.getIdentityLinkConfirmation(confirmationId, browserBinding);
    expect(view).toMatchObject({
      challengeId: proof.challengeId,
      platformUserId: "selected-platform-user",
      issuer: proof.identity.issuer,
    });
    expect(view).not.toHaveProperty("subject");
    const consumed = await service.consumeIdentityLinkConfirmation(confirmationId, view!.csrfToken, browserBinding);
    expect(consumed).toMatchObject({
      challengeId: proof.challengeId,
      platformUserId: "selected-platform-user",
      identity: proof.identity,
    });
    expect(await service.consumeIdentityLinkConfirmation(confirmationId, view!.csrfToken, browserBinding)).toBeNull();

    const expired = await service.createIdentityLinkConfirmation(proof, "selected-platform-user");
    redis.values.delete(`dbp:oidc:identity-link-confirmation:${expired.confirmationId}`);
    expect(await service.getIdentityLinkConfirmation(expired.confirmationId, expired.browserBinding)).toBeNull();
    expect(await service.consumeIdentityLinkConfirmation(expired.confirmationId, "csrf", expired.browserBinding)).toBeNull();
  });

  it("rejects authorization responses when the OIDC library rejects token validation", async () => {
    const redis = new MemoryRedis();
    const service = createOidcService({
      redis: redis as unknown as Redis,
      issuer: "https://idp.example.test/realm",
      clientId: "dbp-web",
      clientSecret: "synthetic-test-secret",
      redirectUri: "https://api.example.test/api/v1/auth/callback",
      postLogoutRedirectUri: "https://api.example.test/api/v1/auth/logout/callback",
    });
    const { state } = await service.startLogin("browser-binding");
    oidcMocks.authorizationCodeGrant.mockRejectedValueOnce(new Error("invalid ID token signature"));

    await expect(service.completeLogin(
      new URL(`https://api.example.test/api/v1/auth/callback?code=code&state=${state}`),
      state,
      "browser-binding",
    )).rejects.toThrow("invalid ID token signature");
  });

  it("builds a Keycloak RP-initiated logout URL from discovery metadata", async () => {
    const service = createOidcService({
      redis: new MemoryRedis() as unknown as Redis,
      issuer: "https://idp.example.test/realm",
      clientId: "dbp-web",
      clientSecret: "synthetic-test-secret",
      redirectUri: "https://api.example.test/api/v1/auth/callback",
      postLogoutRedirectUri: "https://app.example.test/",
    });

    const state = await service.createLogoutState();
    const logoutUrl = new URL(await service.buildLogoutUrl(state));
    expect(logoutUrl.origin).toBe("http://localhost:8080");
    expect(logoutUrl.searchParams.get("client_id")).toBe("dbp-web");
    expect(logoutUrl.searchParams.get("post_logout_redirect_uri")).toBe("https://app.example.test/");
    expect(logoutUrl.searchParams.get("state")).toBe(state);
    expect(await service.consumeLogoutState(state)).toBe(true);
    expect(await service.consumeLogoutState(state)).toBe(false);
  });
});
