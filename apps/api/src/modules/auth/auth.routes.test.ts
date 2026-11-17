import Fastify from "fastify";
import cookie from "@fastify/cookie";
import cors from "@fastify/cors";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createAuthRoutes } from "./auth.routes.js";
import { registerPlatformAuthentication } from "./auth.middleware.js";
import { OwnerRecoveryVerificationError } from "./oidc.service.js";
import type { IdentityService } from "./identity.service.js";
import type { OidcService } from "./oidc.service.js";
import type { PlatformSession, SessionStore } from "./session.store.js";

const testState = "state_value_012345678901234567890";
const identityLinkState = "il_state_value_012345678901234567890";
const testSessionId = "s".repeat(43);
const confirmationId = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const confirmationCookie = `dbp_identity_link_${confirmationId}`;

function createHarness(identity: { id: string; displayName: string } | null = {
  id: "platform-user-1",
  displayName: "DBP Member",
}) {
  let loginBinding = "";
  let session: PlatformSession | null = null;
  let identityLinkConfirmationConsumed = false;
  const oidc: OidcService = {
    startLogin: vi.fn(async (browserBinding) => {
      loginBinding = browserBinding;
      return {
        state: testState,
        authorizationUrl: `http://localhost:8080/authorize?state=${testState}`,
      };
    }),
    completeLogin: vi.fn(async (_url, state, browserBinding) => {
      if (state !== testState || browserBinding !== loginBinding) throw new Error("invalid transaction");
      return {
        issuer: "http://localhost:8080/realms/distributed-business-platform",
        subject: "sub-1",
      };
    }),
    startIdentityLink: vi.fn(async () => ({ authorizationUrl: "http://localhost:8080/link" })),
    completeIdentityLink: vi.fn(async () => ({
      challengeId: "00000000-0000-4000-8000-000000000001",
      identity: { issuer: "https://issuer.example.test", subject: "linked-subject" },
      verifiedAt: new Date("2026-11-17T12:00:00Z"),
    })),
    startOwnerRecovery: vi.fn(async () => ({ authorizationUrl: "http://localhost:8080/recovery" })),
    completeOwnerRecovery: vi.fn(async () => ({
      operationId: "00000000-0000-4000-8000-000000000009",
      identity: { issuer: "https://issuer.example.test", subject: "recovered-subject" },
      verifiedAt: new Date("2026-11-17T12:00:00Z"),
    })),
    createIdentityLinkConfirmation: vi.fn(async () => ({
      confirmationId,
      browserBinding: "identity-link-browser-binding",
    })),
    getIdentityLinkConfirmation: vi.fn(async (id, browserBinding) => id === confirmationId && browserBinding === "identity-link-browser-binding"
      ? {
        challengeId: "00000000-0000-4000-8000-000000000001",
        platformUserId: "platform-user-1",
        issuer: "https://issuer.example.test",
        csrfToken: "identity-link-csrf",
      }
      : null),
    consumeIdentityLinkConfirmation: vi.fn(async (id, csrfToken, browserBinding) => {
      if (identityLinkConfirmationConsumed || id !== confirmationId || csrfToken !== "identity-link-csrf" ||
          browserBinding !== "identity-link-browser-binding") return null;
      identityLinkConfirmationConsumed = true;
      return {
        challengeId: "00000000-0000-4000-8000-000000000001",
        platformUserId: "platform-user-1",
        identity: { issuer: "https://issuer.example.test", subject: "linked-subject" },
        verifiedAt: new Date("2026-11-17T12:00:00Z"),
      };
    }),
    createLogoutState: vi.fn(async () => "logout-state-value-0123456789"),
    consumeLogoutState: vi.fn(async (state) => state === "logout-state-value-0123456789"),
    buildLogoutUrl: vi.fn(async (state) => `http://localhost:8080/logout?state=${state}`),
  };
  const sessions: SessionStore = {
    create: vi.fn(async (userId, identity) => {
      const createdSession: PlatformSession = {
        userId,
        identity,
        csrfToken: "csrf-token-test",
        createdAt: Date.now(),
        absoluteExpiresAt: Date.now() + 12 * 60 * 60 * 1000,
      };
      session = createdSession;
      return { sessionId: testSessionId, session: createdSession };
    }),
    get: vi.fn(async (sessionId) => sessionId === testSessionId && session
      ? { session, maxAgeMs: 30 * 60 * 1000 }
      : null),
    getAndTouch: vi.fn(async (sessionId) => sessionId === testSessionId && session
      ? { session, maxAgeMs: 30 * 60 * 1000 }
      : null),
    destroy: vi.fn(async (sessionId) => {
      if (sessionId === testSessionId) session = null;
    }),
  };
  const identities = {
    resolveActiveIdentity: vi.fn(async () => identity),
    getActiveUser: vi.fn(async (userId: string) => userId === identity?.id ? identity : null),
  } as unknown as IdentityService;
  const identityLinks = {
    getPendingTarget: vi.fn(async () => ({ platformUserId: "platform-user-1" })),
    complete: vi.fn(async () => "LINKED"),
    reject: vi.fn(async () => undefined),
  };
  const ownerRecoveryKits = {
    isActiveOwner: vi.fn(async () => true),
    issueOrReplace: vi.fn(async () => ({ kit_id: "kit-1", generation: 1, replaced: false, codes: Array.from({ length: 10 }, (_, index) => `code-${index}`) })),
  };
  const ownerRecoveryCallback = {
    complete: vi.fn(async () => "PREPARED"),
    reject: vi.fn(async () => undefined),
  };

  const app = Fastify({ logger: false });
  app.register(cookie);
  registerPlatformAuthentication(app, { sessions, identities });
  app.register(createAuthRoutes({
    oidc,
    sessions,
    identities,
    webOrigin: "http://localhost:5174",
    redirectUri: "http://localhost:3001/api/v1/auth/callback",
    postLogoutRedirectUri: "http://localhost:5174/",
    identityLinks,
    ownerRecoveryKits,
    ownerRecoveryCallback,
  }));

  return { app, oidc, sessions, identities, identityLinks, ownerRecoveryKits, ownerRecoveryCallback };
}

function cookiePair(setCookie: string | string[] | undefined, prefix: string): string {
  const values = Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : [];
  const pair = values.map((value) => value.split(";")[0]!).find((value) => value.startsWith(`${prefix}=`));
  if (!pair) throw new Error(`Cookie ${prefix} missing from response`);
  return pair;
}

async function completeLogin(app: ReturnType<typeof createHarness>["app"]): Promise<string> {
  const start = await app.inject({ method: "GET", url: "/api/v1/auth/login" });
  const binding = cookiePair(start.headers["set-cookie"], `dbp_oidc_${testState}`);
  const callback = await app.inject({
    method: "GET",
    url: `/api/v1/auth/callback?code=example-code&state=${testState}`,
    headers: { cookie: binding },
  });
  expect(callback.statusCode).toBe(302);
  return cookiePair(callback.headers["set-cookie"], "dbp_session");
}

describe("BFF authentication routes", () => {
  beforeEach(() => vi.clearAllMocks());

  it("requires first-party confirmation for the original PlatformUser before linking and never creates a login session", async () => {
    const { app, oidc, sessions, identityLinks } = createHarness();
    const callback = await app.inject({
      method: "GET",
      url: `/api/v1/auth/callback?code=opaque-code&state=${identityLinkState}&platformUserId=attacker-selected&issuer=https://attacker.example`,
    });

    expect(callback.statusCode).toBe(302);
    expect(callback.headers.location).toBe(`http://localhost:5174/#identity-link-confirmation/${confirmationId}`);
    expect(oidc.completeIdentityLink).toHaveBeenCalledOnce();
    expect(oidc.createIdentityLinkConfirmation).toHaveBeenCalledWith(expect.objectContaining({
      challengeId: "00000000-0000-4000-8000-000000000001",
    }), "platform-user-1");
    expect(identityLinks.getPendingTarget).toHaveBeenCalledWith("00000000-0000-4000-8000-000000000001");
    expect(identityLinks.complete).not.toHaveBeenCalled();
    expect(sessions.create).not.toHaveBeenCalled();

    const confirmationCookiePair = cookiePair(callback.headers["set-cookie"], confirmationCookie);
    const consent = await app.inject({
      method: "GET",
      url: `/api/v1/auth/identity-link/confirmation/${confirmationId}`,
      headers: { origin: "http://localhost:5174", cookie: confirmationCookiePair },
    });
    expect(consent.statusCode).toBe(200);
    expect(consent.json()).toMatchObject({ platformUserId: "platform-user-1", issuer: "https://issuer.example.test" });
    expect(consent.json()).not.toHaveProperty("subject");

    const confirmation = await app.inject({
      method: "POST",
      url: "/api/v1/auth/identity-link/confirmation",
      headers: { origin: "http://localhost:5174", cookie: confirmationCookiePair },
      payload: { confirmationId, csrfToken: "identity-link-csrf", decision: "confirm" },
    });
    expect(confirmation.statusCode).toBe(200);
    expect(confirmation.json()).toEqual({ outcome: "linked" });
    expect(identityLinks.complete).toHaveBeenCalledWith({
      challengeId: "00000000-0000-4000-8000-000000000001",
      platformUserId: "platform-user-1",
      issuer: "https://issuer.example.test",
      subject: "linked-subject",
      verifiedAt: new Date("2026-11-17T12:00:00Z"),
    });
    const replay = await app.inject({
      method: "POST",
      url: "/api/v1/auth/identity-link/confirmation",
      headers: { origin: "http://localhost:5174", cookie: confirmationCookiePair },
      payload: { confirmationId, csrfToken: "identity-link-csrf", decision: "confirm" },
    });
    expect(replay.statusCode).toBe(400);
    expect(identityLinks.complete).toHaveBeenCalledOnce();
    expect(sessions.create).not.toHaveBeenCalled();
    await app.close();
  });

  it("allows explicit holder cancellation and rejects cross-origin or altered confirmation requests", async () => {
    const { app, oidc, identityLinks } = createHarness();
    const callback = await app.inject({ method: "GET", url: `/api/v1/auth/callback?code=opaque&state=${identityLinkState}` });
    const cookie = cookiePair(callback.headers["set-cookie"], confirmationCookie);
    const deniedOrigin = await app.inject({
      method: "POST", url: "/api/v1/auth/identity-link/confirmation",
      headers: { origin: "https://attacker.example", cookie },
      payload: { confirmationId, csrfToken: "identity-link-csrf", decision: "confirm" },
    });
    expect(deniedOrigin.statusCode).toBe(403);
    expect(oidc.consumeIdentityLinkConfirmation).not.toHaveBeenCalled();
    const substitutedTarget = await app.inject({
      method: "POST", url: "/api/v1/auth/identity-link/confirmation",
      headers: { origin: "http://localhost:5174", cookie },
      payload: { confirmationId, csrfToken: "identity-link-csrf", decision: "confirm", platformUserId: "attacker-selected" },
    });
    expect(substitutedTarget.statusCode).toBe(400);
    expect(oidc.consumeIdentityLinkConfirmation).not.toHaveBeenCalled();
    const substitutedChallenge = await app.inject({
      method: "POST", url: "/api/v1/auth/identity-link/confirmation",
      headers: { origin: "http://localhost:5174", cookie },
      payload: { confirmationId: `B${confirmationId.slice(1)}`, csrfToken: "identity-link-csrf", decision: "confirm" },
    });
    expect(substitutedChallenge.statusCode).toBe(400);
    expect(identityLinks.complete).not.toHaveBeenCalled();
    const cancelled = await app.inject({
      method: "POST", url: "/api/v1/auth/identity-link/confirmation",
      headers: { origin: "http://localhost:5174", cookie },
      payload: { confirmationId, csrfToken: "identity-link-csrf", decision: "cancel" },
    });
    expect(cancelled.statusCode).toBe(200);
    expect(cancelled.json()).toEqual({ outcome: "cancelled" });
    expect(identityLinks.reject).toHaveBeenCalledWith("00000000-0000-4000-8000-000000000001", "holder_cancelled");
    expect(identityLinks.complete).not.toHaveBeenCalled();
    await app.close();
  });

  it("denies expired identity-link confirmation without creating a mapping", async () => {
    const { app, oidc, identityLinks } = createHarness();
    vi.mocked(oidc.getIdentityLinkConfirmation).mockResolvedValueOnce(null);
    const callback = await app.inject({ method: "GET", url: `/api/v1/auth/callback?code=opaque&state=${identityLinkState}` });
    const cookie = cookiePair(callback.headers["set-cookie"], confirmationCookie);
    const expired = await app.inject({
      method: "GET", url: `/api/v1/auth/identity-link/confirmation/${confirmationId}`,
      headers: { origin: "http://localhost:5174", cookie },
    });
    expect(expired.statusCode).toBe(404);
    vi.mocked(oidc.consumeIdentityLinkConfirmation).mockResolvedValueOnce(null);
    const expiredPost = await app.inject({
      method: "POST", url: "/api/v1/auth/identity-link/confirmation",
      headers: { origin: "http://localhost:5174", cookie },
      payload: { confirmationId, csrfToken: "identity-link-csrf", decision: "confirm" },
    });
    expect(expiredPost.statusCode).toBe(400);
    expect(identityLinks.complete).not.toHaveBeenCalled();
    await app.close();
  });

  it("starts login and establishes a session for an existing active identity", async () => {
    const { app, oidc, identities, sessions } = createHarness();
    const sessionCookie = await completeLogin(app);

    expect(oidc.startLogin).toHaveBeenCalledOnce();
    expect(oidc.completeLogin).toHaveBeenCalledWith(
      expect.objectContaining({
        origin: "http://localhost:3001",
        pathname: "/api/v1/auth/callback",
      }),
      testState,
      expect.any(String),
    );
    expect(identities.resolveActiveIdentity).toHaveBeenCalledWith(
      "http://localhost:8080/realms/distributed-business-platform",
      "sub-1",
    );

    const sessionResponse = await app.inject({
      method: "GET",
      url: "/api/v1/auth/session",
      headers: { cookie: sessionCookie },
    });
    expect(sessionResponse.statusCode).toBe(200);
    expect(sessionResponse.json()).toMatchObject({
      user: { id: "platform-user-1", displayName: "DBP Member" },
      csrfToken: "csrf-token-test",
      isPlatformOwner: true,
    });
    expect(sessions.create).toHaveBeenCalledWith("platform-user-1", {
      issuer: "http://localhost:8080/realms/distributed-business-platform",
      subject: "sub-1",
    });
    expect(sessionResponse.headers["set-cookie"]).toContain("HttpOnly");
    await app.close();
  });

  it("accepts fresh owner-recovery proof without creating an ordinary login session", async () => {
    const { app, oidc, sessions, ownerRecoveryCallback } = createHarness();
    const state = "or_state_value_012345678901234567890";
    const response = await app.inject({ method: "GET", url: `/api/v1/auth/callback?code=opaque-code&state=${state}` });
    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toBe("http://localhost:5174/?owner_recovery=processing");
    expect(oidc.completeOwnerRecovery).toHaveBeenCalledWith(expect.any(URL), state);
    expect(ownerRecoveryCallback.complete).toHaveBeenCalledWith({
      operationId: "00000000-0000-4000-8000-000000000009",
      issuer: "https://issuer.example.test",
      subject: "recovered-subject",
      verifiedAt: new Date("2026-11-17T12:00:00Z"),
    });
    expect(sessions.create).not.toHaveBeenCalled();
    await app.close();
  });

  it("records a bounded OIDC recovery-proof failure without exposing it in the browser response", async () => {
    const { app, oidc, sessions, ownerRecoveryCallback } = createHarness();
    vi.mocked(oidc.completeOwnerRecovery).mockRejectedValueOnce(new OwnerRecoveryVerificationError(
      "00000000-0000-4000-8000-000000000009", "oidc_proof_rejected",
    ));
    const response = await app.inject({
      method: "GET",
      url: "/api/v1/auth/callback?code=opaque-code&state=or_state_value_012345678901234567890",
    });
    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toBe("http://localhost:5174/?owner_recovery=failed");
    expect(ownerRecoveryCallback.reject).toHaveBeenCalledWith("00000000-0000-4000-8000-000000000009", "oidc_proof_rejected");
    expect(sessions.create).not.toHaveBeenCalled();
    await app.close();
  });

  it("issues a ten-code kit only from the authenticated owner session with exact origin and CSRF proof", async () => {
    const { app, ownerRecoveryKits } = createHarness();
    const sessionCookie = await completeLogin(app);
    const response = await app.inject({
      method: "POST",
      url: "/api/v1/auth/owner/recovery-kit",
      headers: { cookie: sessionCookie, origin: "http://localhost:5174", "x-csrf-token": "csrf-token-test" },
      payload: {},
    });
    expect(response.statusCode).toBe(200);
    expect(response.json().codes).toHaveLength(10);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(ownerRecoveryKits.issueOrReplace).toHaveBeenCalledWith({
      platformUserId: "platform-user-1",
      issuer: "http://localhost:8080/realms/distributed-business-platform",
      subject: "sub-1",
    });
    const deniedOrigin = await app.inject({
      method: "POST", url: "/api/v1/auth/owner/recovery-kit",
      headers: { cookie: sessionCookie, origin: "https://attacker.test", "x-csrf-token": "csrf-token-test" }, payload: {},
    });
    expect(deniedOrigin.statusCode).toBe(403);
    const deniedCsrf = await app.inject({
      method: "POST", url: "/api/v1/auth/owner/recovery-kit",
      headers: { cookie: sessionCookie, origin: "http://localhost:5174", "x-csrf-token": "wrong" }, payload: {},
    });
    expect(deniedCsrf.statusCode).toBe(403);
    expect(ownerRecoveryKits.issueOrReplace).toHaveBeenCalledOnce();
    await app.close();
  });

  it("denies unknown external identities without creating a session", async () => {
    const { app, sessions } = createHarness(null);
    const start = await app.inject({ method: "GET", url: "/api/v1/auth/login" });
    const binding = cookiePair(start.headers["set-cookie"], `dbp_oidc_${testState}`);
    const callback = await app.inject({
      method: "GET",
      url: `/api/v1/auth/callback?code=example-code&state=${testState}`,
      headers: { cookie: binding },
    });

    expect(callback.statusCode).toBe(302);
    expect(callback.headers.location).toBe("http://localhost:5174/?auth=denied");
    expect(sessions.create).not.toHaveBeenCalled();
    await app.close();
  });

  it("rejects callback state that is not bound to the initiating browser", async () => {
    const { app, oidc, sessions } = createHarness();
    const callback = await app.inject({
      method: "GET",
      url: `/api/v1/auth/callback?code=example-code&state=${testState}`,
    });

    expect(callback.statusCode).toBe(400);
    expect(oidc.completeLogin).not.toHaveBeenCalled();
    expect(sessions.create).not.toHaveBeenCalled();
    await app.close();
  });

  it("requires the configured browser origin and CSRF token, then destroys the Redis session", async () => {
    const { app, sessions } = createHarness();
    const sessionCookie = await completeLogin(app);
    const rejected = await app.inject({
      method: "POST",
      url: "/api/v1/auth/logout",
      headers: {
        cookie: sessionCookie,
        origin: "http://attacker.example",
        "x-csrf-token": "csrf-token-test",
      },
    });
    expect(rejected.statusCode).toBe(403);
    expect(sessions.destroy).not.toHaveBeenCalled();

    const logout = await app.inject({
      method: "POST",
      url: "/api/v1/auth/logout",
      headers: {
        cookie: sessionCookie,
        origin: "http://localhost:5174",
        "x-csrf-token": "csrf-token-test",
      },
    });
    expect(logout.statusCode).toBe(200);
    expect(logout.json().logoutUrl).toContain("http://localhost:8080/logout");
    expect(sessions.destroy).toHaveBeenCalledWith(testSessionId);
    expect(logout.headers["set-cookie"]).toContain("Max-Age=0");
    await app.close();
  });

  it("returns to the web origin when no local session exists", async () => {
    const { app } = createHarness();
    const response = await app.inject({
      method: "POST",
      url: "/api/v1/auth/logout",
      headers: { cookie: "dbp_session=unknown-session" },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().logoutUrl).toBe("http://localhost:5174");
    expect(response.json().logoutUrl).not.toContain("/api/v1/auth/logout/callback");
    await app.close();
  });

  it("returns to the web origin when Keycloak logout URL creation fails", async () => {
    const { app, oidc, sessions } = createHarness();
    vi.mocked(oidc.buildLogoutUrl).mockRejectedValueOnce(new Error("Keycloak unavailable"));
    const sessionCookie = await completeLogin(app);

    const response = await app.inject({
      method: "POST",
      url: "/api/v1/auth/logout",
      headers: {
        cookie: sessionCookie,
        origin: "http://localhost:5174",
        "x-csrf-token": "csrf-token-test",
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().logoutUrl).toBe("http://localhost:5174");
    expect(response.json().logoutUrl).not.toContain("/api/v1/auth/logout/callback");
    expect(sessions.destroy).toHaveBeenCalledWith(testSessionId);
    await app.close();
  });

  it("validates one-time Keycloak logout state before returning to the browser app", async () => {
    const { app, oidc } = createHarness();
    const logoutCallback = await app.inject({
      method: "GET",
      url: "/api/v1/auth/logout/callback?state=logout-state-value-0123456789",
    });
    expect(logoutCallback.statusCode).toBe(302);
    expect(logoutCallback.headers.location).toBe("http://localhost:5174");
    expect(oidc.consumeLogoutState).toHaveBeenCalledWith("logout-state-value-0123456789");

    const replay = await app.inject({
      method: "GET",
      url: "/api/v1/auth/logout/callback?state=unknown-state-value-0123456789",
    });
    expect(replay.statusCode).toBe(400);
    await app.close();
  });

  it("allows credentials only from the configured web origin", async () => {
    const app = Fastify({ logger: false });
    await app.register(cors, {
      origin: "http://localhost:5174",
      credentials: true,
      allowedHeaders: ["Content-Type", "X-CSRF-Token"],
    });
    const preflight = await app.inject({
      method: "OPTIONS",
      url: "/api/v1/auth/logout",
      headers: {
        origin: "http://localhost:5174",
        "access-control-request-method": "POST",
        "access-control-request-headers": "x-csrf-token",
      },
    });
    expect(preflight.headers["access-control-allow-origin"]).toBe("http://localhost:5174");
    expect(preflight.headers["access-control-allow-credentials"]).toBe("true");
    expect(preflight.headers["access-control-allow-headers"]?.toLowerCase()).toContain("x-csrf-token");
    await app.close();
  });
});
