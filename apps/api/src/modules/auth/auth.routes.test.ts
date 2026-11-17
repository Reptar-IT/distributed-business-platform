import Fastify from "fastify";
import cookie from "@fastify/cookie";
import cors from "@fastify/cors";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createAuthRoutes } from "./auth.routes.js";
import { registerPlatformAuthentication } from "./auth.middleware.js";
import type { IdentityService } from "./identity.service.js";
import type { OidcService } from "./oidc.service.js";
import type { PlatformSession, SessionStore } from "./session.store.js";

const testState = "state_value_012345678901234567890";
const testSessionId = "s".repeat(43);

function createHarness(identity: { id: string; displayName: string } | null = {
  id: "platform-user-1",
  displayName: "DBP Member",
}) {
  let loginBinding = "";
  let session: PlatformSession | null = null;
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
    createLogoutState: vi.fn(async () => "logout-state-value-0123456789"),
    consumeLogoutState: vi.fn(async (state) => state === "logout-state-value-0123456789"),
    buildLogoutUrl: vi.fn(async (state) => `http://localhost:8080/logout?state=${state}`),
  };
  const sessions: SessionStore = {
    create: vi.fn(async (userId) => {
      session = {
        userId,
        csrfToken: "csrf-token-test",
        createdAt: Date.now(),
        absoluteExpiresAt: Date.now() + 12 * 60 * 60 * 1000,
      };
      return { sessionId: testSessionId, session };
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
  }));

  return { app, oidc, sessions, identities };
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
    });
    expect(sessions.create).toHaveBeenCalledWith("platform-user-1");
    expect(sessionResponse.headers["set-cookie"]).toContain("HttpOnly");
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
