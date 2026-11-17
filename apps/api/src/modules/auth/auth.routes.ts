import { timingSafeEqual } from "node:crypto";
import type { FastifyPluginAsync, FastifyRequest } from "fastify";
import type { IdentityService } from "./identity.service.js";
import { createBrowserBinding, IdentityLinkVerificationError, type OidcService } from "./oidc.service.js";
import { requireBrowserOrigin } from "./auth.middleware.js";
import {
  clearPlatformSessionCookie,
  sessionCookieName,
  setPlatformSessionCookie,
  SESSION_IDLE_TIMEOUT_MS,
  type SessionStore,
} from "./session.store.js";

interface AuthRouteOptions {
  oidc: OidcService;
  sessions: SessionStore;
  identities: IdentityService;
  webOrigin: string;
  redirectUri: string;
  postLogoutRedirectUri: string;
  identityLinks?: {
    complete(input: { challengeId: string; issuer: string; subject: string; verifiedAt: Date }): Promise<string>;
    reject(challengeId: string, outcomeCode: string): Promise<void>;
  };
}

function safeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

function cookieOptions(maxAgeSeconds: number) {
  return {
    path: "/",
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax" as const,
    maxAge: maxAgeSeconds,
  };
}

function transactionCookieName(state: string): string {
  const prefix = process.env.NODE_ENV === "production" ? "__Host-dbp_oidc_" : "dbp_oidc_";
  return `${prefix}${state}`;
}

export function createAuthRoutes(options: AuthRouteOptions): FastifyPluginAsync {
  return async (app) => {
    app.addHook("onRequest", async (_request, reply) => {
      reply.header("Cache-Control", "no-store");
      reply.header("Referrer-Policy", "no-referrer");
    });

    app.get("/api/v1/auth/login", async (_request, reply) => {
      try {
        const browserBinding = createBrowserBinding();
        const { state, authorizationUrl } = await options.oidc.startLogin(browserBinding);
        const cookieName = transactionCookieName(state);
        reply.setCookie(cookieName, browserBinding, cookieOptions(5 * 60));
        return reply.redirect(authorizationUrl);
      } catch {
        return reply.code(503).send({ error: "Authentication is temporarily unavailable" });
      }
    });

    app.get("/api/v1/auth/callback", async (request, reply) => {
      const query = request.query as Record<string, unknown>;
      const state = typeof query.state === "string" ? query.state : "";
      if (state.startsWith("il_")) {
        if (!options.identityLinks) return reply.code(503).send({ error: "Identity linking is unavailable" });
        const callbackUrl = new URL(options.redirectUri);
        const requestUrl = new URL(request.raw.url ?? "/api/v1/auth/callback", callbackUrl);
        if (requestUrl.origin !== callbackUrl.origin || requestUrl.pathname !== callbackUrl.pathname) {
          return reply.code(400).send({ error: "Identity linking could not be completed" });
        }
        callbackUrl.search = requestUrl.search;
        try {
          const proof = await options.oidc.completeIdentityLink(callbackUrl, state);
          const outcome = await options.identityLinks.complete({
            ...proof.identity,
            challengeId: proof.challengeId,
            verifiedAt: proof.verifiedAt,
          });
          return reply.redirect(`${options.webOrigin}/?identity_link=${outcome === "LINKED" || outcome === "ALREADY_VERIFIED" ? "complete" : "failed"}`);
        } catch (error) {
          if (error instanceof IdentityLinkVerificationError) {
            try { await options.identityLinks.reject(error.challengeId, error.outcomeCode); } catch { /* Keep callback errors generic. */ }
          }
          return reply.redirect(`${options.webOrigin}/?identity_link=failed`);
        }
      }
      const bindingCookie = state ? transactionCookieName(state) : "";
      const browserBinding = bindingCookie ? request.cookies[bindingCookie] : undefined;
      if (!state || !browserBinding) {
        return reply.code(400).send({ error: "Authentication could not be completed" });
      }

      reply.clearCookie(bindingCookie, cookieOptions(0));
      const callbackUrl = new URL(options.redirectUri);
      const requestUrl = new URL(request.raw.url ?? "/api/v1/auth/callback", callbackUrl);
      if (requestUrl.origin !== callbackUrl.origin || requestUrl.pathname !== callbackUrl.pathname) {
        return reply.code(400).send({ error: "Authentication could not be completed" });
      }
      callbackUrl.search = requestUrl.search;

      let externalIdentity: { issuer: string; subject: string };
      try {
        externalIdentity = await options.oidc.completeLogin(callbackUrl, state, browserBinding);
      } catch {
        return reply.redirect(`${options.webOrigin}/?auth=failed`);
      }

      let platformUser: { id: string; displayName: string } | null;
      try {
        platformUser = await options.identities.resolveActiveIdentity(
          externalIdentity.issuer,
          externalIdentity.subject,
        );
      } catch {
        return reply.redirect(`${options.webOrigin}/?auth=unavailable`);
      }
      if (!platformUser) {
        return reply.redirect(`${options.webOrigin}/?auth=denied`);
      }

      try {
        const { sessionId, session } = await options.sessions.create(platformUser.id);
        reply.header("Cache-Control", "no-store");
        setPlatformSessionCookie(reply, sessionId, Math.min(
          SESSION_IDLE_TIMEOUT_MS,
          session.absoluteExpiresAt - session.createdAt,
        ));
        return reply.redirect(options.webOrigin);
      } catch {
        return reply.redirect(`${options.webOrigin}/?auth=unavailable`);
      }
    });

    app.get("/api/v1/auth/logout/callback", async (request, reply) => {
      const query = request.query as Record<string, unknown>;
      const state = typeof query.state === "string" ? query.state : "";
      if (!state || !(await options.oidc.consumeLogoutState(state))) {
        return reply.code(400).send({ error: "Sign-out could not be completed" });
      }
      return reply.redirect(options.webOrigin);
    });

    app.get("/api/v1/auth/session", {
      preHandler: app.authenticatePlatformUser,
    }, async (request, reply) => {
      const platformUser = request.platformUser!;
      const session = request.platformSession!;
      return reply.send({
        user: platformUser,
        csrfToken: session.csrfToken,
        expiresAt: session.absoluteExpiresAt,
      });
    });

    app.post("/api/v1/auth/logout", async (request, reply) => {
      const sessionId = request.cookies[sessionCookieName()];
      const stored = await options.sessions.get(sessionId);
      if (!stored) {
        clearPlatformSessionCookie(reply);
        return reply.send({ logoutUrl: options.webOrigin });
      }

      const csrfToken = request.headers["x-csrf-token"];
      if (
        !requireBrowserOrigin(request, options.webOrigin) ||
        typeof csrfToken !== "string" ||
        !safeEqual(csrfToken, stored.session.csrfToken)
      ) {
        return reply.code(403).send({ error: "Request verification failed" });
      }

      await options.sessions.destroy(sessionId);
      clearPlatformSessionCookie(reply);
      try {
        const state = await options.oidc.createLogoutState();
        const logoutUrl = await options.oidc.buildLogoutUrl(state);
        return reply.send({ logoutUrl, postLogoutRedirectUri: options.postLogoutRedirectUri });
      } catch {
        return reply.send({ logoutUrl: options.webOrigin });
      }
    });
  };
}
