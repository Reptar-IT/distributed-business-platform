import { timingSafeEqual } from "node:crypto";
import type { FastifyPluginAsync, FastifyRequest } from "fastify";
import type { IdentityService } from "./identity.service.js";
import { createBrowserBinding, IdentityLinkVerificationError, OwnerRecoveryVerificationError, type OidcService } from "./oidc.service.js";
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
    getPendingTarget(challengeId: string): Promise<{ platformUserId: string } | null>;
    complete(input: { challengeId: string; platformUserId: string; issuer: string; subject: string; verifiedAt: Date }): Promise<string>;
    reject(challengeId: string, outcomeCode: string): Promise<void>;
  };
  ownerRecoveryKits?: {
    isActiveOwner(platformUserId: string): Promise<boolean>;
    issueOrReplace(input: { platformUserId: string; issuer: string; subject: string }): Promise<{ kit_id: string; generation: number; replaced: boolean; codes: string[] }>;
  };
  ownerRecoveryCallback?: {
    complete(input: { operationId: string; issuer: string; subject: string; verifiedAt: Date }): Promise<string>;
    reject(operationId: string, outcomeCode: string): Promise<void>;
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

function identityLinkConfirmationCookieName(confirmationId: string): string {
  const prefix = process.env.NODE_ENV === "production" ? "__Host-dbp_identity_link_" : "dbp_identity_link_";
  return `${prefix}${confirmationId}`;
}

function identityLinkCookieOptions(maxAgeSeconds: number) {
  return {
    path: "/",
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict" as const,
    maxAge: maxAgeSeconds,
  };
}

function confirmationFields(body: unknown): { confirmationId: string; csrfToken: string; decision: "confirm" | "cancel" } | null {
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  const fields = body as Record<string, unknown>;
  if (Object.keys(fields).sort().join(",") !== "confirmationId,csrfToken,decision" ||
      typeof fields.confirmationId !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(fields.confirmationId) ||
      typeof fields.csrfToken !== "string" ||
      (fields.decision !== "confirm" && fields.decision !== "cancel")) return null;
  return { confirmationId: fields.confirmationId, csrfToken: fields.csrfToken, decision: fields.decision };
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
      if (state.startsWith("or_")) {
        if (!options.ownerRecoveryCallback) return reply.code(503).send({ error: "Owner recovery is unavailable" });
        const callbackUrl = new URL(options.redirectUri);
        const requestUrl = new URL(request.raw.url ?? "/api/v1/auth/callback", callbackUrl);
        if (requestUrl.origin !== callbackUrl.origin || requestUrl.pathname !== callbackUrl.pathname) {
          return reply.code(400).send({ error: "Owner recovery could not be completed" });
        }
        callbackUrl.search = requestUrl.search;
        try {
          const proof = await options.oidc.completeOwnerRecovery(callbackUrl, state);
          const outcome = await options.ownerRecoveryCallback.complete({
            operationId: proof.operationId,
            ...proof.identity,
            verifiedAt: proof.verifiedAt,
          });
          const accepted = ["PREPARED", "AWAITING_ARCHIVE", "READY_TO_FINALIZE", "FINALIZED"].includes(outcome);
          return reply.redirect(`${options.webOrigin}/?owner_recovery=${accepted ? "processing" : "failed"}`);
        } catch (error) {
          if (error instanceof OwnerRecoveryVerificationError) {
            try { await options.ownerRecoveryCallback.reject(error.operationId, error.outcomeCode); } catch { /* Failure remains bounded and audited when the database is available. */ }
          }
          return reply.redirect(`${options.webOrigin}/?owner_recovery=failed`);
        }
      }
      if (state.startsWith("il_")) {
        if (!options.identityLinks) return reply.code(503).send({ error: "Identity linking is unavailable" });
        const callbackUrl = new URL(options.redirectUri);
        const requestUrl = new URL(request.raw.url ?? "/api/v1/auth/callback", callbackUrl);
        if (requestUrl.origin !== callbackUrl.origin || requestUrl.pathname !== callbackUrl.pathname) {
          return reply.code(400).send({ error: "Identity linking could not be completed" });
        }
        callbackUrl.search = requestUrl.search;
        let challengeId: string | undefined;
        try {
          const proof = await options.oidc.completeIdentityLink(callbackUrl, state);
          challengeId = proof.challengeId;
          const target = await options.identityLinks.getPendingTarget(challengeId);
          if (!target) {
            await options.identityLinks.reject(challengeId, "confirmation_not_available");
            return reply.redirect(`${options.webOrigin}/?identity_link=failed`);
          }
          const confirmation = await options.oidc.createIdentityLinkConfirmation(proof, target.platformUserId);
          reply.setCookie(
            identityLinkConfirmationCookieName(confirmation.confirmationId),
            confirmation.browserBinding,
            identityLinkCookieOptions(5 * 60),
          );
          const confirmationUrl = new URL(options.webOrigin);
          confirmationUrl.hash = `identity-link-confirmation/${confirmation.confirmationId}`;
          return reply.redirect(confirmationUrl.href);
        } catch (error) {
          const rejectedChallengeId = error instanceof IdentityLinkVerificationError ? error.challengeId : challengeId;
          const outcomeCode = error instanceof IdentityLinkVerificationError ? error.outcomeCode : "confirmation_unavailable";
          if (rejectedChallengeId) try { await options.identityLinks.reject(rejectedChallengeId, outcomeCode); } catch { /* Keep callback errors generic. */ }
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
        const { sessionId, session } = await options.sessions.create(platformUser.id, externalIdentity);
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

    app.get<{ Params: { confirmationId: string } }>("/api/v1/auth/identity-link/confirmation/:confirmationId", async (request, reply) => {
      if (!requireBrowserOrigin(request, options.webOrigin) || !options.identityLinks) {
        return reply.code(options.identityLinks ? 403 : 503).send({ error: "Identity-link confirmation is unavailable" });
      }
      const { confirmationId } = request.params;
      if (!/^[A-Za-z0-9_-]{43}$/.test(confirmationId)) return reply.code(404).send({ error: "Confirmation was not found" });
      const confirmation = await options.oidc.getIdentityLinkConfirmation(
        confirmationId,
        request.cookies[identityLinkConfirmationCookieName(confirmationId)] ?? "",
      );
      if (!confirmation) return reply.code(404).send({ error: "Confirmation was not found or has expired" });
      const target = await options.identityLinks.getPendingTarget(confirmation.challengeId);
      if (!target || target.platformUserId !== confirmation.platformUserId) {
        try { await options.identityLinks.reject(confirmation.challengeId, "confirmation_target_mismatch"); } catch { /* Fail closed. */ }
        return reply.code(410).send({ error: "Confirmation was not found or has expired" });
      }
      reply.header("Cache-Control", "no-store");
      reply.header("Referrer-Policy", "no-referrer");
      return reply.send({ platformUserId: confirmation.platformUserId, issuer: confirmation.issuer, csrfToken: confirmation.csrfToken });
    });

    app.post("/api/v1/auth/identity-link/confirmation", async (request, reply) => {
      if (!requireBrowserOrigin(request, options.webOrigin) || !options.identityLinks) {
        return reply.code(options.identityLinks ? 403 : 503).send({ error: "Identity-link confirmation is unavailable" });
      }
      const fields = confirmationFields(request.body);
      if (!fields) return reply.code(400).send({ error: "Identity-link confirmation is invalid" });
      const cookieName = identityLinkConfirmationCookieName(fields.confirmationId);
      const proof = await options.oidc.consumeIdentityLinkConfirmation(
        fields.confirmationId,
        fields.csrfToken,
        request.cookies[cookieName] ?? "",
      );
      reply.clearCookie(cookieName, identityLinkCookieOptions(0));
      if (!proof) return reply.code(400).send({ error: "Identity-link confirmation is invalid or expired" });
      if (fields.decision === "cancel") {
        await options.identityLinks.reject(proof.challengeId, "holder_cancelled");
        return reply.send({ outcome: "cancelled" });
      }
      const target = await options.identityLinks.getPendingTarget(proof.challengeId);
      if (!target || target.platformUserId !== proof.platformUserId) {
        await options.identityLinks.reject(proof.challengeId, "confirmation_target_mismatch");
        return reply.code(409).send({ error: "Identity-link confirmation could not be completed" });
      }
      try {
        const outcome = await options.identityLinks.complete({
          challengeId: proof.challengeId,
          platformUserId: proof.platformUserId,
          ...proof.identity,
          verifiedAt: proof.verifiedAt,
        });
        return reply.send({ outcome: outcome === "LINKED" || outcome === "ALREADY_VERIFIED" ? "linked" : "rejected" });
      } catch {
        try { await options.identityLinks.reject(proof.challengeId, "confirmation_processing_failed"); } catch { /* Keep callback failures generic. */ }
        return reply.code(503).send({ error: "Identity-link confirmation could not be completed" });
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
        isPlatformOwner: options.ownerRecoveryKits ? await options.ownerRecoveryKits.isActiveOwner(platformUser.id) : false,
      });
    });

    app.post("/api/v1/auth/owner/recovery-kit", {
      preHandler: app.authenticatePlatformUser,
    }, async (request, reply) => {
      const session = request.platformSession!;
      const csrfToken = request.headers["x-csrf-token"];
      if (!options.ownerRecoveryKits) return reply.code(503).send({ error: "Owner recovery-kit issuance is unavailable" });
      if (!requireBrowserOrigin(request, options.webOrigin) || typeof csrfToken !== "string" || !safeEqual(csrfToken, session.csrfToken)) {
        return reply.code(403).send({ error: "Request verification failed" });
      }
      try {
        const kit = await options.ownerRecoveryKits.issueOrReplace({
          platformUserId: session.userId,
          issuer: session.identity.issuer,
          subject: session.identity.subject,
        });
        reply.header("Cache-Control", "no-store");
        reply.header("Pragma", "no-cache");
        return reply.send({ generation: kit.generation, replaced: kit.replaced, codes: kit.codes });
      } catch {
        return reply.code(403).send({ error: "Recovery-kit issuance was rejected" });
      }
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
