import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { IdentityService, PlatformIdentity } from "./identity.service.js";
import {
  clearPlatformSessionCookie,
  sessionCookieName,
  setPlatformSessionCookie,
  type PlatformSession,
  type SessionStore,
} from "./session.store.js";

type PlatformAuthHook = (request: FastifyRequest, reply: FastifyReply) => Promise<void | FastifyReply>;

declare module "fastify" {
  interface FastifyRequest {
    platformUser: PlatformIdentity | null;
    platformSession: PlatformSession | null;
  }
  interface FastifyInstance {
    authenticatePlatformUser: PlatformAuthHook;
  }
}

export function registerPlatformAuthentication(
  app: FastifyInstance,
  dependencies: { sessions: SessionStore; identities: IdentityService },
): void {
  app.decorateRequest("platformUser", null);
  app.decorateRequest("platformSession", null);

  const authenticatePlatformUser: PlatformAuthHook = async (request, reply) => {
    const sessionId = request.cookies[sessionCookieName()];
    const stored = await dependencies.sessions.getAndTouch(sessionId);
    if (!stored) {
      clearPlatformSessionCookie(reply);
      return reply.code(401).send({ error: "Not authenticated" });
    }

    const platformUser = await dependencies.identities.getActiveUser(stored.session.userId);
    if (!platformUser) {
      await dependencies.sessions.destroy(sessionId);
      clearPlatformSessionCookie(reply);
      return reply.code(401).send({ error: "Not authenticated" });
    }

    request.platformUser = platformUser;
    request.platformSession = stored.session;
    setPlatformSessionCookie(reply, sessionId!, stored.maxAgeMs);
  };

  app.decorate("authenticatePlatformUser", authenticatePlatformUser);
}

export function requireBrowserOrigin(request: FastifyRequest, expectedOrigin: string): boolean {
  return request.headers.origin === expectedOrigin;
}
