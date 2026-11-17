import { createHash, randomBytes } from "node:crypto";
import type { Redis } from "ioredis";
import type { FastifyReply } from "fastify";

export const SESSION_IDLE_TIMEOUT_MS = 30 * 60 * 1000;
export const SESSION_ABSOLUTE_LIFETIME_MS = 12 * 60 * 60 * 1000;

export interface PlatformSession {
  userId: string;
  csrfToken: string;
  createdAt: number;
  absoluteExpiresAt: number;
}

function sessionKey(sessionId: string): string {
  const digest = createHash("sha256").update(sessionId).digest("hex");
  return `dbp:session:${digest}`;
}

export function sessionCookieName(production = process.env.NODE_ENV === "production"): string {
  return production ? "__Host-dbp_session" : "dbp_session";
}

function sessionCookieOptions(maxAgeSeconds: number) {
  return {
    path: "/",
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax" as const,
    maxAge: maxAgeSeconds,
  };
}

export function setPlatformSessionCookie(reply: FastifyReply, sessionId: string, maxAgeMs: number): void {
  reply.setCookie(
    sessionCookieName(),
    sessionId,
    sessionCookieOptions(Math.max(1, Math.floor(maxAgeMs / 1000))),
  );
}

export function clearPlatformSessionCookie(reply: FastifyReply): void {
  reply.clearCookie(sessionCookieName(), sessionCookieOptions(0));
}

export function createSessionStore(redis: Redis, now: () => number = Date.now) {
  function remainingLifetime(session: PlatformSession): number {
    return Math.max(0, Math.min(SESSION_IDLE_TIMEOUT_MS, session.absoluteExpiresAt - now()));
  }

  return {
    async create(userId: string): Promise<{ sessionId: string; session: PlatformSession }> {
      const currentTime = now();
      const session: PlatformSession = {
        userId,
        csrfToken: randomBytes(32).toString("base64url"),
        createdAt: currentTime,
        absoluteExpiresAt: currentTime + SESSION_ABSOLUTE_LIFETIME_MS,
      };
      const sessionId = randomBytes(32).toString("base64url");
      const ttl = remainingLifetime(session);
      await redis.set(sessionKey(sessionId), JSON.stringify(session), "PX", ttl, "NX");
      return { sessionId, session };
    },

    async get(sessionId: string | undefined): Promise<{ session: PlatformSession; maxAgeMs: number } | null> {
      if (!sessionId || !/^[A-Za-z0-9_-]{43}$/.test(sessionId)) return null;

      const key = sessionKey(sessionId);
      const serialized = await redis.get(key);
      if (!serialized) return null;

      let session: PlatformSession;
      try {
        session = JSON.parse(serialized) as PlatformSession;
      } catch {
        await redis.del(key);
        return null;
      }

      if (
        typeof session.userId !== "string" ||
        typeof session.csrfToken !== "string" ||
        !Number.isFinite(session.createdAt) ||
        !Number.isFinite(session.absoluteExpiresAt)
      ) {
        await redis.del(key);
        return null;
      }

      const maxAgeMs = remainingLifetime(session);
      if (maxAgeMs <= 0) {
        await redis.del(key);
        return null;
      }

      return { session, maxAgeMs };
    },

    async getAndTouch(sessionId: string | undefined): Promise<{ session: PlatformSession; maxAgeMs: number } | null> {
      const stored = await this.get(sessionId);
      if (!stored || !sessionId) return null;

      const touched = await redis.pexpire(sessionKey(sessionId), stored.maxAgeMs);
      if (touched !== 1) return null;
      return stored;
    },

    async destroy(sessionId: string | undefined): Promise<void> {
      if (!sessionId || !/^[A-Za-z0-9_-]{43}$/.test(sessionId)) return;
      await redis.del(sessionKey(sessionId));
    },
  };
}

export type SessionStore = ReturnType<typeof createSessionStore>;
