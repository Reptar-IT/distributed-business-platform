import { describe, expect, it } from "vitest";
import type { Redis } from "ioredis";
import {
  createSessionStore,
  SESSION_ABSOLUTE_LIFETIME_MS,
  SESSION_IDLE_TIMEOUT_MS,
} from "./session.store.js";

class MemoryRedis {
  values = new Map<string, string>();
  expirations = new Map<string, number>();
  lastSetTtl = 0;
  lastExpireTtl = 0;

  async set(key: string, value: string, mode: string, ttl: number): Promise<"OK"> {
    if (mode === "PX") this.lastSetTtl = ttl;
    this.values.set(key, value);
    return "OK";
  }

  async get(key: string): Promise<string | null> {
    return this.values.get(key) ?? null;
  }

  async pexpire(key: string, ttl: number): Promise<number> {
    this.lastExpireTtl = ttl;
    return this.values.has(key) ? 1 : 0;
  }

  async del(key: string): Promise<number> {
    return this.values.delete(key) ? 1 : 0;
  }
}

describe("Redis platform sessions", () => {
  it("starts with the idle timeout and renews activity without extending absolute expiry", async () => {
    let now = 1_000_000;
    const redis = new MemoryRedis();
    const sessions = createSessionStore(redis as unknown as Redis, () => now);
    const { sessionId, session } = await sessions.create("user-1");

    expect(redis.lastSetTtl).toBe(SESSION_IDLE_TIMEOUT_MS);
    expect(session.absoluteExpiresAt - session.createdAt).toBe(SESSION_ABSOLUTE_LIFETIME_MS);

    now += SESSION_ABSOLUTE_LIFETIME_MS - 60_000;
    const stored = await sessions.getAndTouch(sessionId);
    expect(stored?.maxAgeMs).toBe(60_000);
    expect(redis.lastExpireTtl).toBe(60_000);

    now += 60_001;
    expect(await sessions.getAndTouch(sessionId)).toBeNull();
    expect(redis.values.size).toBe(0);
  });

  it("immediately invalidates a session on destroy", async () => {
    const redis = new MemoryRedis();
    const sessions = createSessionStore(redis as unknown as Redis);
    const { sessionId } = await sessions.create("user-2");

    await sessions.destroy(sessionId);
    expect(await sessions.get(sessionId)).toBeNull();
  });
});
