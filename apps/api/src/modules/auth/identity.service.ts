import type { PrismaClient } from "@platform/database";

export interface PlatformIdentity {
  id: string;
  displayName: string;
}

export function createIdentityService(prisma: PrismaClient) {
  return {
    async resolveActiveIdentity(issuer: string, subject: string): Promise<PlatformIdentity | null> {
      const identity = await prisma.userIdentity.findUnique({
        where: { issuer_subject: { issuer, subject } },
        include: { user: true },
      });

      if (!identity || identity.user.status !== "ACTIVE") {
        return null;
      }

      return { id: identity.user.id, displayName: identity.user.displayName };
    },

    async getActiveUser(userId: string): Promise<PlatformIdentity | null> {
      const user = await prisma.platformUser.findUnique({ where: { id: userId } });
      if (!user || user.status !== "ACTIVE") return null;
      return { id: user.id, displayName: user.displayName };
    },
  };
}

export type IdentityService = ReturnType<typeof createIdentityService>;
