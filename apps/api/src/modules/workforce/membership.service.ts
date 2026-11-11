
import { prisma } from "@platform/database";
import type { CreateMembershipInput } from "./workforce.schemas.js";

/**
 * Creates a pending membership.
 *
 * Membership activation is deliberately separate:
 * an ACTIVE membership must have exactly one active PRIMARY assignment.
 */
export const createMembership = async (input: CreateMembershipInput) => {
  const existingMembership = await prisma.ventureMembership.findFirst({
    where: {
      ventureId: input.ventureId,
      userId: input.userId,
      status: {
        in: ["PENDING", "ACTIVE", "SUSPENDED"],
      },
    },
  });

  if (existingMembership) {
    throw new Error(
      "This user already has a membership in this venture that has not ended.",
    );
  }

  return prisma.ventureMembership.create({
    data: {
      ventureId: input.ventureId,
      userId: input.userId,
      status: "PENDING",
    },
  });
};

/**
 * Activates a pending membership and creates its primary assignment.
 *
 * Both operations happen in one database transaction.
 */
export const activateMembership = async (
  membershipId: string,
  organizationalRoleId: string,
) => {
  return prisma.$transaction(async (tx) => {
    const membership = await tx.ventureMembership.findUnique({
      where: {
        id: membershipId,
      },
    });

    if (!membership) {
      throw new Error("Membership not found.");
    }

    if (membership.status !== "PENDING") {
      throw new Error("Only pending memberships can be activated.");
    }

    const role = await tx.organizationalRole.findFirst({
      where: {
        id: organizationalRoleId,
        ventureId: membership.ventureId,
        status: "ACTIVE",
      },
    });

    if (!role) {
      throw new Error(
        "The selected role does not exist, is inactive, or belongs to another venture.",
      );
    }

    const existingPrimaryAssignment = await tx.roleAssignment.findFirst({
      where: {
        membershipId,
        status: "ACTIVE",
        assignmentType: "PRIMARY",
      },
    });

    if (existingPrimaryAssignment) {
      throw new Error(
        "This membership already has an active primary assignment.",
      );
    }

    const now = new Date();

    const assignment = await tx.roleAssignment.create({
      data: {
        membershipId,
        organizationalRoleId,
        ventureId: membership.ventureId,
        assignmentType: "PRIMARY",
        status: "ACTIVE",
        startsAt: now,
      },
    });

    const activatedMembership = await tx.ventureMembership.update({
      where: {
        id: membershipId,
      },
      data: {
        status: "ACTIVE",
        joinedAt: now,
        endedAt: null,
      },
    });

    return {
      membership: activatedMembership,
      primaryAssignment: assignment,
    };
  });
};

/**
 * Suspends an active membership.
 *
 * Existing assignments are preserved so that a permitted reactivation
 * does not require reconstructing the member's role history.
 *
 * Access control must independently reject suspended memberships.
 */
export const suspendMembership = async (membershipId: string) => {
  return prisma.$transaction(async (tx) => {
    const membership = await tx.ventureMembership.findUnique({
      where: {
        id: membershipId,
      },
    });

    if (!membership) {
      throw new Error("Membership not found.");
    }

    if (membership.status !== "ACTIVE") {
      throw new Error("Only active memberships can be suspended.");
    }

    return tx.ventureMembership.update({
      where: {
        id: membershipId,
      },
      data: {
        status: "SUSPENDED",
      },
    });
  });
};

/**
 * Reactivates a suspended membership.
 *
 * The original active primary assignment must still exist.
 */
export const reactivateMembership = async (membershipId: string) => {
  return prisma.$transaction(async (tx) => {
    const membership = await tx.ventureMembership.findUnique({
      where: {
        id: membershipId,
      },
    });

    if (!membership) {
      throw new Error("Membership not found.");
    }

    if (membership.status !== "SUSPENDED") {
      throw new Error("Only suspended memberships can be reactivated.");
    }

    const primaryAssignments = await tx.roleAssignment.findMany({
      where: {
        membershipId,
        status: "ACTIVE",
        assignmentType: "PRIMARY",
      },
    });

    if (primaryAssignments.length !== 1) {
      throw new Error(
        "Membership cannot be reactivated without exactly one active primary assignment.",
      );
    }

    return tx.ventureMembership.update({
      where: {
        id: membershipId,
      },
      data: {
        status: "ACTIVE",
      },
    });
  });
};

/**
 * Ends a membership and completes all its active assignments.
 *
 * Ownership and vesting records are not modified by this operation.
 */
export const endMembership = async (membershipId: string) => {
  return prisma.$transaction(async (tx) => {
    const membership = await tx.ventureMembership.findUnique({
      where: {
        id: membershipId,
      },
    });

    if (!membership) {
      throw new Error("Membership not found.");
    }

    if (membership.status === "ENDED") {
      throw new Error("This membership has already ended.");
    }

    const now = new Date();

    await tx.roleAssignment.updateMany({
      where: {
        membershipId,
        status: "ACTIVE",
      },
      data: {
        status: "COMPLETED",
        endsAt: now,
      },
    });

    return tx.ventureMembership.update({
      where: {
        id: membershipId,
      },
      data: {
        status: "ENDED",
        endedAt: now,
      },
    });
  });
};

/**
 * Retrieves a membership and its assignment history.
 */
export const getMembership = async (membershipId: string) => {
  return prisma.ventureMembership.findUnique({
    where: {
      id: membershipId,
    },
    include: {
      user: true,
      venture: true,
      assignments: {
        include: {
          organizationalRole: true,
        },
        orderBy: {
          startsAt: "desc",
        },
      },
    },
  });
};

/**
 * Lists memberships belonging to a venture.
 */
export const getVentureMemberships = async (ventureId: string) => {
  return prisma.ventureMembership.findMany({
    where: {
      ventureId,
    },
    include: {
      user: true,
      assignments: {
        where: {
          status: "ACTIVE",
        },
        include: {
          organizationalRole: true,
        },
      },
    },
    orderBy: {
      createdAt: "desc",
    },
  });
};