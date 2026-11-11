
import { prisma, type Prisma } from "@platform/database";

import type { CreateAssignmentInput } from "./workforce.schemas.js";

type TransactionClient = Prisma.TransactionClient;

/**
 * Runs an operation using an existing transaction when supplied.
 * Otherwise, creates a new transaction.
 */
const executeInTransaction = <T>(
  tx: TransactionClient | undefined,
  operation: (client: TransactionClient) => Promise<T>,
): Promise<T> => {
  if (tx) {
    return operation(tx);
  }

  return prisma.$transaction(operation);
};

/**
 * Creates an assignment for an active venture member.
 *
 * PRIMARY:
 *   The member's normal venture role.
 *
 * ACTING:
 *   A temporary additional assignment, including promotion trials
 *   and temporary vacancy coverage.
 *
 * Creating an ACTING assignment never terminates or replaces
 * the member's existing PRIMARY assignment.
 */
export const createAssignment = async (
  input: CreateAssignmentInput,
  tx?: TransactionClient,
) => {
  return executeInTransaction(tx, async (client) => {
    const membership = await client.ventureMembership.findUnique({
      where: {
        id: input.membershipId,
      },
    });

    if (!membership) {
      throw new Error("Membership not found.");
    }

    if (membership.status !== "ACTIVE") {
      throw new Error(
        "Assignments can only be created for active memberships.",
      );
    }

    const role = await client.organizationalRole.findFirst({
      where: {
        id: input.organizationalRoleId,
        ventureId: membership.ventureId,
        status: "ACTIVE",
      },
    });

    if (!role) {
      throw new Error(
        "The selected role does not exist, is inactive, or belongs to another venture.",
      );
    }

    if (input.assignmentType === "PRIMARY") {
      const existingPrimary = await client.roleAssignment.findFirst({
        where: {
          membershipId: membership.id,
          status: "ACTIVE",
          assignmentType: "PRIMARY",
        },
      });

      if (existingPrimary) {
        throw new Error(
          "This membership already has an active primary role.",
        );
      }
    }

    return client.roleAssignment.create({
      data: {
        membershipId: membership.id,
        organizationalRoleId: role.id,
        ventureId: membership.ventureId,
        assignmentType: input.assignmentType,
        status: "ACTIVE",
        startsAt: input.startsAt ?? new Date(),
      },
    });
  });
};

/**
 * Completes an active ACTING assignment.
 *
 * Completing an acting assignment does not affect the member's
 * existing primary assignment.
 *
 * Primary assignments are managed through membership termination
 * or an explicit primary-role transition.
 */
export const completeAssignment = async (
  assignmentId: string,
  tx?: TransactionClient,
) => {
  return executeInTransaction(tx, async (client) => {
    const assignment = await client.roleAssignment.findUnique({
      where: {
        id: assignmentId,
      },
      include: {
        membership: true,
      },
    });

    if (!assignment) {
      throw new Error("Role assignment not found.");
    }

    if (assignment.status !== "ACTIVE") {
      throw new Error("Only active assignments can be completed.");
    }

    if (assignment.assignmentType === "PRIMARY") {
      throw new Error(
        "Primary assignments cannot be completed through this operation. Use a primary-role transition or end the membership.",
      );
    }

    if (assignment.membership.status !== "ACTIVE") {
      throw new Error(
        "Acting assignments can only be completed through this operation for active memberships.",
      );
    }

    return client.roleAssignment.update({
      where: {
        id: assignment.id,
      },
      data: {
        status: "COMPLETED",
        endsAt: new Date(),
      },
    });
  });
};

/**
 * Confirms a successful promotion trial.
 *
 * The member must have exactly one active PRIMARY assignment
 * and an active ACTING assignment in the same venture.
 *
 * The former primary assignment is completed, and the acting
 * assignment becomes the new primary assignment.
 *
 * Both changes happen in one database transaction.
 */
export const transitionPrimaryAssignment = async (
  membershipId: string,
  actingAssignmentId: string,
  tx?: TransactionClient,
) => {
  return executeInTransaction(tx, async (client) => {
    const membership = await client.ventureMembership.findUnique({
      where: {
        id: membershipId,
      },
    });

    if (!membership || membership.status !== "ACTIVE") {
      throw new Error("An active membership is required.");
    }

    const primaryAssignments = await client.roleAssignment.findMany({
      where: {
        membershipId,
        status: "ACTIVE",
        assignmentType: "PRIMARY",
      },
    });

    if (primaryAssignments.length !== 1) {
      throw new Error(
        "The membership must have exactly one active primary assignment.",
      );
    }

    const actingAssignment = await client.roleAssignment.findFirst({
      where: {
        id: actingAssignmentId,
        membershipId,
        ventureId: membership.ventureId,
        assignmentType: "ACTING",
        status: "ACTIVE",
      },
    });

    if (!actingAssignment) {
      throw new Error(
        "An active acting assignment belonging to this membership is required.",
      );
    }

    const now = new Date();

    const completedPrimary = await client.roleAssignment.update({
      where: {
        id: primaryAssignments[0].id,
      },
      data: {
        status: "COMPLETED",
        endsAt: now,
      },
    });

    const newPrimary = await client.roleAssignment.update({
      where: {
        id: actingAssignment.id,
      },
      data: {
        assignmentType: "PRIMARY",
      },
    });

    return {
      previousPrimaryAssignment: completedPrimary,
      newPrimaryAssignment: newPrimary,
    };
  });
};

/**
 * Retrieves an assignment and its associated membership and role.
 */
export const getAssignment = async (assignmentId: string) => {
  return prisma.roleAssignment.findUnique({
    where: {
      id: assignmentId,
    },
    include: {
      membership: {
        include: {
          user: true,
        },
      },
      organizationalRole: true,
    },
  });
};

/**
 * Lists active assignments belonging to a membership.
 */
export const getMembershipAssignments = async (
  membershipId: string,
) => {
  return prisma.roleAssignment.findMany({
    where: {
      membershipId,
      status: "ACTIVE",
    },
    include: {
      organizationalRole: true,
    },
    orderBy: {
      startsAt: "asc",
    },
  });
};
