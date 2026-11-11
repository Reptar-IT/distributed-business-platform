
import { prisma, type Prisma, type MembershipEndReason } from "@platform/database";

import { endMembership } from "./membership.service.js";

import {
  completeAssignment,
  transitionPrimaryAssignment,
} from "./assignment.service.js";

import {
  markVacancyFilled,
  openVacancy,
} from "./vacancy.service.js";

type TransactionClient = Prisma.TransactionClient;

interface ConfirmPromotionTrialInput {
  membershipId: string;
  actingAssignmentId: string;
  vacancyId: string;
}

/**
 * Confirms a successful promotion trial.
 *
 * The operation is atomic:
 *
 * 1. The member's former PRIMARY assignment is completed.
 * 2. Their ACTING assignment becomes their new PRIMARY assignment.
 * 3. The vacancy they were trialling for is marked FILLED.
 * 4. A new vacancy is opened for their former PRIMARY role.
 *
 * The former primary role is not opened for recruitment until
 * the promotion succeeds.
 */
export const confirmPromotionTrial = async (
  input: ConfirmPromotionTrialInput,
) => {
  return prisma.$transaction(async (tx) => {
    const {
      previousPrimaryAssignment,
      newPrimaryAssignment,
    } = await transitionPrimaryAssignment(
      input.membershipId,
      input.actingAssignmentId,
      tx,
    );

    const filledVacancy = await markVacancyFilled(
      input.vacancyId,
      newPrimaryAssignment.id,
      tx,
    );

    const resultingVacancy = await openVacancy(
      {
        ventureId: previousPrimaryAssignment.ventureId,
        organizationalRoleId:
          previousPrimaryAssignment.organizationalRoleId,
        previousAssignmentId: previousPrimaryAssignment.id,
        sourceVacancyId: input.vacancyId,
      },
      tx,
    );

    return {
      previousPrimaryAssignment,
      newPrimaryAssignment,
      filledVacancy,
      resultingVacancy,
    };
  });
};

/**
 * Records an unsuccessful promotion trial.
 *
 * The ACTING assignment is completed.
 * The member's former PRIMARY assignment remains active.
 *
 * No vacancy is opened for the member's former role.
 */
export const failPromotionTrial = async (
  actingAssignmentId: string,
) => {
  return prisma.$transaction(async (tx) => {
    const completedActingAssignment = await completeAssignment(
      actingAssignmentId,
      tx,
    );

    return {
      completedActingAssignment,
    };
  });
};


export const endVentureMembership = async (
  membershipId: string,
) => {
  return prisma.$transaction(async (tx) => {
    const membership = await tx.ventureMembership.findUnique({
      where: {
        id: membershipId,
      },
    });

    if (!membership) {
      throw new Error("Venture membership not found.");
    }

    if (membership.status !== "ACTIVE") {
      throw new Error(
        "Only active venture memberships can be ended through this operation.",
      );
    }

    const primaryAssignment = await tx.roleAssignment.findFirst({
      where: {
        membershipId,
        assignmentType: "PRIMARY",
        status: "ACTIVE",
      },
    });

    if (!primaryAssignment) {
      throw new Error(
        "The active membership does not have an active primary assignment.",
      );
    }

    const endedMembership = await endMembership(
      membershipId,
      tx,
    );

    const resultingVacancy = await openVacancy(
      {
        ventureId: membership.ventureId,
        organizationalRoleId:
          primaryAssignment.organizationalRoleId,
        previousAssignmentId: primaryAssignment.id,
      },
      tx,
    );

    return {
      membership: endedMembership,
      previousPrimaryAssignment: primaryAssignment,
      resultingVacancy,
    };
  });
};


/**
 * Ends a suspended venture membership.
 *
 * All active assignments are completed by the membership service.
 * No vacancy is opened automatically because the suspended
 * membership may already be covered by an existing arrangement.
 *
 * Ownership and previously earned vesting are not modified.
 */
export const endSuspendedVentureMembership = async (
  membershipId: string,
) => {
  return prisma.$transaction(async (tx) => {
    const membership = await tx.ventureMembership.findUnique({
      where: {
        id: membershipId,
      },
    });

    if (!membership) {
      throw new Error("Venture membership not found.");
    }

    if (membership.status !== "SUSPENDED") {
      throw new Error(
        "Only suspended venture memberships can be ended through this operation.",
      );
    }

    const endedMembership = await endMembership(
      membershipId,
      tx,
    );

    return {
      membership: endedMembership,
    };
  });
};

/**
 * Ends a pending membership when the person does not proceed
 * into an active venture role.
 *
 * No assignment or vacancy is created.
 * Ownership and vesting records are not modified.
 */
export const endPendingVentureMembership = async (
  membershipId: string,
  reason: MembershipEndReason,
) => {
  return prisma.$transaction(async (tx) => {
    const membership = await tx.ventureMembership.findUnique({
      where: {
        id: membershipId,
      },
    });

    if (!membership) {
      throw new Error("Venture membership not found.");
    }

    if (membership.status !== "PENDING") {
      throw new Error(
        "Only pending venture memberships can be ended through this operation.",
      );
    }

    const endedMembership = await endMembership(
      membershipId,
      tx,
      reason,
    );

    return {
      membership: endedMembership,
    };
  });
};

