
import {
  prisma,
  type Prisma,
  type VacancyStatus,
} from "@platform/database";

import type { CreateVacancyInput } from "./workforce.schemas.js";

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
 * Opens a vacancy for an active organisational role.
 *
 * A previous assignment, when supplied, must already be completed.
 * This prevents a promotion trial from prematurely opening the
 * member's existing primary role.
 */
export const openVacancy = async (
  input: CreateVacancyInput,
  tx?: TransactionClient,
) => {
  return executeInTransaction(tx, async (client) => {
    const role = await client.organizationalRole.findFirst({
      where: {
        id: input.organizationalRoleId,
        ventureId: input.ventureId,
        status: "ACTIVE",
      },
    });

    if (!role) {
      throw new Error(
        "The organisational role does not exist, is inactive, or belongs to another venture.",
      );
    }

    if (input.previousAssignmentId) {
      const previousAssignment = await client.roleAssignment.findFirst({
        where: {
          id: input.previousAssignmentId,
          ventureId: input.ventureId,
          organizationalRoleId: input.organizationalRoleId,
          assignmentType: "PRIMARY",
          status: "COMPLETED",
        },
      });

      if (!previousAssignment) {
        throw new Error(
          "The previous primary assignment must be completed and belong to the vacant role.",
        );
      }
    }

    if (input.sourceVacancyId) {
      const sourceVacancy = await client.roleVacancy.findFirst({
        where: {
          id: input.sourceVacancyId,
          ventureId: input.ventureId,
        },
      });

      if (!sourceVacancy) {
        throw new Error(
          "The source vacancy does not exist or belongs to another venture.",
        );
      }
    }

    return client.roleVacancy.create({
      data: {
        ventureId: input.ventureId,
        organizationalRoleId: input.organizationalRoleId,
        previousAssignmentId: input.previousAssignmentId ?? null,
        sourceVacancyId: input.sourceVacancyId ?? null,
        status: "OPEN",
        resolutionDeadline: input.resolutionDeadline ?? null,
      },
    });
  });
};

/**
 * Moves a vacancy from an expected status to a new status.
 *
 * The conditional update protects against concurrent attempts
 * to advance the same vacancy.
 */
const transitionVacancy = async (
  vacancyId: string,
  expectedStatus: VacancyStatus | VacancyStatus[],
  nextStatus: VacancyStatus,
  tx?: TransactionClient,
) => {
  return executeInTransaction(tx, async (client) => {
    const vacancy = await client.roleVacancy.findUnique({
      where: {
        id: vacancyId,
      },
    });

    if (!vacancy) {
      throw new Error("Vacancy not found.");
    }

    const allowedStatuses = Array.isArray(expectedStatus)
      ? expectedStatus
      : [expectedStatus];

    if (!allowedStatuses.includes(vacancy.status)) {
      throw new Error(
        `Cannot move vacancy from ${vacancy.status} to ${nextStatus}.`,
      );
    }

    const result = await client.roleVacancy.updateMany({
      where: {
        id: vacancyId,
        status: {
          in: allowedStatuses,
        },
      },
      data: {
        status: nextStatus,
        ...(nextStatus === "FILLED" ||
        nextStatus === "UNRESOLVED" ||
        nextStatus === "CANCELLED"
          ? { resolvedAt: new Date() }
          : {}),
      },
    });

    if (result.count !== 1) {
      throw new Error(
        "The vacancy changed during this operation. Retrieve its latest status and try again.",
      );
    }

    return client.roleVacancy.findUniqueOrThrow({
      where: {
        id: vacancyId,
      },
    });
  });
};

/**
 * Starts internal recruitment within the originating venture.
 */
export const startVentureRecruitment = async (
  vacancyId: string,
  tx?: TransactionClient,
) => {
  return transitionVacancy(
    vacancyId,
    "OPEN",
    "RECRUITING_VENTURE",
    tx,
  );
};

/**
 * Expands recruitment to the wider platform workforce.
 *
 * This should happen only after venture-level recruitment
 * has failed to produce a suitable appointment.
 */
export const expandRecruitmentToPlatform = async (
  vacancyId: string,
  tx?: TransactionClient,
) => {
  return transitionVacancy(
    vacancyId,
    "RECRUITING_VENTURE",
    "RECRUITING_PLATFORM",
    tx,
  );
};

/**
 * Expands recruitment to external candidates.
 *
 * This should happen only after platform-wide recruitment
 * has failed to produce a suitable appointment.
 */
export const expandRecruitmentExternally = async (
  vacancyId: string,
  tx?: TransactionClient,
) => {
  return transitionVacancy(
    vacancyId,
    "RECRUITING_PLATFORM",
    "RECRUITING_EXTERNAL",
    tx,
  );
};

/**
 * Moves recruitment into the team decision stage.
 *
 * Candidate eligibility and voting are managed separately.
 * This operation only advances the vacancy lifecycle.
 */
export const beginTeamDecision = async (
  vacancyId: string,
  tx?: TransactionClient,
) => {
  return transitionVacancy(
    vacancyId,
    [
      "RECRUITING_VENTURE",
      "RECRUITING_PLATFORM",
      "RECRUITING_EXTERNAL",
    ],
    "AWAITING_DECISION",
    tx,
  );
};

/**
 * Starts automated placement after the team decision deadline.
 *
 * A configured deadline is required, and it must have expired.
 * Team abstention, insufficient participation or failure to
 * reach a valid decision do not require individual penalties.
 */
export const beginAutomatedPlacement = async (
  vacancyId: string,
  tx?: TransactionClient,
) => {
  return executeInTransaction(tx, async (client) => {
    const vacancy = await client.roleVacancy.findUnique({
      where: {
        id: vacancyId,
      },
    });

    if (!vacancy) {
      throw new Error("Vacancy not found.");
    }

    if (vacancy.status !== "AWAITING_DECISION") {
      throw new Error(
        "Automated placement can only begin after the team decision stage.",
      );
    }

    if (!vacancy.resolutionDeadline) {
      throw new Error(
        "A resolution deadline must be configured before automated placement can begin.",
      );
    }

    const now = new Date();

    if (vacancy.resolutionDeadline > now) {
      throw new Error(
        "The team decision deadline has not yet expired.",
      );
    }

    const result = await client.roleVacancy.updateMany({
      where: {
        id: vacancyId,
        status: "AWAITING_DECISION",
        resolutionDeadline: {
          lte: now,
        },
      },
      data: {
        status: "AUTOMATED_PLACEMENT",
      },
    });

    if (result.count !== 1) {
      throw new Error(
        "The vacancy changed during this operation. Retrieve its latest status.",
      );
    }

    return client.roleVacancy.findUniqueOrThrow({
      where: {
        id: vacancyId,
      },
    });
  });
};

/**
 * Records that a candidate has received an offer.
 *
 * An offer may result from a valid team decision or
 * automated placement.
 */
export const markOfferPending = async (
  vacancyId: string,
  tx?: TransactionClient,
) => {
  return transitionVacancy(
    vacancyId,
    [
      "AWAITING_DECISION",
      "AUTOMATED_PLACEMENT",
    ],
    "OFFER_PENDING",
    tx,
  );
};

/**
 * Marks a vacancy as filled after verifying the appointment.
 *
 * The supplied assignment must be an active PRIMARY assignment
 * for the vacant role, belonging to an active member of the
 * same venture.
 *
 * Acting assignments do not permanently fill vacancies.
 */
export const markVacancyFilled = async (
  vacancyId: string,
  assignmentId: string,
  tx?: TransactionClient,
) => {
  return executeInTransaction(tx, async (client) => {
    const vacancy = await client.roleVacancy.findUnique({
      where: {
        id: vacancyId,
      },
    });

    if (!vacancy) {
      throw new Error("Vacancy not found.");
    }

    if (vacancy.status !== "OFFER_PENDING") {
      throw new Error(
        "Only vacancies with a pending offer can be marked as filled.",
      );
    }

    const assignment = await client.roleAssignment.findFirst({
      where: {
        id: assignmentId,
        ventureId: vacancy.ventureId,
        organizationalRoleId: vacancy.organizationalRoleId,
        assignmentType: "PRIMARY",
        status: "ACTIVE",
        membership: {
          status: "ACTIVE",
        },
      },
    });

    if (!assignment) {
      throw new Error(
        "The appointment must have an active primary assignment for this role and venture.",
      );
    }

    const result = await client.roleVacancy.updateMany({
      where: {
        id: vacancyId,
        status: "OFFER_PENDING",
      },
      data: {
        status: "FILLED",
        resolvedAt: new Date(),
      },
    });

    if (result.count !== 1) {
      throw new Error(
        "The vacancy changed during this operation. Retrieve its latest status.",
      );
    }

    return client.roleVacancy.findUniqueOrThrow({
      where: {
        id: vacancyId,
      },
    });
  });
};

/**
 * Marks a vacancy unresolved when recruitment cannot produce
 * a suitable appointment.
 */
export const markVacancyUnresolved = async (
  vacancyId: string,
  tx?: TransactionClient,
) => {
  return transitionVacancy(
    vacancyId,
    [
      "RECRUITING_VENTURE",
      "RECRUITING_PLATFORM",
      "RECRUITING_EXTERNAL",
      "AWAITING_DECISION",
      "AUTOMATED_PLACEMENT",
      "OFFER_PENDING",
    ],
    "UNRESOLVED",
    tx,
  );
};

/**
 * Cancels an unresolved recruitment process.
 *
 * A filled or already cancelled vacancy cannot be cancelled.
 */
export const cancelVacancy = async (
  vacancyId: string,
  tx?: TransactionClient,
) => {
  return transitionVacancy(
    vacancyId,
    [
      "OPEN",
      "RECRUITING_VENTURE",
      "RECRUITING_PLATFORM",
      "RECRUITING_EXTERNAL",
      "AWAITING_DECISION",
      "AUTOMATED_PLACEMENT",
      "OFFER_PENDING",
      "UNRESOLVED",
    ],
    "CANCELLED",
    tx,
  );
};

/**
 * Retrieves a vacancy with its organisational role,
 * previous assignment and resulting vacancy chain.
 */
export const getVacancy = async (vacancyId: string) => {
  return prisma.roleVacancy.findUnique({
    where: {
      id: vacancyId,
    },
    include: {
      organizationalRole: true,
      previousAssignment: true,
      sourceVacancy: true,
      resultingVacancies: true,
    },
  });
};

/**
 * Lists vacancies belonging to a venture.
 */
export const getVentureVacancies = async (
  ventureId: string,
) => {
  return prisma.roleVacancy.findMany({
    where: {
      ventureId,
    },
    include: {
      organizationalRole: true,
      previousAssignment: true,
      sourceVacancy: true,
    },
    orderBy: {
      openedAt: "desc",
    },
  });
};
