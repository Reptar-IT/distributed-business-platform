
import { prisma } from "@platform/database";
import type { CreateRoleInput } from "./workforce.schemas.js";

/**
 * Creates an organisational role within a venture.
 *
 * New roles begin in DRAFT status and must be explicitly activated.
 */
export const createRole = async (input: CreateRoleInput) => {
  const venture = await prisma.venture.findUnique({
    where: {
      id: input.ventureId,
    },
  });

  if (!venture) {
    throw new Error("Venture not found.");
  }

  if (input.parentRoleId) {
    const parentRole = await prisma.organizationalRole.findFirst({
      where: {
        id: input.parentRoleId,
        ventureId: input.ventureId,
        status: {
          not: "INACTIVE",
        },
      },
    });

    if (!parentRole) {
      throw new Error(
        "The parent role does not exist, is inactive, or belongs to another venture.",
      );
    }
  }

  return prisma.organizationalRole.create({
    data: {
      ventureId: input.ventureId,
      parentRoleId: input.parentRoleId ?? null,
      title: input.title,
      description: input.description ?? null,
      responsibilities: input.responsibilities ?? undefined,
      authorityScope: input.authorityScope ?? undefined,
      requirements: input.requirements ?? undefined,
      isMandatory: input.isMandatory,
      status: "DRAFT",
    },
  });
};

/**
 * Activates a draft organisational role.
 */
export const activateRole = async (roleId: string) => {
  const role = await prisma.organizationalRole.findUnique({
    where: {
      id: roleId,
    },
  });

  if (!role) {
    throw new Error("Organisational role not found.");
  }

  if (role.status !== "DRAFT") {
    throw new Error("Only draft roles can be activated.");
  }

  return prisma.organizationalRole.update({
    where: {
      id: roleId,
    },
    data: {
      status: "ACTIVE",
    },
  });
};

/**
 * Retrieves an organisational role and its hierarchy.
 */
export const getRole = async (roleId: string) => {
  return prisma.organizationalRole.findUnique({
    where: {
      id: roleId,
    },
    include: {
      parentRole: true,
      childRoles: true,
      assignments: {
        where: {
          status: "ACTIVE",
        },
      },
      vacancies: {
        where: {
          status: {
            notIn: ["FILLED", "CANCELLED"],
          },
        },
      },
    },
  });
};

/**
 * Lists all organisational roles belonging to a venture.
 */
export const getVentureRoles = async (ventureId: string) => {
  return prisma.organizationalRole.findMany({
    where: {
      ventureId,
    },
    include: {
      parentRole: true,
      childRoles: true,
      _count: {
        select: {
          assignments: true,
          vacancies: true,
        },
      },
    },
    orderBy: [
      {
        createdAt: "asc",
      },
      {
        title: "asc",
      },
    ],
  });
};