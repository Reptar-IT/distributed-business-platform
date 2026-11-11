import { z } from "zod";

export const uuidSchema = z.string().uuid();

export const jsonObjectSchema = z.record(z.string(), z.json());

export const membershipStatusSchema = z.enum([
  "PENDING",
  "ACTIVE",
  "SUSPENDED",
  "ENDED",
]);

export const assignmentTypeSchema = z.enum(["PRIMARY", "ACTING"]);

export const assignmentStatusSchema = z.enum([
  "ACTIVE",
  "COMPLETED",
  "CANCELLED",
]);

export const organizationalRoleStatusSchema = z.enum([
  "DRAFT",
  "ACTIVE",
  "INACTIVE",
]);

export const vacancyStatusSchema = z.enum([
  "OPEN",
  "RECRUITING_VENTURE",
  "RECRUITING_PLATFORM",
  "RECRUITING_EXTERNAL",
  "AWAITING_DECISION",
  "AUTOMATED_PLACEMENT",
  "OFFER_PENDING",
  "FILLED",
  "UNRESOLVED",
  "CANCELLED",
]);

export const createMembershipSchema = z.object({
  ventureId: uuidSchema,
  userId: uuidSchema,
});

export const membershipIdParamsSchema = z.object({
  membershipId: uuidSchema,
});

export const createRoleSchema = z.object({
  ventureId: uuidSchema,
  parentRoleId: uuidSchema.nullable().optional(),
  title: z.string().trim().min(2).max(150),
  description: z.string().trim().max(5000).nullable().optional(),
  responsibilities: jsonObjectSchema.nullable().optional(),
  authorityScope: jsonObjectSchema.nullable().optional(),
  requirements: jsonObjectSchema.nullable().optional(),
  isMandatory: z.boolean().default(false),
});

export const roleIdParamsSchema = z.object({
  roleId: uuidSchema,
});

export const createAssignmentSchema = z.object({
  membershipId: uuidSchema,
  organizationalRoleId: uuidSchema,
  assignmentType: assignmentTypeSchema,
  startsAt: z.coerce.date().optional(),
});

export const assignmentIdParamsSchema = z.object({
  assignmentId: uuidSchema,
});

export const createVacancySchema = z.object({
  ventureId: uuidSchema,
  organizationalRoleId: uuidSchema,
  previousAssignmentId: uuidSchema.nullable().optional(),
  sourceVacancyId: uuidSchema.nullable().optional(),
  resolutionDeadline: z.coerce.date().nullable().optional(),
});

export const vacancyIdParamsSchema = z.object({
  vacancyId: uuidSchema,
});

export type CreateMembershipInput = z.infer<typeof createMembershipSchema>;

export type CreateRoleInput = z.infer<typeof createRoleSchema>;

export type CreateAssignmentInput = z.infer<typeof createAssignmentSchema>;

export type CreateVacancyInput = z.infer<typeof createVacancySchema>;