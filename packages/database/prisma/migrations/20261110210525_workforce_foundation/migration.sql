-- CreateEnum
CREATE TYPE "MembershipStatus" AS ENUM ('PENDING', 'ACTIVE', 'SUSPENDED', 'ENDED');

-- CreateEnum
CREATE TYPE "OrganizationalRoleStatus" AS ENUM ('DRAFT', 'ACTIVE', 'INACTIVE');

-- CreateEnum
CREATE TYPE "AssignmentType" AS ENUM ('PRIMARY', 'SECONDARY', 'ACTING');

-- CreateEnum
CREATE TYPE "AssignmentStatus" AS ENUM ('ACTIVE', 'COMPLETED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "VacancyStatus" AS ENUM ('OPEN', 'RECRUITING_VENTURE', 'RECRUITING_PLATFORM', 'RECRUITING_EXTERNAL', 'AWAITING_DECISION', 'AUTOMATED_PLACEMENT', 'OFFER_PENDING', 'FILLED', 'UNRESOLVED', 'CANCELLED');

-- CreateTable
CREATE TABLE "venture_memberships" (
    "id" UUID NOT NULL,
    "ventureId" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "status" "MembershipStatus" NOT NULL DEFAULT 'PENDING',
    "joinedAt" TIMESTAMP(3),
    "endedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "venture_memberships_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "organizational_roles" (
    "id" UUID NOT NULL,
    "ventureId" UUID NOT NULL,
    "parentRoleId" UUID,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "responsibilities" JSONB,
    "authorityScope" JSONB,
    "requirements" JSONB,
    "status" "OrganizationalRoleStatus" NOT NULL DEFAULT 'DRAFT',
    "isMandatory" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "organizational_roles_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "role_assignments" (
    "id" UUID NOT NULL,
    "membershipId" UUID NOT NULL,
    "organizationalRoleId" UUID NOT NULL,
    "ventureId" UUID NOT NULL,
    "assignmentType" "AssignmentType" NOT NULL,
    "status" "AssignmentStatus" NOT NULL DEFAULT 'ACTIVE',
    "startsAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "endsAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "role_assignments_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "role_vacancies" (
    "id" UUID NOT NULL,
    "ventureId" UUID NOT NULL,
    "organizationalRoleId" UUID NOT NULL,
    "previousAssignmentId" UUID,
    "sourceVacancyId" UUID,
    "status" "VacancyStatus" NOT NULL DEFAULT 'OPEN',
    "openedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "resolutionDeadline" TIMESTAMP(3),
    "resolvedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "role_vacancies_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "venture_memberships_userId_idx" ON "venture_memberships"("userId");

-- CreateIndex
CREATE INDEX "venture_memberships_ventureId_status_idx" ON "venture_memberships"("ventureId", "status");

-- CreateIndex
CREATE UNIQUE INDEX "venture_memberships_id_ventureId_key" ON "venture_memberships"("id", "ventureId");

-- CreateIndex
CREATE INDEX "organizational_roles_ventureId_status_idx" ON "organizational_roles"("ventureId", "status");

-- CreateIndex
CREATE INDEX "organizational_roles_parentRoleId_idx" ON "organizational_roles"("parentRoleId");

-- CreateIndex
CREATE UNIQUE INDEX "organizational_roles_id_ventureId_key" ON "organizational_roles"("id", "ventureId");

-- CreateIndex
CREATE INDEX "role_assignments_membershipId_status_idx" ON "role_assignments"("membershipId", "status");

-- CreateIndex
CREATE INDEX "role_assignments_organizationalRoleId_status_idx" ON "role_assignments"("organizationalRoleId", "status");

-- CreateIndex
CREATE INDEX "role_assignments_assignmentType_status_idx" ON "role_assignments"("assignmentType", "status");

-- CreateIndex
CREATE UNIQUE INDEX "role_assignments_id_ventureId_key" ON "role_assignments"("id", "ventureId");

-- CreateIndex
CREATE INDEX "role_vacancies_ventureId_status_idx" ON "role_vacancies"("ventureId", "status");

-- CreateIndex
CREATE INDEX "role_vacancies_organizationalRoleId_status_idx" ON "role_vacancies"("organizationalRoleId", "status");

-- CreateIndex
CREATE INDEX "role_vacancies_sourceVacancyId_idx" ON "role_vacancies"("sourceVacancyId");

-- CreateIndex
CREATE UNIQUE INDEX "role_vacancies_id_ventureId_key" ON "role_vacancies"("id", "ventureId");

-- CreateIndex
CREATE UNIQUE INDEX "role_vacancies_previousAssignmentId_ventureId_key" ON "role_vacancies"("previousAssignmentId", "ventureId");

-- AddForeignKey
ALTER TABLE "venture_memberships" ADD CONSTRAINT "venture_memberships_ventureId_fkey" FOREIGN KEY ("ventureId") REFERENCES "ventures"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "venture_memberships" ADD CONSTRAINT "venture_memberships_userId_fkey" FOREIGN KEY ("userId") REFERENCES "platform_users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "organizational_roles" ADD CONSTRAINT "organizational_roles_ventureId_fkey" FOREIGN KEY ("ventureId") REFERENCES "ventures"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "organizational_roles" ADD CONSTRAINT "organizational_roles_parentRoleId_ventureId_fkey" FOREIGN KEY ("parentRoleId", "ventureId") REFERENCES "organizational_roles"("id", "ventureId") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "role_assignments" ADD CONSTRAINT "role_assignments_membershipId_ventureId_fkey" FOREIGN KEY ("membershipId", "ventureId") REFERENCES "venture_memberships"("id", "ventureId") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "role_assignments" ADD CONSTRAINT "role_assignments_organizationalRoleId_ventureId_fkey" FOREIGN KEY ("organizationalRoleId", "ventureId") REFERENCES "organizational_roles"("id", "ventureId") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "role_vacancies" ADD CONSTRAINT "role_vacancies_ventureId_fkey" FOREIGN KEY ("ventureId") REFERENCES "ventures"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "role_vacancies" ADD CONSTRAINT "role_vacancies_organizationalRoleId_ventureId_fkey" FOREIGN KEY ("organizationalRoleId", "ventureId") REFERENCES "organizational_roles"("id", "ventureId") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "role_vacancies" ADD CONSTRAINT "role_vacancies_previousAssignmentId_ventureId_fkey" FOREIGN KEY ("previousAssignmentId", "ventureId") REFERENCES "role_assignments"("id", "ventureId") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "role_vacancies" ADD CONSTRAINT "role_vacancies_sourceVacancyId_ventureId_fkey" FOREIGN KEY ("sourceVacancyId", "ventureId") REFERENCES "role_vacancies"("id", "ventureId") ON DELETE RESTRICT ON UPDATE CASCADE;

-- Prevent a membership from having multiple active primary roles.
CREATE UNIQUE INDEX "role_assignments_one_active_primary_per_membership_key"
ON "role_assignments" ("membershipId")
WHERE "status" = 'ACTIVE'
  AND "assignmentType" = 'PRIMARY';

-- Prevent multiple unresolved vacancies for the same role.
CREATE UNIQUE INDEX "role_vacancies_one_unresolved_per_role_key"
ON "role_vacancies" ("ventureId", "organizationalRoleId")
WHERE "status" IN (
  'OPEN',
  'RECRUITING_VENTURE',
  'RECRUITING_PLATFORM',
  'RECRUITING_EXTERNAL',
  'AWAITING_DECISION',
  'AUTOMATED_PLACEMENT',
  'OFFER_PENDING'
);