
-- Remove the unapproved SECONDARY assignment type.
-- Preserve the assignment table and its integrity constraints.

-- Temporarily remove the partial index that references AssignmentType.
DROP INDEX "role_assignments_one_active_primary_per_membership_key";

-- Create the replacement enum.
CREATE TYPE "AssignmentType_new" AS ENUM ('PRIMARY', 'ACTING');

-- Convert the assignment column.
ALTER TABLE "role_assignments"
  ALTER COLUMN "assignmentType"
  TYPE "AssignmentType_new"
  USING ("assignmentType"::text::"AssignmentType_new");

-- Replace the original enum.
DROP TYPE "AssignmentType";

ALTER TYPE "AssignmentType_new" RENAME TO "AssignmentType";

-- Restore the one-active-primary-per-membership protection.
CREATE UNIQUE INDEX "role_assignments_one_active_primary_per_membership_key"
ON "role_assignments" ("membershipId")
WHERE "status" = 'ACTIVE'
  AND "assignmentType" = 'PRIMARY';
