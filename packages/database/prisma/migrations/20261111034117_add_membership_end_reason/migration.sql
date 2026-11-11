-- CreateEnum
CREATE TYPE "MembershipEndReason" AS ENUM ('ROLE_NOT_AWARDED', 'APPLICATION_DECLINED', 'WITHDRAWN', 'INVITATION_EXPIRED');

-- AlterTable
ALTER TABLE "venture_memberships" ADD COLUMN     "endReason" "MembershipEndReason";
