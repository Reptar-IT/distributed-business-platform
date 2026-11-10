import { prisma } from "./client.js";

try {
  await prisma.$connect();

  const result = await prisma.$queryRaw<
    Array<{ current_database: string; current_user: string }>
  >`
    SELECT current_database(), current_user
  `;

  console.log("Database connection successful:");
  console.log(result[0]);
} catch (error) {
  console.error("Database connection failed:", error);
  process.exitCode = 1;
} finally {
  await prisma.$disconnect();
}