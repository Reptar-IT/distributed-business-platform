import dotenv from "dotenv";
import { defineConfig } from "prisma/config";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const configDirectory = dirname(fileURLToPath(import.meta.url));
const rootEnvPath = resolve(configDirectory, "../../.env");

const envResult = dotenv.config({
  path: rootEnvPath,
});

if (envResult.error) {
  throw new Error(`Could not load environment file: ${rootEnvPath}`);
}

const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
  throw new Error("DATABASE_URL is missing from the root .env file");
}

export default defineConfig({
  schema: resolve(configDirectory, "prisma/schema.prisma"),
  migrations: {
    path: resolve(configDirectory, "prisma/migrations"),
  },
  datasource: {
    url: databaseUrl,
  },
});