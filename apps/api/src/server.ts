import Fastify from "fastify";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import sensible from "@fastify/sensible";
import swagger from "@fastify/swagger";
import swaggerUI from "@fastify/swagger-ui";

import { prisma } from "@platform/database";

import { Queue } from "bullmq";

const app = Fastify({
  logger: true,
});

const redisUrl = new URL(
  process.env.REDIS_URL ?? "redis://localhost:6380"
);

const jobQueue = new Queue("platform-jobs", {
  connection: {
    host: redisUrl.hostname,
    port: Number(redisUrl.port || 6379),
    username: redisUrl.username || undefined,
    password: redisUrl.password || undefined,
  },
});

await app.register(cors, {
  origin: process.env.WEB_ORIGIN ?? "http://localhost:5173",
});

await app.register(helmet);
await app.register(rateLimit, {
  max: 100,
  timeWindow: "1 minute",
});
await app.register(sensible);

await app.register(swagger, {
  openapi: {
    info: {
      title: "Distributed Business Platform API",
      description: "Platform API documentation",
      version: "0.1.0",
    },
  },
});

await app.register(swaggerUI, {
  routePrefix: "/documentation",
});

app.get("/api/v1/health", async (_request, reply) => {
  try {
    await prisma.$queryRaw`SELECT 1`;

    return {
      status: "ok",
      service: "distributed-business-platform-api",
      database: "connected",
      version: "0.1.0",
    };
  } catch (error) {
    app.log.error(error, "Database health check failed");

    return reply.code(503).send({
      status: "error",
      service: "distributed-business-platform-api",
      database: "unavailable",
      version: "0.1.0",
    });
  }
});

app.post("/api/v1/jobs/health-check", async (_request, reply) => {
  try {
    const job = await jobQueue.add("health-check", {
      requestedAt: new Date().toISOString(),
    });

    return reply.code(202).send({
      status: "queued",
      jobId: job.id,
      queue: "platform-jobs",
    });
  } catch (error) {
    app.log.error(error, "Failed to enqueue health-check job");

    return reply.code(503).send({
      status: "error",
      message: "Could not enqueue job",
    });
  }
});

const start = async () => {
  try {
    const port = Number(process.env.API_PORT ?? 3001);
    const host = process.env.API_HOST ?? "0.0.0.0";

    await app.listen({ port, host });
  } catch (error) {
    app.log.error(error);
    process.exit(1);
  }
};

const shutdown = async () => {
  await app.close();
  await jobQueue.close();
  await prisma.$disconnect();
  process.exit(0);
};

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

await start();
