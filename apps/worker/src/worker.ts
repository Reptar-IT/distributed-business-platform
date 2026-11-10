import { Worker, type Job } from "bullmq";
import IORedis from "ioredis";

const redisUrl = process.env.REDIS_URL ?? "redis://localhost:6380";

const connection = new IORedis(redisUrl, {
  maxRetriesPerRequest: null,
});

const worker = new Worker(
  "platform-jobs",
  async (job: Job) => {
    console.log(`Processing job: ${job.name}`, job.id);

    switch (job.name) {
      case "health-check":
        return {
          status: "processed",
          jobId: job.id,
          processedAt: new Date().toISOString(),
        };

      default:
        throw new Error(`Unsupported job type: ${job.name}`);
    }
  },
  { connection },
);

worker.on("completed", (job) => {
  console.log(`Job completed: ${job.id}`);
});

worker.on("failed", (job, error) => {
  console.error(`Job failed: ${job?.id}`, error);
});

worker.on("error", (error) => {
  console.error("Worker error:", error);
});

const shutdown = async () => {
  console.log("Shutting down worker...");
  await worker.close();
  await connection.quit();
  process.exit(0);
};

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

console.log("Platform worker started.");
console.log(`Redis: ${redisUrl}`);
