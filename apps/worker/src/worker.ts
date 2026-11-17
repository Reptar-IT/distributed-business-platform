import { Worker, type Job } from "bullmq";
import {Redis} from "ioredis";

import { prisma } from "@platform/database";
import { createAuditExporter } from "./modules/audit-exporter.js";
import { createCriticalOperationWorker } from "./modules/critical-operations.js";

const redisUrl = process.env.REDIS_URL ?? "redis://localhost:6380";

const connection = new Redis(redisUrl, {
  maxRetriesPerRequest: null,
});

const auditExporterDatabaseUrl = process.env.AUDIT_EXPORTER_DATABASE_URL;
const auditReceiptVerifierUrl = process.env.AUDIT_RECEIPT_VERIFIER_URL;
const auditReceiptVerifierServiceToken = process.env.AUDIT_RECEIPT_VERIFIER_SERVICE_TOKEN;
const criticalOperationDatabaseUrl = process.env.CRITICAL_OPERATION_DATABASE_URL;
const criticalOperationEnabled = process.env.CRITICAL_OPERATION_ENGINE_ENABLED === "true";
if (criticalOperationEnabled && !["development", "test"].includes(process.env.NODE_ENV ?? "")) {
  throw new Error("Critical-operation enforcement is restricted to development/test until independent production archive deployments and failure domains are verified");
}
if (criticalOperationEnabled && !criticalOperationDatabaseUrl) {
  throw new Error("CRITICAL_OPERATION_DATABASE_URL is required when the critical-operation engine is enabled");
}
const criticalOperationWorker = criticalOperationEnabled && criticalOperationDatabaseUrl
  ? createCriticalOperationWorker(criticalOperationDatabaseUrl)
  : undefined;
if (criticalOperationWorker) criticalOperationWorker.start();
let auditExporter: ReturnType<typeof createAuditExporter> | undefined;
let auditExportTimer: NodeJS.Timeout | undefined;
const lastAuditHealthReport = new Map<string, { state: string; at: number }>();
const auditHealthReportIntervalMs = 5 * 60 * 1000;

if (auditExporterDatabaseUrl && auditReceiptVerifierUrl && auditReceiptVerifierServiceToken) {
  const destinations = [];
  for (const destination of [
    {
      id: "physical" as const,
      prefix: "AUDIT_PHYSICAL_ARCHIVE",
    },
    {
      id: "hosted" as const,
      prefix: "AUDIT_HOSTED_ARCHIVE",
    },
  ]) {
    const url = process.env[`${destination.prefix}_URL`];
    const ingestToken = process.env[`${destination.prefix}_INGEST_TOKEN`];
    if (url && ingestToken) {
      destinations.push({ id: destination.id, url, ingestToken });
    } else {
      console.error(`Audit archive destination is not configured: ${destination.id}`);
    }
  }
  auditExporter = createAuditExporter({
    exporterDatabaseUrl: auditExporterDatabaseUrl,
    receiptVerifierUrl: auditReceiptVerifierUrl,
    receiptVerifierServiceToken: auditReceiptVerifierServiceToken,
    destinations,
  });
  const runAuditExport = async () => {
    try {
      const report = await auditExporter?.runOnce();
      if (!report) return;
      const now = Date.now();
      report.destinations.forEach((health) => {
        const degraded = health.consecutiveFailures > 0;
        const state = degraded ? `degraded:${health.lastErrorCategory ?? "UNKNOWN"}` : "healthy";
        const previous = lastAuditHealthReport.get(health.destinationId);
        if (!previous || previous.state !== state || now - previous.at >= auditHealthReportIntervalMs) {
          const entry = {
            service: "audit-exporter",
            destinationId: health.destinationId,
            state: degraded ? "degraded" : "healthy",
            lastSucceededAt: health.lastSucceededAt,
            consecutiveFailures: health.consecutiveFailures,
            lastErrorCategory: health.lastErrorCategory,
          };
          if (degraded) console.error(JSON.stringify(entry));
          else console.info(JSON.stringify(entry));
          lastAuditHealthReport.set(health.destinationId, { state, at: now });
        }
      });
      report.retryMetadataFailures.forEach((destinationId) => {
        const key = `retry-metadata:${destinationId}`;
        const previous = lastAuditHealthReport.get(key);
        if (!previous || now - previous.at >= auditHealthReportIntervalMs) {
          console.error(JSON.stringify({ service: "audit-exporter", destinationId, state: "retry-metadata-persistence-failed" }));
          lastAuditHealthReport.set(key, { state: "retry-metadata-persistence-failed", at: now });
        }
      });
      report.processingFailures.forEach((destinationId) => {
        const key = `processing:${destinationId}`;
        const previous = lastAuditHealthReport.get(key);
        if (!previous || now - previous.at >= auditHealthReportIntervalMs) {
          console.error(JSON.stringify({ service: "audit-exporter", destinationId, state: "delivery-processing-failed", errorCategory: "DESTINATION_PROCESSING_FAILED" }));
          lastAuditHealthReport.set(key, { state: "delivery-processing-failed", at: now });
        }
      });
    } catch {
      const now = Date.now();
      const previous = lastAuditHealthReport.get("polling");
      if (!previous || now - previous.at >= auditHealthReportIntervalMs) {
        console.error(JSON.stringify({ service: "audit-exporter", state: "polling-failed", errorCategory: "EXPORT_POLL_FAILED" }));
        lastAuditHealthReport.set("polling", { state: "polling-failed", at: now });
      }
    }
  };
  await runAuditExport();
  auditExportTimer = setInterval(() => { void runAuditExport(); }, 2_000);
}

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

  if (auditExportTimer) clearInterval(auditExportTimer);
  await auditExporter?.close();
  await criticalOperationWorker?.close();

  await worker.close();
  await connection.quit();
  await prisma.$disconnect();

  process.exit(0);
};

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

console.log("Platform worker started.");
console.log(`Redis: ${redisUrl}`);
