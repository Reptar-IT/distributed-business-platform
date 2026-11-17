-- Stage 1 authorization audit foundation. Requires PostgreSQL 17 and pre-provisioned roles.
-- Login roles and passwords are managed outside migrations; see infrastructure/database/.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$
BEGIN
  IF current_setting('server_version_num')::integer < 170000
     OR current_setting('server_version_num')::integer >= 180000 THEN
    RAISE EXCEPTION 'Audit serialization v1 requires PostgreSQL major version 17';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_audit_append_owner')
     OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_runtime')
     OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_audit_exporter')
     OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_audit_receipt_verifier')
     OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_audit_receipt_owner')
     OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_migrator') THEN
    RAISE EXCEPTION 'Provision DBP database roles before applying this migration';
  END IF;
END $$;

CREATE TYPE "AuthorizationAuditActorType" AS ENUM ('HUMAN', 'MACHINE', 'SYSTEM', 'BOOTSTRAP');
CREATE TYPE "AuthorizationAuditDecision" AS ENUM ('ALLOW', 'DENY', 'NOT_APPLICABLE');
CREATE TYPE "AuditExportStatus" AS ENUM ('PENDING', 'ACKNOWLEDGED');
CREATE TYPE "AuditDestinationType" AS ENUM ('PHYSICAL', 'HOSTED');

CREATE TABLE "authorization_audit_streams" (
  "id" UUID NOT NULL,
  "name" TEXT NOT NULL,
  "createdAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "authorization_audit_streams_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "authorization_audit_streams_name_key" UNIQUE ("name")
);

CREATE TABLE "authorization_audit_heads" (
  "streamId" UUID NOT NULL,
  "lastSequence" BIGINT NOT NULL DEFAULT 0,
  "lastEventHash" BYTEA NOT NULL,
  "updatedAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "authorization_audit_heads_pkey" PRIMARY KEY ("streamId"),
  CONSTRAINT "authorization_audit_heads_sequence_check" CHECK ("lastSequence" >= 0),
  CONSTRAINT "authorization_audit_heads_hash_length_check" CHECK (octet_length("lastEventHash") = 32),
  CONSTRAINT "authorization_audit_heads_streamId_fkey" FOREIGN KEY ("streamId")
    REFERENCES "authorization_audit_streams"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE TABLE "authorization_audit_events" (
  "id" UUID NOT NULL,
  "streamId" UUID NOT NULL,
  "sequence" BIGINT NOT NULL,
  "eventType" VARCHAR(100) NOT NULL,
  "actorType" "AuthorizationAuditActorType" NOT NULL,
  "actorId" VARCHAR(200) NOT NULL,
  "delegatingHumanId" VARCHAR(200),
  "callingClientId" VARCHAR(200),
  "permissionCode" VARCHAR(200),
  "decision" "AuthorizationAuditDecision" NOT NULL DEFAULT 'NOT_APPLICABLE',
  "decisionReasonCode" VARCHAR(100),
  "targetType" VARCHAR(100),
  "targetId" VARCHAR(200),
  "ventureId" UUID,
  "delegationId" UUID,
  "approvalId" UUID,
  "policyVersion" VARCHAR(100),
  "operation" VARCHAR(100) NOT NULL,
  "outcome" VARCHAR(100) NOT NULL,
  "requestId" VARCHAR(200),
  "jobId" VARCHAR(200),
  "correlationId" VARCHAR(200),
  "occurredAt" TIMESTAMPTZ(6) NOT NULL,
  "serializationVersion" INTEGER NOT NULL DEFAULT 1,
  "hashVersion" INTEGER NOT NULL DEFAULT 1,
  "canonicalPayload" TEXT NOT NULL,
  "previousHash" BYTEA NOT NULL,
  "eventHash" BYTEA NOT NULL,
  CONSTRAINT "authorization_audit_events_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "authorization_audit_events_streamId_sequence_key" UNIQUE ("streamId", "sequence"),
  CONSTRAINT "authorization_audit_events_sequence_check" CHECK ("sequence" > 0),
  CONSTRAINT "authorization_audit_events_versions_check" CHECK ("serializationVersion" = 1 AND "hashVersion" = 1),
  CONSTRAINT "authorization_audit_events_hash_length_check" CHECK (octet_length("previousHash") = 32 AND octet_length("eventHash") = 32),
  CONSTRAINT "authorization_audit_events_streamId_fkey" FOREIGN KEY ("streamId")
    REFERENCES "authorization_audit_streams"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE INDEX "authorization_audit_events_actorType_actorId_occurredAt_idx" ON "authorization_audit_events" ("actorType", "actorId", "occurredAt");
CREATE INDEX "authorization_audit_events_targetType_targetId_occurredAt_idx" ON "authorization_audit_events" ("targetType", "targetId", "occurredAt");
CREATE INDEX "authorization_audit_events_correlationId_idx" ON "authorization_audit_events" ("correlationId");
CREATE INDEX "authorization_audit_events_ventureId_occurredAt_idx" ON "authorization_audit_events" ("ventureId", "occurredAt");

CREATE TABLE "audit_destinations" (
  "id" VARCHAR(80) NOT NULL,
  "type" "AuditDestinationType" NOT NULL,
  "enabled" BOOLEAN NOT NULL DEFAULT TRUE,
  "createdAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "audit_destinations_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "audit_export_checkpoints" (
  "streamId" UUID NOT NULL,
  "destinationId" VARCHAR(80) NOT NULL,
  "lastAcknowledgedSequence" BIGINT NOT NULL DEFAULT 0,
  "lastAcknowledgedEventHash" BYTEA NOT NULL,
  "updatedAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "audit_export_checkpoints_pkey" PRIMARY KEY ("streamId", "destinationId"),
  CONSTRAINT "audit_export_checkpoints_sequence_check" CHECK ("lastAcknowledgedSequence" >= 0),
  CONSTRAINT "audit_export_checkpoints_hash_length_check" CHECK (octet_length("lastAcknowledgedEventHash") = 32),
  CONSTRAINT "audit_export_checkpoints_streamId_fkey" FOREIGN KEY ("streamId")
    REFERENCES "authorization_audit_streams"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT "audit_export_checkpoints_destinationId_fkey" FOREIGN KEY ("destinationId")
    REFERENCES "audit_destinations"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE TABLE "audit_export_batches" (
  "id" UUID NOT NULL,
  "streamId" UUID NOT NULL,
  "firstSequence" BIGINT NOT NULL,
  "lastSequence" BIGINT NOT NULL,
  "eventCount" INTEGER NOT NULL,
  "previousHash" BYTEA NOT NULL,
  "terminalEventHash" BYTEA NOT NULL,
  "batchHash" BYTEA NOT NULL,
  "canonicalBatch" TEXT NOT NULL,
  "createdAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "audit_export_batches_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "audit_export_batches_streamId_firstSequence_key" UNIQUE ("streamId", "firstSequence"),
  CONSTRAINT "audit_export_batches_range_check" CHECK ("firstSequence" > 0 AND "lastSequence" >= "firstSequence" AND "eventCount" = "lastSequence" - "firstSequence" + 1),
  CONSTRAINT "audit_export_batches_hash_length_check" CHECK (octet_length("previousHash") = 32 AND octet_length("terminalEventHash") = 32 AND octet_length("batchHash") = 32),
  CONSTRAINT "audit_export_batches_streamId_fkey" FOREIGN KEY ("streamId")
    REFERENCES "authorization_audit_streams"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE TABLE "audit_export_deliveries" (
  "batchId" UUID NOT NULL,
  "destinationId" VARCHAR(80) NOT NULL,
  "status" "AuditExportStatus" NOT NULL DEFAULT 'PENDING',
  "attempts" INTEGER NOT NULL DEFAULT 0,
  "nextAttemptAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "lastErrorCode" VARCHAR(100),
  "createdAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "audit_export_deliveries_pkey" PRIMARY KEY ("batchId", "destinationId"),
  CONSTRAINT "audit_export_deliveries_attempts_check" CHECK ("attempts" >= 0),
  CONSTRAINT "audit_export_deliveries_batchId_fkey" FOREIGN KEY ("batchId")
    REFERENCES "audit_export_batches"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT "audit_export_deliveries_destinationId_fkey" FOREIGN KEY ("destinationId")
    REFERENCES "audit_destinations"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE INDEX "audit_export_deliveries_destinationId_status_nextAttemptAt_idx" ON "audit_export_deliveries" ("destinationId", "status", "nextAttemptAt");

CREATE TABLE "audit_archive_receipts" (
  "id" UUID NOT NULL,
  "batchId" UUID NOT NULL,
  "destinationId" VARCHAR(80) NOT NULL,
  "batchHash" BYTEA NOT NULL,
  "firstSequence" BIGINT NOT NULL,
  "lastSequence" BIGINT NOT NULL,
  "terminalEventHash" BYTEA NOT NULL,
  "acceptedAt" TIMESTAMPTZ(6) NOT NULL,
  "keyId" VARCHAR(100) NOT NULL,
  "receiptPayload" TEXT NOT NULL,
  "signature" BYTEA NOT NULL,
  "verifiedAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "audit_archive_receipts_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "audit_archive_receipts_batchId_destinationId_key" UNIQUE ("batchId", "destinationId"),
  CONSTRAINT "audit_archive_receipts_range_check" CHECK ("firstSequence" > 0 AND "lastSequence" >= "firstSequence"),
  CONSTRAINT "audit_archive_receipts_hash_length_check" CHECK (octet_length("batchHash") = 32 AND octet_length("terminalEventHash") = 32),
  CONSTRAINT "audit_archive_receipts_batchId_destinationId_fkey" FOREIGN KEY ("batchId", "destinationId")
    REFERENCES "audit_export_deliveries"("batchId", "destinationId") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE INDEX "audit_archive_receipts_destinationId_acceptedAt_idx" ON "audit_archive_receipts" ("destinationId", "acceptedAt");

-- Stable identifiers make initial checkpoints reproducible across installation runs.
INSERT INTO "authorization_audit_streams" ("id", "name")
VALUES ('00000000-0000-0000-0000-000000000001', 'authorization');
INSERT INTO "authorization_audit_heads" ("streamId", "lastSequence", "lastEventHash")
VALUES ('00000000-0000-0000-0000-000000000001', 0, decode(repeat('00', 32), 'hex'));
INSERT INTO "audit_destinations" ("id", "type") VALUES ('physical', 'PHYSICAL'), ('hosted', 'HOSTED');
INSERT INTO "audit_export_checkpoints" ("streamId", "destinationId", "lastAcknowledgedSequence", "lastAcknowledgedEventHash")
SELECT '00000000-0000-0000-0000-000000000001', "id", 0, decode(repeat('00', 32), 'hex') FROM "audit_destinations";

CREATE FUNCTION public.reject_authorization_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  RAISE EXCEPTION 'Authorization audit events are append-only';
END;
$$;

CREATE TRIGGER "authorization_audit_events_immutable"
BEFORE UPDATE OR DELETE ON "authorization_audit_events"
FOR EACH ROW EXECUTE FUNCTION public.reject_authorization_audit_mutation();

CREATE TRIGGER "audit_archive_receipts_immutable"
BEFORE UPDATE OR DELETE ON "audit_archive_receipts"
FOR EACH ROW EXECUTE FUNCTION public.reject_authorization_audit_mutation();

CREATE FUNCTION public.guard_audit_delivery_status()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP = 'INSERT' AND NEW."status" <> 'PENDING' THEN
    RAISE EXCEPTION 'Audit delivery must start pending';
  END IF;
  IF TG_OP = 'UPDATE' AND NEW."status" IS DISTINCT FROM OLD."status"
     AND current_user <> 'dbp_audit_receipt_owner' THEN
    RAISE EXCEPTION 'Only verified receipt recording can acknowledge a delivery';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "audit_delivery_status_guard"
BEFORE INSERT OR UPDATE OF "status" ON "audit_export_deliveries"
FOR EACH ROW EXECUTE FUNCTION public.guard_audit_delivery_status();

CREATE FUNCTION public.append_authorization_audit(p_event JSONB, p_stream_id UUID DEFAULT '00000000-0000-0000-0000-000000000001')
RETURNS TABLE("eventId" UUID, "sequence" BIGINT, "canonicalPayload" TEXT, "eventHash" BYTEA)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_allowed_keys TEXT[] := ARRAY[
    'eventType', 'actorType', 'actorId', 'delegatingHumanId', 'callingClientId',
    'permissionCode', 'decision', 'decisionReasonCode', 'targetType', 'targetId',
    'ventureId', 'delegationId', 'approvalId', 'policyVersion', 'operation',
    'outcome', 'requestId', 'jobId', 'correlationId'
  ];
  v_key TEXT;
  v_occurred_at TIMESTAMPTZ(6) := clock_timestamp();
  v_payload JSONB;
  v_payload_text TEXT;
  v_payload_bytes BYTEA;
  v_previous_hash BYTEA;
  v_event_hash BYTEA;
  v_sequence BIGINT;
  v_event_id UUID := pg_catalog.gen_random_uuid();
BEGIN
  IF current_setting('server_version_num')::integer < 170000
     OR current_setting('server_version_num')::integer >= 180000 THEN
    RAISE EXCEPTION 'Audit serialization v1 requires PostgreSQL major version 17';
  END IF;
  IF jsonb_typeof(p_event) <> 'object' THEN
    RAISE EXCEPTION 'Audit event must be a JSON object';
  END IF;
  FOR v_key IN SELECT jsonb_object_keys(p_event) LOOP
    IF NOT (v_key = ANY(v_allowed_keys)) THEN
      RAISE EXCEPTION 'Unsupported audit event field: %', v_key;
    END IF;
    IF jsonb_typeof(p_event -> v_key) NOT IN ('string', 'null') THEN
      RAISE EXCEPTION 'Audit field must be a string or null: %', v_key;
    END IF;
  END LOOP;
  IF NULLIF(p_event ->> 'eventType', '') IS NULL
     OR NULLIF(p_event ->> 'actorType', '') IS NULL
     OR NULLIF(p_event ->> 'actorId', '') IS NULL
     OR NULLIF(p_event ->> 'operation', '') IS NULL
     OR NULLIF(p_event ->> 'outcome', '') IS NULL THEN
    RAISE EXCEPTION 'Audit event requires eventType, actorType, actorId, operation, and outcome';
  END IF;
  IF length(p_event ->> 'eventType') > 100 OR length(p_event ->> 'actorId') > 200
     OR length(p_event ->> 'operation') > 100 OR length(p_event ->> 'outcome') > 100 THEN
    RAISE EXCEPTION 'Audit event field exceeds its maximum length';
  END IF;

  -- All fields are present, including nulls. PostgreSQL 17 jsonb text output is
  -- the version-pinned canonical JSON UTF-8 representation for serialization v1.
  v_payload := jsonb_build_object(
    'eventType', p_event ->> 'eventType',
    'actorType', p_event ->> 'actorType',
    'actorId', p_event ->> 'actorId',
    'delegatingHumanId', p_event ->> 'delegatingHumanId',
    'callingClientId', p_event ->> 'callingClientId',
    'permissionCode', p_event ->> 'permissionCode',
    'decision', COALESCE(p_event ->> 'decision', 'NOT_APPLICABLE'),
    'decisionReasonCode', p_event ->> 'decisionReasonCode',
    'targetType', p_event ->> 'targetType',
    'targetId', p_event ->> 'targetId',
    'ventureId', p_event ->> 'ventureId',
    'delegationId', p_event ->> 'delegationId',
    'approvalId', p_event ->> 'approvalId',
    'policyVersion', p_event ->> 'policyVersion',
    'operation', p_event ->> 'operation',
    'outcome', p_event ->> 'outcome',
    'requestId', p_event ->> 'requestId',
    'jobId', p_event ->> 'jobId',
    'correlationId', p_event ->> 'correlationId',
    'occurredAt', to_char(v_occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
  );
  v_payload_text := v_payload::text;
  v_payload_bytes := convert_to(v_payload_text, 'UTF8');

  SELECT h."lastSequence" + 1, h."lastEventHash"
    INTO v_sequence, v_previous_hash
    FROM public.authorization_audit_heads h
   WHERE h."streamId" = p_stream_id
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Unknown audit stream';
  END IF;

  v_event_hash := public.digest(
    decode('4442502d415554485a2d4556454e5400', 'hex') ||
    pg_catalog.int2send(1::smallint) ||
    pg_catalog.uuid_send(p_stream_id) ||
    pg_catalog.int8send(v_sequence) ||
    v_previous_hash ||
    pg_catalog.int8send(octet_length(v_payload_bytes)::bigint) ||
    v_payload_bytes,
    'sha256'
  );

  INSERT INTO public.authorization_audit_events (
    "id", "streamId", "sequence", "eventType", "actorType", "actorId",
    "delegatingHumanId", "callingClientId", "permissionCode", "decision",
    "decisionReasonCode", "targetType", "targetId", "ventureId", "delegationId",
    "approvalId", "policyVersion", "operation", "outcome", "requestId", "jobId",
    "correlationId", "occurredAt", "serializationVersion", "hashVersion",
    "canonicalPayload", "previousHash", "eventHash"
  ) VALUES (
    v_event_id, p_stream_id, v_sequence, v_payload ->> 'eventType',
    (v_payload ->> 'actorType')::"AuthorizationAuditActorType", v_payload ->> 'actorId',
    v_payload ->> 'delegatingHumanId', v_payload ->> 'callingClientId',
    v_payload ->> 'permissionCode', (v_payload ->> 'decision')::"AuthorizationAuditDecision",
    v_payload ->> 'decisionReasonCode', v_payload ->> 'targetType', v_payload ->> 'targetId',
    NULLIF(v_payload ->> 'ventureId', '')::uuid, NULLIF(v_payload ->> 'delegationId', '')::uuid,
    NULLIF(v_payload ->> 'approvalId', '')::uuid, v_payload ->> 'policyVersion',
    v_payload ->> 'operation', v_payload ->> 'outcome', v_payload ->> 'requestId',
    v_payload ->> 'jobId', v_payload ->> 'correlationId', v_occurred_at, 1, 1,
    v_payload_text, v_previous_hash, v_event_hash
  );

  UPDATE public.authorization_audit_heads
     SET "lastSequence" = v_sequence, "lastEventHash" = v_event_hash, "updatedAt" = v_occurred_at
   WHERE "streamId" = p_stream_id;

  RETURN QUERY SELECT v_event_id, v_sequence, v_payload_text, v_event_hash;
END;
$$;

ALTER FUNCTION public.append_authorization_audit(JSONB, UUID) OWNER TO dbp_audit_append_owner;
REVOKE ALL ON FUNCTION public.append_authorization_audit(JSONB, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.append_authorization_audit(JSONB, UUID) TO dbp_runtime;

CREATE FUNCTION public.record_verified_audit_receipt(
  p_batch_id UUID,
  p_destination_id TEXT,
  p_receipt_payload TEXT,
  p_signature BYTEA
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_batch public.audit_export_batches%ROWTYPE;
  v_delivery public.audit_export_deliveries%ROWTYPE;
  v_checkpoint public.audit_export_checkpoints%ROWTYPE;
  v_receipt JSONB;
  v_accepted_at TIMESTAMPTZ(6);
  v_key_id TEXT;
BEGIN
  IF octet_length(p_signature) <> 64 THEN
    RAISE EXCEPTION 'Invalid Ed25519 signature size';
  END IF;
  v_receipt := p_receipt_payload::jsonb;
  -- Batch rows are immutable to verifier/exporter roles, so no row lock is
  -- needed here (and the function owner deliberately has no batch UPDATE grant).
  SELECT * INTO v_batch FROM public.audit_export_batches WHERE "id" = p_batch_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'Unknown audit batch'; END IF;
  SELECT * INTO v_delivery FROM public.audit_export_deliveries
   WHERE "batchId" = p_batch_id AND "destinationId" = p_destination_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Unknown destination delivery'; END IF;
  SELECT * INTO v_checkpoint FROM public.audit_export_checkpoints
   WHERE "streamId" = v_batch."streamId" AND "destinationId" = p_destination_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Unknown destination checkpoint'; END IF;

  IF v_delivery."status" = 'ACKNOWLEDGED' THEN
    IF EXISTS (
      SELECT 1 FROM public.audit_archive_receipts r
       WHERE r."batchId" = p_batch_id AND r."destinationId" = p_destination_id
         AND r."receiptPayload" = p_receipt_payload AND r."signature" = p_signature
    ) THEN RETURN; END IF;
    RAISE EXCEPTION 'Conflicting receipt for acknowledged delivery';
  END IF;

  IF (v_receipt ->> 'version') IS DISTINCT FROM '1'
     OR (v_receipt ->> 'destinationId') IS DISTINCT FROM p_destination_id
     OR (v_receipt ->> 'batchHash') IS DISTINCT FROM encode(v_batch."batchHash", 'hex')
     OR (v_receipt ->> 'firstSequence') IS DISTINCT FROM v_batch."firstSequence"::text
     OR (v_receipt ->> 'lastSequence') IS DISTINCT FROM v_batch."lastSequence"::text
     OR (v_receipt ->> 'terminalEventHash') IS DISTINCT FROM encode(v_batch."terminalEventHash", 'hex')
     OR (v_receipt ->> 'keyId') IS NULL THEN
    RAISE EXCEPTION 'Archive receipt does not match stored batch';
  END IF;
  IF v_batch."firstSequence" <> v_checkpoint."lastAcknowledgedSequence" + 1
     OR v_batch."previousHash" <> v_checkpoint."lastAcknowledgedEventHash" THEN
    RAISE EXCEPTION 'Archive receipt would advance a non-contiguous checkpoint';
  END IF;

  v_accepted_at := (v_receipt ->> 'acceptedAt')::timestamptz;
  v_key_id := v_receipt ->> 'keyId';
  INSERT INTO public.audit_archive_receipts (
    "id", "batchId", "destinationId", "batchHash", "firstSequence", "lastSequence",
    "terminalEventHash", "acceptedAt", "keyId", "receiptPayload", "signature", "verifiedAt"
  ) VALUES (
    pg_catalog.gen_random_uuid(), p_batch_id, p_destination_id, v_batch."batchHash",
    v_batch."firstSequence", v_batch."lastSequence", v_batch."terminalEventHash",
    v_accepted_at, v_key_id, p_receipt_payload, p_signature, clock_timestamp()
  );
  UPDATE public.audit_export_checkpoints
     SET "lastAcknowledgedSequence" = v_batch."lastSequence",
         "lastAcknowledgedEventHash" = v_batch."terminalEventHash",
         "updatedAt" = clock_timestamp()
   WHERE "streamId" = v_batch."streamId" AND "destinationId" = p_destination_id;
  UPDATE public.audit_export_deliveries
     SET "status" = 'ACKNOWLEDGED', "updatedAt" = clock_timestamp()
   WHERE "batchId" = p_batch_id AND "destinationId" = p_destination_id;
END;
$$;

ALTER FUNCTION public.record_verified_audit_receipt(UUID, TEXT, TEXT, BYTEA) OWNER TO dbp_audit_receipt_owner;
REVOKE ALL ON FUNCTION public.record_verified_audit_receipt(UUID, TEXT, TEXT, BYTEA) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.record_verified_audit_receipt(UUID, TEXT, TEXT, BYTEA) TO dbp_audit_receipt_verifier;

REVOKE ALL ON public.authorization_audit_events, public.authorization_audit_heads FROM PUBLIC, dbp_runtime, dbp_audit_exporter;
GRANT SELECT ON public.authorization_audit_streams, public.authorization_audit_events, public.audit_destinations TO dbp_audit_exporter;
GRANT SELECT, INSERT ON public.audit_export_batches, public.audit_export_deliveries TO dbp_audit_exporter;
GRANT UPDATE ("attempts", "nextAttemptAt", "lastErrorCode", "updatedAt") ON public.audit_export_deliveries TO dbp_audit_exporter;
GRANT SELECT ON public.audit_export_checkpoints TO dbp_audit_exporter;
GRANT SELECT ON public.audit_export_batches, public.audit_export_deliveries, public.audit_destinations TO dbp_audit_receipt_verifier;
GRANT SELECT ON public.audit_export_checkpoints TO dbp_audit_receipt_verifier;
GRANT SELECT ON public.audit_export_batches, public.audit_export_deliveries, public.audit_export_checkpoints TO dbp_audit_receipt_owner;
GRANT INSERT ON public.audit_archive_receipts TO dbp_audit_receipt_owner;
GRANT UPDATE ("lastAcknowledgedSequence", "lastAcknowledgedEventHash", "updatedAt") ON public.audit_export_checkpoints TO dbp_audit_receipt_owner;
GRANT UPDATE ("status", "updatedAt") ON public.audit_export_deliveries TO dbp_audit_receipt_owner;

GRANT USAGE ON SCHEMA public TO dbp_audit_append_owner, dbp_audit_exporter, dbp_audit_receipt_verifier, dbp_audit_receipt_owner;
GRANT SELECT ON public.authorization_audit_streams TO dbp_audit_append_owner;
GRANT INSERT ON public.authorization_audit_events TO dbp_audit_append_owner;
GRANT SELECT, UPDATE ("lastSequence", "lastEventHash", "updatedAt") ON public.authorization_audit_heads TO dbp_audit_append_owner;
GRANT USAGE ON TYPE public."AuthorizationAuditActorType", public."AuthorizationAuditDecision" TO dbp_audit_append_owner;
GRANT EXECUTE ON FUNCTION public.digest(BYTEA, TEXT) TO dbp_audit_append_owner;
GRANT EXECUTE ON FUNCTION pg_catalog.int2send(SMALLINT), pg_catalog.int8send(BIGINT), pg_catalog.uuid_send(UUID) TO dbp_audit_append_owner;

-- The exporter records a receipt only after verifying its Ed25519 signature and
-- exact destination/range/hash correspondence. It cannot mutate audit history.
REVOKE ALL ON public.audit_archive_receipts FROM PUBLIC, dbp_runtime, dbp_audit_exporter;
