-- Durable, generic critical-operation gate. No domain lifecycle is implemented here.
BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_critical_operation_owner') THEN CREATE ROLE dbp_critical_operation_owner NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_critical_operation_service') THEN CREATE ROLE dbp_critical_operation_service NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_critical_operation_reconciler') THEN CREATE ROLE dbp_critical_operation_reconciler NOLOGIN; END IF;
END $$;

CREATE TYPE public."CriticalOperationStatus" AS ENUM (
  'PREPARED', 'AWAITING_ARCHIVE', 'READY_TO_ACTIVATE', 'REVOCATION_PENDING_ARCHIVE',
  'COMPLETED', 'FAILED', 'RECONCILIATION_REQUIRED'
);
REVOKE ALL ON TYPE public."CriticalOperationStatus" FROM PUBLIC, dbp_runtime, dbp_audit_exporter, dbp_audit_receipt_verifier;
GRANT USAGE ON TYPE public."CriticalOperationStatus" TO dbp_critical_operation_owner;

CREATE TABLE public.critical_operations (
  id UUID PRIMARY KEY,
  "operationType" VARCHAR(100) NOT NULL,
  "targetType" VARCHAR(100) NOT NULL,
  "targetId" VARCHAR(200) NOT NULL,
  "idempotencyDigest" BYTEA NOT NULL UNIQUE,
  "requestFingerprint" BYTEA NOT NULL,
  status public."CriticalOperationStatus" NOT NULL DEFAULT 'PREPARED',
  "streamId" UUID NOT NULL,
  "intentEventId" UUID NOT NULL,
  "intentSequence" BIGINT NOT NULL,
  "readyOrRevocationEventId" UUID,
  "readyOrRevocationSequence" BIGINT,
  "completionEventId" UUID,
  "completionSequence" BIGINT,
  "qualifyingReceiptId" UUID,
  "qualifyingDestinationId" VARCHAR(80),
  "qualifyingKeyId" VARCHAR(100),
  "failureCategory" VARCHAR(100),
  "reconciliationMetadata" JSONB,
  "createdAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "completedAt" TIMESTAMPTZ(6),
  CONSTRAINT critical_operations_hash_lengths CHECK (octet_length("idempotencyDigest") = 32 AND octet_length("requestFingerprint") = 32),
  CONSTRAINT "critical_operations_intentEventId_fkey" FOREIGN KEY ("intentEventId") REFERENCES public.authorization_audit_events("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT "critical_operations_readyOrRevocationEventId_fkey" FOREIGN KEY ("readyOrRevocationEventId") REFERENCES public.authorization_audit_events("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT "critical_operations_completionEventId_fkey" FOREIGN KEY ("completionEventId") REFERENCES public.authorization_audit_events("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT "critical_operations_qualifyingReceiptId_fkey" FOREIGN KEY ("qualifyingReceiptId") REFERENCES public.audit_archive_receipts("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT critical_operations_state_shape CHECK (
    (status = 'PREPARED' AND "readyOrRevocationSequence" IS NULL AND "completionSequence" IS NULL AND "qualifyingReceiptId" IS NULL AND "completedAt" IS NULL)
    OR (status IN ('AWAITING_ARCHIVE','READY_TO_ACTIVATE') AND "readyOrRevocationSequence" IS NOT NULL AND "completionSequence" IS NULL AND "qualifyingReceiptId" IS NULL AND "completedAt" IS NULL)
    OR (status = 'REVOCATION_PENDING_ARCHIVE' AND "readyOrRevocationSequence" IS NOT NULL AND "completionSequence" IS NULL AND "completedAt" IS NULL)
    OR (status = 'COMPLETED' AND "readyOrRevocationSequence" IS NOT NULL AND "completionSequence" IS NOT NULL AND "qualifyingReceiptId" IS NOT NULL AND "qualifyingDestinationId" IS NOT NULL AND "qualifyingKeyId" IS NOT NULL AND "completedAt" IS NOT NULL)
    OR (status = 'FAILED' AND "completionSequence" IS NULL AND "failureCategory" IS NOT NULL AND "completedAt" IS NULL)
    OR (status = 'RECONCILIATION_REQUIRED' AND "completionSequence" IS NULL AND "reconciliationMetadata" IS NOT NULL AND "completedAt" IS NULL)
  ),
  CONSTRAINT critical_operations_reconciliation_metadata_safe CHECK (
    "reconciliationMetadata" IS NULL OR
    (jsonb_typeof("reconciliationMetadata")='object'
     AND ("reconciliationMetadata" - 'reasonCode' - 'relatedOperationId')='{}'::jsonb
     AND (NOT ("reconciliationMetadata" ? 'reasonCode') OR (jsonb_typeof("reconciliationMetadata"->'reasonCode')='string' AND ("reconciliationMetadata"->>'reasonCode') ~ '^[a-z0-9_]{1,100}$'))
     AND (NOT ("reconciliationMetadata" ? 'relatedOperationId') OR (jsonb_typeof("reconciliationMetadata"->'relatedOperationId')='string' AND ("reconciliationMetadata"->>'relatedOperationId') ~ '^[0-9a-fA-F-]{36}$')))
  )
);
CREATE INDEX "critical_operations_status_createdAt_idx" ON public.critical_operations(status, "createdAt");
CREATE INDEX "critical_operations_targetType_targetId_createdAt_idx" ON public.critical_operations("targetType", "targetId", "createdAt");
CREATE UNIQUE INDEX critical_operations_one_open_target_idx ON public.critical_operations("targetType", "targetId")
  WHERE status IN ('PREPARED','AWAITING_ARCHIVE','READY_TO_ACTIVATE','REVOCATION_PENDING_ARCHIVE','RECONCILIATION_REQUIRED');

CREATE TABLE public.critical_operation_gates (
  "targetType" VARCHAR(100) NOT NULL,
  "targetId" VARCHAR(200) NOT NULL,
  state VARCHAR(20) NOT NULL,
  "operationId" UUID NOT NULL,
  "updatedAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY ("targetType", "targetId"),
  CONSTRAINT "critical_operation_gates_operationId_key" UNIQUE ("operationId"),
  CONSTRAINT "critical_operation_gates_operationId_fkey" FOREIGN KEY ("operationId") REFERENCES public.critical_operations("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT critical_operation_gate_state_check CHECK (state IN ('INACTIVE','PROPOSED','ACTIVE','REVOKED'))
);
CREATE INDEX "critical_operation_gates_operationId_idx" ON public.critical_operation_gates("operationId");

REVOKE ALL ON public.critical_operations, public.critical_operation_gates FROM PUBLIC, dbp_runtime, dbp_audit_exporter, dbp_audit_receipt_verifier;
GRANT USAGE ON SCHEMA public TO dbp_critical_operation_owner, dbp_critical_operation_service, dbp_critical_operation_reconciler, dbp_runtime;
GRANT SELECT, INSERT, UPDATE ON public.critical_operations TO dbp_critical_operation_owner;
GRANT SELECT, INSERT, UPDATE ON public.critical_operation_gates TO dbp_critical_operation_owner;
GRANT SELECT ON public.critical_operations, public.critical_operation_gates TO dbp_critical_operation_reconciler;
GRANT SELECT ON public.authorization_audit_events, public.audit_archive_receipts, public.audit_export_batches,
  public.audit_export_deliveries, public.audit_export_checkpoints, public.audit_destinations TO dbp_critical_operation_owner;
GRANT EXECUTE ON FUNCTION public.append_authorization_audit(JSONB, UUID) TO dbp_critical_operation_owner;
GRANT EXECUTE ON FUNCTION public.prepare_authorization_audit_batch(UUID, BIGINT, INTEGER) TO dbp_critical_operation_owner;

CREATE FUNCTION public.critical_operation_receipt(p_operation_id UUID)
RETURNS TABLE(receipt_id UUID, destination_id TEXT, key_id TEXT)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE v_op public.critical_operations%ROWTYPE; v_last BIGINT;
BEGIN
  SELECT * INTO v_op FROM public.critical_operations WHERE id = p_operation_id;
  IF NOT FOUND OR v_op."readyOrRevocationSequence" IS NULL THEN RETURN; END IF;
  v_last := v_op."readyOrRevocationSequence";
  -- The Stage 1 verifier is the only writer of receipts. Its per-destination
  -- checkpoint advances only through source-contiguous verified receipts.
  RETURN QUERY
  SELECT r."id", r."destinationId"::TEXT, r."keyId"::TEXT
    FROM public.audit_archive_receipts r
    JOIN public.audit_export_batches b ON b.id = r."batchId"
    JOIN public.audit_export_deliveries d ON d."batchId" = r."batchId" AND d."destinationId" = r."destinationId"
    JOIN public.audit_destinations dest ON dest.id = r."destinationId"
    JOIN public.audit_export_checkpoints cp ON cp."streamId" = b."streamId" AND cp."destinationId" = r."destinationId"
   WHERE b."streamId" = v_op."streamId"
     AND b."firstSequence" <= v_last
     AND b."lastSequence" >= v_last
     AND cp."lastAcknowledgedSequence" >= v_last
     AND d.status = 'ACKNOWLEDGED'
     AND dest.type IN ('PHYSICAL','HOSTED')
     AND r."batchHash" = b."batchHash"
     AND r."firstSequence" = b."firstSequence"
     AND r."lastSequence" = b."lastSequence"
     AND r."terminalEventHash" = b."terminalEventHash"
     AND octet_length(r.signature) = 64
     AND r."keyId" <> ''
     AND (r."receiptPayload"::jsonb->>'version')='1'
     AND (r."receiptPayload"::jsonb->>'destinationId')=r."destinationId"
     AND (r."receiptPayload"::jsonb->>'keyId')=r."keyId"
     AND (r."receiptPayload"::jsonb->>'batchHash')=encode(b."batchHash",'hex')
     AND (r."receiptPayload"::jsonb->>'firstSequence')=b."firstSequence"::text
     AND (r."receiptPayload"::jsonb->>'lastSequence')=b."lastSequence"::text
     AND (r."receiptPayload"::jsonb->>'terminalEventHash')=encode(b."terminalEventHash",'hex')
     AND EXISTS (
       SELECT 1 FROM public.audit_archive_receipts ri
       JOIN public.audit_export_batches bi ON bi.id=ri."batchId"
       JOIN public.audit_export_deliveries di ON di."batchId"=ri."batchId" AND di."destinationId"=ri."destinationId"
       WHERE ri."destinationId"=r."destinationId" AND bi."streamId"=v_op."streamId"
         AND bi."firstSequence"<=v_op."intentSequence" AND bi."lastSequence">=v_op."intentSequence"
         AND ri."batchHash"=bi."batchHash" AND ri."firstSequence"=bi."firstSequence" AND ri."lastSequence"=bi."lastSequence"
         AND ri."terminalEventHash"=bi."terminalEventHash" AND di.status='ACKNOWLEDGED'
     )
     AND (SELECT count(*) FROM public.authorization_audit_events e
           WHERE e."streamId" = b."streamId" AND e.sequence BETWEEN b."firstSequence" AND b."lastSequence") = b."eventCount"
     AND EXISTS (SELECT 1 FROM public.authorization_audit_events e WHERE e."streamId"=b."streamId" AND e.sequence=b."firstSequence" AND e."previousHash"=b."previousHash")
     AND EXISTS (SELECT 1 FROM public.authorization_audit_events e WHERE e."streamId"=b."streamId" AND e.sequence=b."lastSequence" AND e."eventHash"=b."terminalEventHash")
     AND NOT EXISTS (
       SELECT 1 FROM (
         SELECT e.sequence, e."eventHash", lag(e."eventHash") OVER (ORDER BY e.sequence) AS prior_hash
           FROM public.authorization_audit_events e
          WHERE e."streamId"=b."streamId" AND e.sequence BETWEEN b."firstSequence" AND b."lastSequence"
       ) chain
       WHERE chain.prior_hash IS NOT NULL AND chain.prior_hash IS DISTINCT FROM
         (SELECT e."previousHash" FROM public.authorization_audit_events e WHERE e."streamId"=b."streamId" AND e.sequence=chain.sequence)
     )
     AND EXISTS (SELECT 1 FROM public.authorization_audit_events e WHERE e."streamId"=v_op."streamId" AND e.sequence=v_op."intentSequence" AND e.id=v_op."intentEventId")
     AND EXISTS (SELECT 1 FROM public.authorization_audit_events e WHERE e."streamId"=v_op."streamId" AND e.sequence=v_last AND e.id=v_op."readyOrRevocationEventId")
   ORDER BY r."verifiedAt", r."destinationId"
   LIMIT 1;
END;
$$;

CREATE FUNCTION public.prepare_critical_operation(
  p_operation_type TEXT, p_target_type TEXT, p_target_id TEXT,
  p_idempotency_digest BYTEA, p_request_fingerprint BYTEA, p_actor_id TEXT DEFAULT 'critical-operation-service'
) RETURNS UUID
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE v_existing public.critical_operations%ROWTYPE; v_id UUID; v_event RECORD; v_state TEXT;
BEGIN
  IF p_operation_type = '' OR p_target_type = '' OR p_target_id = '' OR length(p_target_id)>200
     OR octet_length(p_idempotency_digest)<>32 OR octet_length(p_request_fingerprint)<>32 THEN RAISE EXCEPTION 'INVALID_OPERATION_REQUEST'; END IF;
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(encode(p_idempotency_digest,'hex'),0));
  SELECT * INTO v_existing FROM public.critical_operations WHERE "idempotencyDigest"=p_idempotency_digest FOR UPDATE;
  IF FOUND THEN
    IF v_existing."requestFingerprint"<>p_request_fingerprint OR v_existing."operationType"<>p_operation_type
       OR v_existing."targetType"<>p_target_type OR v_existing."targetId"<>p_target_id THEN RAISE EXCEPTION 'IDEMPOTENCY_CONFLICT'; END IF;
    RETURN v_existing.id;
  END IF;
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_target_type || ':' || p_target_id,1));
  SELECT state INTO v_state FROM public.critical_operation_gates WHERE "targetType"=p_target_type AND "targetId"=p_target_id FOR UPDATE;
  IF EXISTS (SELECT 1 FROM public.critical_operations WHERE "targetType"=p_target_type AND "targetId"=p_target_id AND status IN ('PREPARED','AWAITING_ARCHIVE','READY_TO_ACTIVATE','REVOCATION_PENDING_ARCHIVE','RECONCILIATION_REQUIRED')) THEN RAISE EXCEPTION 'OPEN_OPERATION_EXISTS'; END IF;
  v_id := pg_catalog.gen_random_uuid();
  SELECT * INTO v_event FROM public.append_authorization_audit(jsonb_build_object(
    'eventType','critical-operation-intent','actorType','SYSTEM','actorId',p_actor_id,'targetType',p_target_type,'targetId',p_target_id,
    'operation','prepare','outcome','recorded','correlationId',v_id::text));
  INSERT INTO public.critical_operations(id,"operationType","targetType","targetId","idempotencyDigest","requestFingerprint",status,"streamId","intentEventId","intentSequence")
  VALUES(v_id,p_operation_type,p_target_type,p_target_id,p_idempotency_digest,p_request_fingerprint,'PREPARED','00000000-0000-0000-0000-000000000001',v_event."eventId",v_event.sequence);
  INSERT INTO public.critical_operation_gates("targetType","targetId",state,"operationId") VALUES(p_target_type,p_target_id,'PROPOSED',v_id)
  ON CONFLICT ("targetType","targetId") DO UPDATE SET state='PROPOSED',"operationId"=v_id,"updatedAt"=clock_timestamp()
  WHERE public.critical_operation_gates.state IN ('INACTIVE','REVOKED');
  IF NOT FOUND THEN RAISE EXCEPTION 'GATE_NOT_PREPARABLE'; END IF;
  RETURN v_id;
END;
$$;

CREATE FUNCTION public.register_critical_operation_ready(p_operation_id UUID, p_actor_id TEXT DEFAULT 'critical-operation-service') RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_op public.critical_operations%ROWTYPE; v_event RECORD;
BEGIN
  SELECT * INTO v_op FROM public.critical_operations WHERE id=p_operation_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'UNKNOWN_OPERATION'; END IF;
  IF v_op.status IN ('AWAITING_ARCHIVE','READY_TO_ACTIVATE','COMPLETED') THEN RETURN; END IF;
  IF v_op.status<>'PREPARED' THEN RAISE EXCEPTION 'INVALID_OPERATION_STATE'; END IF;
  SELECT * INTO v_event FROM public.append_authorization_audit(jsonb_build_object(
    'eventType','critical-operation-ready','actorType','SYSTEM','actorId',p_actor_id,'targetType',v_op."targetType",'targetId',v_op."targetId",
    'operation','await-archive','outcome','recorded','correlationId',v_op.id::text));
  UPDATE public.critical_operations SET status='AWAITING_ARCHIVE',"readyOrRevocationEventId"=v_event."eventId",
    "readyOrRevocationSequence"=v_event.sequence,"updatedAt"=clock_timestamp() WHERE id=v_op.id;
END; $$;

CREATE FUNCTION public.request_critical_operation_revocation(
  p_operation_type TEXT, p_target_type TEXT, p_target_id TEXT, p_idempotency_digest BYTEA,
  p_request_fingerprint BYTEA, p_actor_id TEXT DEFAULT 'critical-operation-service'
) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_op public.critical_operations%ROWTYPE; v_id UUID; v_intent RECORD; v_event RECORD;
        v_gate_state TEXT;
BEGIN
  IF octet_length(p_idempotency_digest)<>32 OR octet_length(p_request_fingerprint)<>32 OR p_target_type='' OR p_target_id='' THEN RAISE EXCEPTION 'INVALID_OPERATION_REQUEST'; END IF;
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(encode(p_idempotency_digest,'hex'),0));
  SELECT * INTO v_op FROM public.critical_operations WHERE "idempotencyDigest"=p_idempotency_digest FOR UPDATE;
  IF FOUND THEN
    IF v_op."requestFingerprint"<>p_request_fingerprint OR v_op."operationType"<>p_operation_type OR v_op."targetType"<>p_target_type OR v_op."targetId"<>p_target_id THEN RAISE EXCEPTION 'IDEMPOTENCY_CONFLICT'; END IF;
    RETURN v_op.id;
  END IF;
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_target_type || ':' || p_target_id,1));
  -- Acquire the authority row before touching the audit stream. An authorized
  -- action holds this row FOR SHARE while it appends its own audit event.
  -- This ordering makes revocation wait for in-flight actions without a
  -- gate/head lock inversion that could deadlock.
  SELECT state INTO v_gate_state FROM public.critical_operation_gates
   WHERE "targetType"=p_target_type AND "targetId"=p_target_id FOR UPDATE;
  IF EXISTS (SELECT 1 FROM public.critical_operations WHERE "targetType"=p_target_type AND "targetId"=p_target_id AND status IN ('PREPARED','AWAITING_ARCHIVE','READY_TO_ACTIVATE','REVOCATION_PENDING_ARCHIVE','RECONCILIATION_REQUIRED')) THEN RAISE EXCEPTION 'OPEN_OPERATION_EXISTS'; END IF;
  v_id := pg_catalog.gen_random_uuid();
  SELECT * INTO v_intent FROM public.append_authorization_audit(jsonb_build_object(
    'eventType','critical-operation-revocation-intent','actorType','SYSTEM','actorId',p_actor_id,'targetType',p_target_type,'targetId',p_target_id,
    'operation','revoke','outcome','recorded','correlationId',v_id::text));
  INSERT INTO public.critical_operations(id,"operationType","targetType","targetId","idempotencyDigest","requestFingerprint",status,"streamId","intentEventId","intentSequence")
  VALUES(v_id,p_operation_type,p_target_type,p_target_id,p_idempotency_digest,p_request_fingerprint,'PREPARED','00000000-0000-0000-0000-000000000001',v_intent."eventId",v_intent.sequence);
  INSERT INTO public.critical_operation_gates("targetType","targetId",state,"operationId") VALUES(p_target_type,p_target_id,'REVOKED',v_id)
  ON CONFLICT ("targetType","targetId") DO UPDATE SET state='REVOKED',"operationId"=v_id,"updatedAt"=clock_timestamp();
  SELECT * INTO v_event FROM public.append_authorization_audit(jsonb_build_object(
    'eventType','critical-operation-revoked','actorType','SYSTEM','actorId',p_actor_id,'targetType',p_target_type,'targetId',p_target_id,
    'operation','revoke','outcome','effective','correlationId',v_id::text));
  UPDATE public.critical_operations SET status='REVOCATION_PENDING_ARCHIVE',"readyOrRevocationEventId"=v_event."eventId",
    "readyOrRevocationSequence"=v_event.sequence,"updatedAt"=clock_timestamp() WHERE id=v_id;
  RETURN v_id;
END; $$;

CREATE FUNCTION public.finalize_critical_operation(p_operation_id UUID) RETURNS TEXT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_op public.critical_operations%ROWTYPE; v_receipt RECORD; v_event RECORD; v_gate public.critical_operation_gates%ROWTYPE;
BEGIN
  SELECT * INTO v_op FROM public.critical_operations WHERE id=p_operation_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'UNKNOWN_OPERATION'; END IF;
  IF v_op.status='COMPLETED' THEN RETURN 'COMPLETED'; END IF;
  IF v_op.status NOT IN ('READY_TO_ACTIVATE','REVOCATION_PENDING_ARCHIVE') THEN RAISE EXCEPTION 'OPERATION_NOT_READY'; END IF;
  SELECT * INTO v_gate FROM public.critical_operation_gates WHERE "targetType"=v_op."targetType" AND "targetId"=v_op."targetId" FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'GATE_MISSING'; END IF;
  SELECT * INTO v_receipt FROM public.critical_operation_receipt(v_op.id);
  IF NOT FOUND THEN RAISE EXCEPTION 'ARCHIVE_RECEIPT_REQUIRED'; END IF;
  IF v_op.status='READY_TO_ACTIVATE' THEN
    IF v_gate.state<>'PROPOSED' OR v_gate."operationId"<>v_op.id THEN RAISE EXCEPTION 'GATE_NOT_PROPOSED'; END IF;
    UPDATE public.critical_operation_gates SET state='ACTIVE',"updatedAt"=clock_timestamp() WHERE "targetType"=v_op."targetType" AND "targetId"=v_op."targetId";
  ELSE
    IF v_gate.state<>'REVOKED' THEN RAISE EXCEPTION 'REVOCATION_NOT_EFFECTIVE'; END IF;
  END IF;
  SELECT * INTO v_event FROM public.append_authorization_audit(jsonb_build_object(
    'eventType','critical-operation-completed','actorType','SYSTEM','actorId','critical-operation-finalizer',
    'targetType',v_op."targetType",'targetId',v_op."targetId",'operation','complete','outcome','committed',
    'correlationId',v_op.id::text,'jobId',v_receipt.receipt_id::text));
  UPDATE public.critical_operations SET status='COMPLETED',"completionEventId"=v_event."eventId","completionSequence"=v_event.sequence,
    "qualifyingReceiptId"=v_receipt.receipt_id,"qualifyingDestinationId"=v_receipt.destination_id,"qualifyingKeyId"=v_receipt.key_id,
    "completedAt"=clock_timestamp(),"updatedAt"=clock_timestamp() WHERE id=v_op.id;
  RETURN 'COMPLETED';
END; $$;

CREATE FUNCTION public.advance_critical_operations(p_limit INTEGER DEFAULT 100) RETURNS INTEGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_op RECORD; v_count INTEGER:=0;
BEGIN
  IF p_limit<1 OR p_limit>1000 THEN RAISE EXCEPTION 'INVALID_LIMIT'; END IF;
  FOR v_op IN SELECT id,status FROM public.critical_operations WHERE status IN ('PREPARED','AWAITING_ARCHIVE','READY_TO_ACTIVATE','REVOCATION_PENDING_ARCHIVE') ORDER BY "createdAt" FOR UPDATE SKIP LOCKED LIMIT p_limit LOOP
    BEGIN
      IF v_op.status='PREPARED' THEN
        PERFORM public.register_critical_operation_ready(v_op.id);
      ELSIF v_op.status='AWAITING_ARCHIVE' THEN
        PERFORM 1 FROM public.critical_operation_receipt(v_op.id);
        IF FOUND THEN
          UPDATE public.critical_operations SET status='READY_TO_ACTIVATE',"updatedAt"=clock_timestamp() WHERE id=v_op.id AND status='AWAITING_ARCHIVE';
        END IF;
      ELSIF v_op.status IN ('READY_TO_ACTIVATE','REVOCATION_PENDING_ARCHIVE') THEN
        PERFORM public.finalize_critical_operation(v_op.id);
      END IF;
      v_count:=v_count+1;
    EXCEPTION WHEN SQLSTATE 'P0001' THEN
      -- Expected not-yet-archived / not-ready conditions are retried next pass.
      IF SQLERRM NOT IN ('ARCHIVE_RECEIPT_REQUIRED','OPERATION_NOT_READY') THEN RAISE; END IF;
    END;
  END LOOP;
  RETURN v_count;
END; $$;

CREATE FUNCTION public.critical_operation_target_is_active(p_target_type TEXT,p_target_id TEXT) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_state TEXT;
BEGIN
  SELECT state INTO v_state FROM public.critical_operation_gates WHERE "targetType"=p_target_type AND "targetId"=p_target_id FOR SHARE;
  RETURN coalesce(v_state='ACTIVE',false);
END; $$;

CREATE FUNCTION public.mark_critical_operation_reconciliation(p_operation_id UUID,p_category TEXT,p_metadata JSONB) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_op public.critical_operations%ROWTYPE; v_event RECORD;
BEGIN
  IF p_category IS NULL OR p_category !~ '^[a-z0-9_]{1,100}$' OR p_metadata IS NULL
     OR jsonb_typeof(p_metadata)<>'object'
     OR EXISTS (SELECT 1 FROM jsonb_object_keys(p_metadata) AS keys(key) WHERE key NOT IN ('reasonCode','relatedOperationId'))
     OR (p_metadata ? 'reasonCode' AND (p_metadata->>'reasonCode') !~ '^[a-z0-9_]{1,100}$')
     OR (p_metadata ? 'relatedOperationId' AND (p_metadata->>'relatedOperationId') !~ '^[0-9a-fA-F-]{36}$')
     THEN RAISE EXCEPTION 'INVALID_RECONCILIATION'; END IF;
  SELECT * INTO v_op FROM public.critical_operations WHERE id=p_operation_id FOR UPDATE;
  IF NOT FOUND OR v_op.status IN ('COMPLETED','FAILED') THEN RAISE EXCEPTION 'INVALID_OPERATION_STATE'; END IF;
  IF v_op.status='RECONCILIATION_REQUIRED' THEN
    IF v_op."failureCategory"=p_category AND v_op."reconciliationMetadata"=p_metadata THEN RETURN; END IF;
    RAISE EXCEPTION 'RECONCILIATION_CONFLICT';
  END IF;
  SELECT * INTO v_event FROM public.append_authorization_audit(jsonb_build_object('eventType','critical-operation-reconciliation-required','actorType','SYSTEM',
    'actorId','critical-operation-reconciler','targetType',v_op."targetType",'targetId',v_op."targetId",'operation','reconcile','outcome',p_category,'correlationId',v_op.id::text));
  UPDATE public.critical_operations SET status='RECONCILIATION_REQUIRED',"failureCategory"=p_category,"reconciliationMetadata"=p_metadata,"updatedAt"=clock_timestamp() WHERE id=v_op.id;
END; $$;

CREATE FUNCTION public.resolve_critical_operation_reconciliation(p_operation_id UUID,p_category TEXT) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_op public.critical_operations%ROWTYPE; v_event RECORD;
BEGIN
  IF p_category IS NULL OR p_category !~ '^[a-z0-9_]{1,100}$' THEN RAISE EXCEPTION 'INVALID_RECONCILIATION'; END IF;
  SELECT * INTO v_op FROM public.critical_operations WHERE id=p_operation_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'INVALID_OPERATION_STATE'; END IF;
  IF v_op.status='FAILED' AND v_op."reconciliationMetadata" IS NOT NULL AND v_op."failureCategory"=p_category THEN RETURN; END IF;
  IF v_op.status<>'RECONCILIATION_REQUIRED' THEN RAISE EXCEPTION 'INVALID_OPERATION_STATE'; END IF;
  UPDATE public.critical_operation_gates SET state='INACTIVE',"updatedAt"=clock_timestamp()
   WHERE "targetType"=v_op."targetType" AND "targetId"=v_op."targetId" AND state='PROPOSED' AND "operationId"=v_op.id;
  SELECT * INTO v_event FROM public.append_authorization_audit(jsonb_build_object('eventType','critical-operation-reconciliation-resolved','actorType','SYSTEM',
    'actorId','critical-operation-reconciler','targetType',v_op."targetType",'targetId',v_op."targetId",'operation','resolve','outcome',p_category,'correlationId',v_op.id::text));
  UPDATE public.critical_operations SET status='FAILED',"failureCategory"=p_category,"updatedAt"=clock_timestamp() WHERE id=v_op.id;
END; $$;

ALTER FUNCTION public.critical_operation_receipt(UUID) OWNER TO dbp_critical_operation_owner;
ALTER FUNCTION public.prepare_critical_operation(TEXT,TEXT,TEXT,BYTEA,BYTEA,TEXT) OWNER TO dbp_critical_operation_owner;
ALTER FUNCTION public.register_critical_operation_ready(UUID,TEXT) OWNER TO dbp_critical_operation_owner;
ALTER FUNCTION public.request_critical_operation_revocation(TEXT,TEXT,TEXT,BYTEA,BYTEA,TEXT) OWNER TO dbp_critical_operation_owner;
ALTER FUNCTION public.finalize_critical_operation(UUID) OWNER TO dbp_critical_operation_owner;
ALTER FUNCTION public.advance_critical_operations(INTEGER) OWNER TO dbp_critical_operation_owner;
ALTER FUNCTION public.critical_operation_target_is_active(TEXT,TEXT) OWNER TO dbp_critical_operation_owner;
ALTER FUNCTION public.mark_critical_operation_reconciliation(UUID,TEXT,JSONB) OWNER TO dbp_critical_operation_owner;
ALTER FUNCTION public.resolve_critical_operation_reconciliation(UUID,TEXT) OWNER TO dbp_critical_operation_owner;
REVOKE ALL ON FUNCTION public.critical_operation_receipt(UUID), public.prepare_critical_operation(TEXT,TEXT,TEXT,BYTEA,BYTEA,TEXT),
  public.register_critical_operation_ready(UUID,TEXT), public.request_critical_operation_revocation(TEXT,TEXT,TEXT,BYTEA,BYTEA,TEXT),
  public.finalize_critical_operation(UUID), public.advance_critical_operations(INTEGER), public.critical_operation_target_is_active(TEXT,TEXT),
  public.mark_critical_operation_reconciliation(UUID,TEXT,JSONB) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.critical_operation_receipt(UUID), public.prepare_critical_operation(TEXT,TEXT,TEXT,BYTEA,BYTEA,TEXT),
  public.register_critical_operation_ready(UUID,TEXT), public.request_critical_operation_revocation(TEXT,TEXT,TEXT,BYTEA,BYTEA,TEXT),
  public.finalize_critical_operation(UUID), public.advance_critical_operations(INTEGER) TO dbp_critical_operation_service;
GRANT EXECUTE ON FUNCTION public.critical_operation_target_is_active(TEXT,TEXT) TO dbp_runtime;
GRANT EXECUTE ON FUNCTION public.mark_critical_operation_reconciliation(UUID,TEXT,JSONB) TO dbp_critical_operation_reconciler;
REVOKE ALL ON FUNCTION public.resolve_critical_operation_reconciliation(UUID,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.resolve_critical_operation_reconciliation(UUID,TEXT) TO dbp_critical_operation_reconciler;
COMMENT ON FUNCTION public.critical_operation_target_is_active(TEXT,TEXT) IS
  'Call inside the same database transaction as protected work; its FOR SHARE lock serializes that work against revocation.';
COMMENT ON FUNCTION public.finalize_critical_operation(UUID) IS
  'Restricted receipt-gated finalizer; trusts only immutable receipts committed by record_verified_audit_receipt.';

CREATE FUNCTION public.guard_critical_operation_write() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF current_user <> 'dbp_critical_operation_owner' THEN RAISE EXCEPTION 'CRITICAL_OPERATION_WRITE_FORBIDDEN'; END IF;
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Critical operations are immutable history'; END IF;
  IF TG_OP='UPDATE' THEN
    IF OLD.status IN ('COMPLETED','FAILED') OR (OLD.status='RECONCILIATION_REQUIRED' AND NEW.status<>'FAILED') THEN RAISE EXCEPTION 'Critical operation is terminal'; END IF;
    IF (NEW.id,NEW."operationType",NEW."targetType",NEW."targetId",NEW."idempotencyDigest",NEW."requestFingerprint",NEW."streamId",NEW."intentEventId",NEW."intentSequence")
       IS DISTINCT FROM
       (OLD.id,OLD."operationType",OLD."targetType",OLD."targetId",OLD."idempotencyDigest",OLD."requestFingerprint",OLD."streamId",OLD."intentEventId",OLD."intentSequence")
       THEN RAISE EXCEPTION 'Critical operation identity is immutable'; END IF;
    IF NEW.status<>OLD.status AND NOT (
      (OLD.status='PREPARED' AND NEW.status IN ('AWAITING_ARCHIVE','REVOCATION_PENDING_ARCHIVE','FAILED','RECONCILIATION_REQUIRED')) OR
      (OLD.status='AWAITING_ARCHIVE' AND NEW.status IN ('READY_TO_ACTIVATE','FAILED','RECONCILIATION_REQUIRED')) OR
      (OLD.status='READY_TO_ACTIVATE' AND NEW.status IN ('COMPLETED','FAILED','RECONCILIATION_REQUIRED')) OR
      (OLD.status='REVOCATION_PENDING_ARCHIVE' AND NEW.status IN ('COMPLETED','RECONCILIATION_REQUIRED')) OR
      (OLD.status='RECONCILIATION_REQUIRED' AND NEW.status='FAILED')
    ) THEN RAISE EXCEPTION 'Invalid critical-operation state transition'; END IF;
  END IF;
  RETURN NEW;
END; $$;
CREATE TRIGGER critical_operations_write_guard BEFORE INSERT OR UPDATE OR DELETE ON public.critical_operations
FOR EACH ROW EXECUTE FUNCTION public.guard_critical_operation_write();

CREATE FUNCTION public.guard_critical_operation_gate_write() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF current_user <> 'dbp_critical_operation_owner' THEN RAISE EXCEPTION 'CRITICAL_OPERATION_GATE_WRITE_FORBIDDEN'; END IF;
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Critical-operation gates cannot be deleted'; END IF;
  IF TG_OP='UPDATE' AND NEW.state<>OLD.state AND NOT (
    (OLD.state='INACTIVE' AND NEW.state IN ('PROPOSED','REVOKED')) OR
    (OLD.state='PROPOSED' AND NEW.state IN ('ACTIVE','INACTIVE','REVOKED')) OR
    (OLD.state='ACTIVE' AND NEW.state='REVOKED') OR
    (OLD.state='REVOKED' AND NEW.state='PROPOSED')
  ) THEN RAISE EXCEPTION 'Invalid critical-operation gate transition'; END IF;
  RETURN NEW;
END; $$;
CREATE TRIGGER critical_operation_gates_write_guard BEFORE INSERT OR UPDATE OR DELETE ON public.critical_operation_gates
FOR EACH ROW EXECUTE FUNCTION public.guard_critical_operation_gate_write();
REVOKE ALL ON FUNCTION public.guard_critical_operation_write(), public.guard_critical_operation_gate_write() FROM PUBLIC;

CREATE FUNCTION public.fail_critical_operation(p_operation_id UUID,p_category TEXT) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_op public.critical_operations%ROWTYPE; v_event RECORD;
BEGIN
  IF p_category IS NULL OR p_category !~ '^[a-z0-9_]{1,100}$' THEN RAISE EXCEPTION 'INVALID_FAILURE_CATEGORY'; END IF;
  SELECT * INTO v_op FROM public.critical_operations WHERE id=p_operation_id FOR UPDATE;
  IF NOT FOUND OR v_op.status NOT IN ('PREPARED','AWAITING_ARCHIVE','READY_TO_ACTIVATE') THEN RAISE EXCEPTION 'INVALID_OPERATION_STATE'; END IF;
  UPDATE public.critical_operation_gates SET state='INACTIVE',"updatedAt"=clock_timestamp()
   WHERE "targetType"=v_op."targetType" AND "targetId"=v_op."targetId" AND state='PROPOSED' AND "operationId"=v_op.id;
  SELECT * INTO v_event FROM public.append_authorization_audit(jsonb_build_object('eventType','critical-operation-failed','actorType','SYSTEM',
    'actorId','critical-operation-reconciler','targetType',v_op."targetType",'targetId',v_op."targetId",'operation','fail','outcome',p_category,'correlationId',v_op.id::text));
  UPDATE public.critical_operations SET status='FAILED',"failureCategory"=p_category,"updatedAt"=clock_timestamp() WHERE id=v_op.id;
END; $$;
ALTER FUNCTION public.fail_critical_operation(UUID,TEXT) OWNER TO dbp_critical_operation_owner;
REVOKE ALL ON FUNCTION public.fail_critical_operation(UUID,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.fail_critical_operation(UUID,TEXT) TO dbp_critical_operation_reconciler;

COMMIT;
