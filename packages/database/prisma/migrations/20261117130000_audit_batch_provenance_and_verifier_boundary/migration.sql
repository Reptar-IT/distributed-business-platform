-- Restrict batch creation to a SECURITY DEFINER function that reads and verifies
-- the immutable PostgreSQL audit rows. The exporter receives only function access.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_audit_batch_owner') THEN
    RAISE EXCEPTION 'Provision dbp_audit_batch_owner with infrastructure/database/roles.sql first';
  END IF;
  IF EXISTS (SELECT 1 FROM public.audit_export_batches) THEN
    RAISE EXCEPTION 'Review and reconcile existing audit batches before applying batch-provenance enforcement';
  END IF;
END $$;

ALTER TABLE public.audit_destinations
  ADD COLUMN "lastSucceededAt" TIMESTAMPTZ(6),
  ADD COLUMN "consecutiveFailures" INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN "lastErrorCategory" VARCHAR(100),
  ADD COLUMN "updatedAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ADD CONSTRAINT "audit_destinations_consecutiveFailures_check" CHECK ("consecutiveFailures" >= 0);

CREATE FUNCTION public.prepare_authorization_audit_batch(
  p_stream_id UUID,
  p_first_sequence BIGINT,
  p_max_events INTEGER DEFAULT 100
)
RETURNS TABLE (
  batch_id UUID,
  stream_id UUID,
  first_sequence BIGINT,
  last_sequence BIGINT,
  event_count INTEGER,
  previous_hash BYTEA,
  terminal_event_hash BYTEA,
  batch_hash BYTEA,
  canonical_batch TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_existing public.audit_export_batches%ROWTYPE;
  v_has_existing BOOLEAN := FALSE;
  v_prior_sequence BIGINT;
  v_prior_hash BYTEA;
  v_expected_sequence BIGINT;
  v_head_sequence BIGINT;
  v_limit INTEGER;
  v_count INTEGER := 0;
  v_first_sequence BIGINT;
  v_last_sequence BIGINT;
  v_previous_hash BYTEA;
  v_expected_previous_hash BYTEA;
  v_terminal_hash BYTEA;
  v_event_hash BYTEA;
  v_ordered_hashes BYTEA := decode('', 'hex');
  v_ordered_hashes_digest BYTEA;
  v_batch_hash BYTEA;
  v_events JSONB := '[]'::jsonb;
  v_batch JSONB;
  v_batch_text TEXT;
  v_batch_id UUID;
  v_destination_count INTEGER;
  v_event RECORD;
BEGIN
  IF p_first_sequence IS NULL OR p_first_sequence < 1 THEN
    RAISE EXCEPTION 'Batch first sequence must be positive';
  END IF;
  IF p_max_events IS NULL OR p_max_events < 1 OR p_max_events > 1000 THEN
    RAISE EXCEPTION 'Batch event limit must be between 1 and 1000';
  END IF;

  -- Serializes batch preparation for this stream. Audit appenders only take the
  -- head row FOR UPDATE, so this does not block normal appends.
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_stream_id::text, 0));

  SELECT b.* INTO v_existing
    FROM public.audit_export_batches b
   WHERE b."streamId" = p_stream_id AND b."firstSequence" = p_first_sequence;
  v_has_existing := FOUND;
  IF v_has_existing THEN
    v_limit := v_existing."eventCount";
  ELSE
    v_limit := p_max_events;
  END IF;

  SELECT b."lastSequence", b."terminalEventHash"
    INTO v_prior_sequence, v_prior_hash
    FROM public.audit_export_batches b
   WHERE b."streamId" = p_stream_id AND b."firstSequence" < p_first_sequence
   ORDER BY b."firstSequence" DESC
   LIMIT 1;
  IF FOUND THEN
    IF v_prior_sequence <> p_first_sequence - 1 THEN
      RAISE EXCEPTION 'Requested batch does not immediately follow the prior prepared range';
    END IF;
    v_expected_sequence := v_prior_sequence + 1;
    v_expected_previous_hash := v_prior_hash;
  ELSE
    v_expected_sequence := 1;
    v_expected_previous_hash := decode(repeat('00', 32), 'hex');
  END IF;
  IF p_first_sequence <> v_expected_sequence THEN
    RAISE EXCEPTION 'Requested batch sequence is not the next source range';
  END IF;

  SELECT h."lastSequence" INTO v_head_sequence
    FROM public.authorization_audit_heads h WHERE h."streamId" = p_stream_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'Unknown audit stream'; END IF;
  IF p_first_sequence > v_head_sequence THEN RETURN; END IF;

  v_first_sequence := p_first_sequence;
  v_expected_sequence := p_first_sequence;
  v_previous_hash := v_expected_previous_hash;
  FOR v_event IN
    SELECT e."streamId", e."sequence", e."serializationVersion", e."hashVersion",
           e."canonicalPayload", e."previousHash", e."eventHash"
      FROM public.authorization_audit_events e
     WHERE e."streamId" = p_stream_id
       AND e."sequence" >= p_first_sequence
       AND e."sequence" <= v_head_sequence
     ORDER BY e."sequence"
     LIMIT v_limit
  LOOP
    IF v_event."sequence" <> v_expected_sequence THEN
      RAISE EXCEPTION 'Audit source range contains a sequence gap at %', v_expected_sequence;
    END IF;
    IF v_event."serializationVersion" <> 1 OR v_event."hashVersion" <> 1 THEN
      RAISE EXCEPTION 'Unsupported audit event serialization or hash version';
    END IF;
    IF v_event."previousHash" <> v_previous_hash THEN
      RAISE EXCEPTION 'Audit source range has a previous-hash discontinuity at %', v_event."sequence";
    END IF;

    v_event_hash := public.digest(
      decode('4442502d415554485a2d4556454e5400', 'hex') ||
      pg_catalog.int2send(v_event."hashVersion"::smallint) ||
      pg_catalog.uuid_send(p_stream_id) ||
      pg_catalog.int8send(v_event."sequence") ||
      v_event."previousHash" ||
      pg_catalog.int8send(octet_length(convert_to(v_event."canonicalPayload", 'UTF8'))::bigint) ||
      convert_to(v_event."canonicalPayload", 'UTF8'),
      'sha256'
    );
    IF v_event_hash <> v_event."eventHash" THEN
      RAISE EXCEPTION 'Stored audit event hash is invalid at sequence %', v_event."sequence";
    END IF;

    v_events := v_events || jsonb_build_array(jsonb_build_object(
      'sequence', v_event."sequence"::text,
      'canonicalPayload', v_event."canonicalPayload",
      'previousHash', encode(v_event."previousHash", 'hex'),
      'eventHash', encode(v_event."eventHash", 'hex')
    ));
    v_ordered_hashes := v_ordered_hashes || v_event."eventHash";
    v_previous_hash := v_event."eventHash";
    v_terminal_hash := v_event."eventHash";
    v_last_sequence := v_event."sequence";
    v_count := v_count + 1;
    v_expected_sequence := v_expected_sequence + 1;
  END LOOP;

  IF v_count = 0 THEN RETURN; END IF;
  IF v_count < v_limit AND v_expected_sequence <= v_head_sequence THEN
    RAISE EXCEPTION 'Audit source range contains a trailing sequence gap at %', v_expected_sequence;
  END IF;
  IF v_has_existing AND v_count <> v_existing."eventCount" THEN
    RAISE EXCEPTION 'Existing batch event count does not match source events';
  END IF;
  v_ordered_hashes_digest := public.digest(v_ordered_hashes, 'sha256');
  v_batch_hash := public.digest(
    decode('4442502d415554485a2d424154434800', 'hex') ||
    pg_catalog.int2send(1::smallint) ||
    pg_catalog.uuid_send(p_stream_id) ||
    pg_catalog.int8send(v_first_sequence) ||
    pg_catalog.int8send(v_last_sequence) ||
    pg_catalog.int8send(v_count::bigint) ||
    v_expected_previous_hash ||
    v_terminal_hash ||
    v_ordered_hashes_digest,
    'sha256'
  );
  v_batch := jsonb_build_object(
    'protocolVersion', 1,
    'serializationVersion', 1,
    'hashVersion', 1,
    'streamId', p_stream_id::text,
    'firstSequence', v_first_sequence::text,
    'lastSequence', v_last_sequence::text,
    'eventCount', v_count,
    'previousHash', encode(v_expected_previous_hash, 'hex'),
    'terminalEventHash', encode(v_terminal_hash, 'hex'),
    'orderedEventHashesDigest', encode(v_ordered_hashes_digest, 'hex'),
    'batchHash', encode(v_batch_hash, 'hex'),
    'events', v_events
  );
  v_batch_text := v_batch::text;

  IF v_has_existing THEN
    IF v_existing."lastSequence" <> v_last_sequence
       OR v_existing."eventCount" <> v_count
       OR v_existing."previousHash" <> v_expected_previous_hash
       OR v_existing."terminalEventHash" <> v_terminal_hash
       OR v_existing."batchHash" <> v_batch_hash
       OR v_existing."canonicalBatch" <> v_batch_text THEN
      RAISE EXCEPTION 'Existing prepared batch metadata does not match immutable source events';
    END IF;
    v_batch_id := v_existing."id";
  ELSE
    IF NOT EXISTS (SELECT 1 FROM public.audit_destinations WHERE "id" = 'physical' AND "enabled")
       OR NOT EXISTS (SELECT 1 FROM public.audit_destinations WHERE "id" = 'hosted' AND "enabled") THEN
      RAISE EXCEPTION 'Both independent audit archive destinations must be enabled';
    END IF;
    v_batch_id := pg_catalog.gen_random_uuid();
    INSERT INTO public.audit_export_batches (
      "id", "streamId", "firstSequence", "lastSequence", "eventCount", "previousHash",
      "terminalEventHash", "batchHash", "canonicalBatch"
    ) VALUES (
      v_batch_id, p_stream_id, v_first_sequence, v_last_sequence, v_count,
      v_expected_previous_hash, v_terminal_hash, v_batch_hash, v_batch_text
    );
    INSERT INTO public.audit_export_deliveries ("batchId", "destinationId")
      SELECT v_batch_id, d."id" FROM public.audit_destinations d WHERE d."enabled";
    GET DIAGNOSTICS v_destination_count = ROW_COUNT;
    IF v_destination_count < 2 THEN
      RAISE EXCEPTION 'Audit batch must have independent physical and hosted delivery rows';
    END IF;
  END IF;

  RETURN QUERY SELECT b."id", b."streamId", b."firstSequence", b."lastSequence", b."eventCount",
                      b."previousHash", b."terminalEventHash", b."batchHash", b."canonicalBatch"
    FROM public.audit_export_batches b WHERE b."id" = v_batch_id;
END;
$$;

ALTER FUNCTION public.prepare_authorization_audit_batch(UUID, BIGINT, INTEGER) OWNER TO dbp_audit_batch_owner;
REVOKE ALL ON FUNCTION public.prepare_authorization_audit_batch(UUID, BIGINT, INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.prepare_authorization_audit_batch(UUID, BIGINT, INTEGER) TO dbp_audit_exporter;

REVOKE ALL ON public.audit_export_batches, public.audit_export_deliveries FROM PUBLIC, dbp_runtime, dbp_audit_exporter;
REVOKE INSERT, UPDATE, DELETE ON public.audit_export_batches, public.audit_export_deliveries FROM dbp_audit_exporter;
REVOKE SELECT ON public.authorization_audit_streams, public.authorization_audit_events FROM dbp_audit_exporter;
GRANT SELECT ON public.audit_export_batches, public.audit_export_deliveries, public.audit_export_checkpoints TO dbp_audit_exporter;
GRANT UPDATE ("attempts", "nextAttemptAt", "lastErrorCode", "updatedAt") ON public.audit_export_deliveries TO dbp_audit_exporter;
GRANT SELECT ON public.audit_destinations TO dbp_audit_exporter;
GRANT UPDATE ("consecutiveFailures", "lastErrorCategory", "updatedAt") ON public.audit_destinations TO dbp_audit_exporter;

GRANT USAGE ON SCHEMA public TO dbp_audit_batch_owner, dbp_runtime;
GRANT SELECT ON public.authorization_audit_streams, public.authorization_audit_heads,
  public.authorization_audit_events, public.audit_export_batches, public.audit_destinations
  TO dbp_audit_batch_owner;
GRANT INSERT ON public.audit_export_batches, public.audit_export_deliveries TO dbp_audit_batch_owner;
GRANT USAGE ON TYPE public."AuditExportStatus" TO dbp_audit_batch_owner;
GRANT EXECUTE ON FUNCTION public.digest(BYTEA, TEXT) TO dbp_audit_batch_owner;
GRANT EXECUTE ON FUNCTION pg_catalog.int2send(SMALLINT), pg_catalog.int8send(BIGINT), pg_catalog.uuid_send(UUID),
  pg_catalog.hashtextextended(TEXT, BIGINT) TO dbp_audit_batch_owner;

CREATE OR REPLACE FUNCTION public.record_verified_audit_receipt(
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
  IF octet_length(p_signature) <> 64 THEN RAISE EXCEPTION 'Invalid Ed25519 signature size'; END IF;
  v_receipt := p_receipt_payload::jsonb;
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
  UPDATE public.audit_destinations
     SET "lastSucceededAt" = clock_timestamp(), "consecutiveFailures" = 0,
         "lastErrorCategory" = NULL, "updatedAt" = clock_timestamp()
   WHERE "id" = p_destination_id;
END;
$$;

REVOKE ALL ON FUNCTION public.record_verified_audit_receipt(UUID, TEXT, TEXT, BYTEA) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.record_verified_audit_receipt(UUID, TEXT, TEXT, BYTEA) FROM dbp_runtime, dbp_audit_exporter;
GRANT EXECUTE ON FUNCTION public.record_verified_audit_receipt(UUID, TEXT, TEXT, BYTEA) TO dbp_audit_receipt_verifier;
GRANT UPDATE ("lastSucceededAt", "consecutiveFailures", "lastErrorCategory", "updatedAt")
  ON public.audit_destinations TO dbp_audit_receipt_owner;
GRANT SELECT ("id") ON public.audit_destinations TO dbp_audit_receipt_owner;
GRANT USAGE ON SCHEMA public TO dbp_runtime;
