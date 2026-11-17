BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='dbp_owner_recovery_owner') THEN CREATE ROLE dbp_owner_recovery_owner NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='dbp_owner_recovery_operator') THEN CREATE ROLE dbp_owner_recovery_operator NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='dbp_owner_recovery_callback') THEN CREATE ROLE dbp_owner_recovery_callback NOLOGIN; END IF;
END $$;

CREATE TYPE public."UserIdentityStatus" AS ENUM ('ACTIVE','PENDING_OWNER_RECOVERY','OWNER_RECOVERY_FAILED');
CREATE TYPE public."OwnerRecoveryKitStatus" AS ENUM ('ACTIVE','REPLACED');
CREATE TYPE public."OwnerRecoveryCodeStatus" AS ENUM ('UNUSED','CONSUMED','REVOKED');
CREATE TYPE public."OwnerRecoveryStatus" AS ENUM (
  'INITIATED','CHALLENGE_PREPARED','OIDC_PROOF_VERIFIED','PREPARED','AWAITING_ARCHIVE',
  'READY_TO_FINALIZE','RECONCILIATION_REQUIRED','FINALIZED','FAILED','EXPIRED'
);

ALTER TABLE public.user_identities
  ADD COLUMN status public."UserIdentityStatus" NOT NULL DEFAULT 'ACTIVE',
  ADD COLUMN "ownerRecoveryOperationId" UUID UNIQUE,
  ADD CONSTRAINT user_identity_recovery_status_shape CHECK(status='ACTIVE' OR "ownerRecoveryOperationId" IS NOT NULL);

CREATE TABLE public.owner_recovery_kits (
  id UUID PRIMARY KEY,
  "designationId" UUID NOT NULL REFERENCES public.platform_owner_designations(id) ON DELETE RESTRICT,
  "platformUserId" UUID NOT NULL REFERENCES public.platform_users(id) ON DELETE RESTRICT,
  "authenticatedIdentityId" UUID NOT NULL,
  "authenticatedIssuer" TEXT NOT NULL,
  "authenticatedSubject" TEXT NOT NULL,
  generation INTEGER NOT NULL CHECK (generation > 0),
  status public."OwnerRecoveryKitStatus" NOT NULL DEFAULT 'ACTIVE',
  "issuedAt" TIMESTAMPTZ(6) NOT NULL DEFAULT clock_timestamp(),
  "replacedAt" TIMESTAMPTZ(6),
  CONSTRAINT owner_recovery_kit_identity_fkey FOREIGN KEY("authenticatedIdentityId","platformUserId","authenticatedIssuer","authenticatedSubject")
    REFERENCES public.user_identities(id,"userId",issuer,subject) ON DELETE RESTRICT,
  CONSTRAINT owner_recovery_kit_state_shape CHECK (
    (status='ACTIVE' AND "replacedAt" IS NULL) OR (status='REPLACED' AND "replacedAt" IS NOT NULL)
  ),
  CONSTRAINT owner_recovery_kit_generation_key UNIQUE("designationId",generation)
);
CREATE UNIQUE INDEX owner_recovery_one_active_kit_idx ON public.owner_recovery_kits("designationId") WHERE status='ACTIVE';
CREATE INDEX owner_recovery_kits_user_issued_idx ON public.owner_recovery_kits("platformUserId","issuedAt");

CREATE TABLE public.owner_recovery_codes (
  id UUID PRIMARY KEY,
  "kitId" UUID NOT NULL REFERENCES public.owner_recovery_kits(id) ON DELETE RESTRICT,
  "verifierKeyId" VARCHAR(100) NOT NULL CHECK("verifierKeyId" ~ '^[A-Za-z0-9._-]{1,100}$'),
  verifier BYTEA NOT NULL CHECK(octet_length(verifier)=32),
  status public."OwnerRecoveryCodeStatus" NOT NULL DEFAULT 'UNUSED',
  "consumedAt" TIMESTAMPTZ(6),
  "usedByRecoveryOperationId" UUID UNIQUE,
  "createdAt" TIMESTAMPTZ(6) NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT owner_recovery_code_state_shape CHECK (
    (status='UNUSED' AND "consumedAt" IS NULL) OR
    (status='CONSUMED' AND "consumedAt" IS NOT NULL AND "usedByRecoveryOperationId" IS NOT NULL) OR
    (status IN ('UNUSED','REVOKED') AND "consumedAt" IS NULL AND "usedByRecoveryOperationId" IS NULL)
  ),
  CONSTRAINT owner_recovery_code_verifier_key UNIQUE("verifierKeyId",verifier)
);
CREATE INDEX owner_recovery_codes_kit_status_idx ON public.owner_recovery_codes("kitId",status);

CREATE TABLE public.owner_recovery_operations (
  id UUID PRIMARY KEY,
  "designationId" UUID NOT NULL REFERENCES public.platform_owner_designations(id) ON DELETE RESTRICT,
  "platformUserId" UUID NOT NULL REFERENCES public.platform_users(id) ON DELETE RESTRICT,
  "recoveryCodeId" UUID NOT NULL UNIQUE REFERENCES public.owner_recovery_codes(id) ON DELETE RESTRICT,
  "expectedIssuer" TEXT NOT NULL,
  status public."OwnerRecoveryStatus" NOT NULL DEFAULT 'INITIATED',
  "expiresAt" TIMESTAMPTZ(6) NOT NULL,
  "initiatedAt" TIMESTAMPTZ(6) NOT NULL DEFAULT clock_timestamp(),
  "challengePreparedAt" TIMESTAMPTZ(6),
  "proofVerifiedAt" TIMESTAMPTZ(6),
  "preparedAt" TIMESTAMPTZ(6),
  "archiveQualifiedAt" TIMESTAMPTZ(6),
  "finalizedAt" TIMESTAMPTZ(6),
  "failedAt" TIMESTAMPTZ(6),
  "outcomeCode" VARCHAR(100),
  "criticalOperationId" UUID UNIQUE REFERENCES public.critical_operations(id) ON DELETE RESTRICT,
  CONSTRAINT owner_recovery_issuer_valid CHECK(length("expectedIssuer") BETWEEN 1 AND 1000),
  CONSTRAINT owner_recovery_outcome_valid CHECK("outcomeCode" IS NULL OR "outcomeCode" ~ '^[a-z0-9_]{1,100}$'),
  CONSTRAINT owner_recovery_state_shape CHECK (
    (status='INITIATED' AND "challengePreparedAt" IS NULL AND "proofVerifiedAt" IS NULL AND "preparedAt" IS NULL AND "archiveQualifiedAt" IS NULL AND "finalizedAt" IS NULL AND "failedAt" IS NULL AND "criticalOperationId" IS NULL) OR
    (status='CHALLENGE_PREPARED' AND "challengePreparedAt" IS NOT NULL AND "proofVerifiedAt" IS NULL AND "preparedAt" IS NULL AND "archiveQualifiedAt" IS NULL AND "finalizedAt" IS NULL AND "failedAt" IS NULL AND "criticalOperationId" IS NULL) OR
    (status='OIDC_PROOF_VERIFIED' AND "challengePreparedAt" IS NOT NULL AND "proofVerifiedAt" IS NOT NULL AND "preparedAt" IS NULL AND "finalizedAt" IS NULL AND "failedAt" IS NULL) OR
    (status IN ('PREPARED','AWAITING_ARCHIVE','READY_TO_FINALIZE','RECONCILIATION_REQUIRED') AND "challengePreparedAt" IS NOT NULL AND "proofVerifiedAt" IS NOT NULL AND "preparedAt" IS NOT NULL AND "finalizedAt" IS NULL AND "failedAt" IS NULL AND "criticalOperationId" IS NOT NULL) OR
    (status='FINALIZED' AND "challengePreparedAt" IS NOT NULL AND "proofVerifiedAt" IS NOT NULL AND "preparedAt" IS NOT NULL AND "archiveQualifiedAt" IS NOT NULL AND "finalizedAt" IS NOT NULL AND "failedAt" IS NULL AND "criticalOperationId" IS NOT NULL) OR
    (status IN ('FAILED','EXPIRED') AND "failedAt" IS NOT NULL AND "finalizedAt" IS NULL)
  )
);
ALTER TABLE public.user_identities ADD CONSTRAINT user_identity_recovery_operation_fkey
  FOREIGN KEY("ownerRecoveryOperationId") REFERENCES public.owner_recovery_operations(id) ON DELETE RESTRICT;
ALTER TABLE public.owner_recovery_codes ADD CONSTRAINT owner_recovery_code_used_by_fkey
  FOREIGN KEY("usedByRecoveryOperationId") REFERENCES public.owner_recovery_operations(id) ON DELETE RESTRICT;
CREATE UNIQUE INDEX owner_recovery_one_open_operation_idx ON public.owner_recovery_operations("designationId")
  WHERE status IN ('INITIATED','CHALLENGE_PREPARED','OIDC_PROOF_VERIFIED','PREPARED','AWAITING_ARCHIVE','READY_TO_FINALIZE','RECONCILIATION_REQUIRED');
CREATE INDEX owner_recovery_operations_status_expiry_idx ON public.owner_recovery_operations(status,"expiresAt");
CREATE INDEX owner_recovery_operations_user_initiated_idx ON public.owner_recovery_operations("platformUserId","initiatedAt");

CREATE TABLE public.owner_recovery_verifications (
  id UUID PRIMARY KEY,
  "recoveryOperationId" UUID NOT NULL UNIQUE REFERENCES public.owner_recovery_operations(id) ON DELETE RESTRICT,
  "userIdentityId" UUID NOT NULL UNIQUE,
  "platformUserId" UUID NOT NULL REFERENCES public.platform_users(id) ON DELETE RESTRICT,
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  "proofMethod" VARCHAR(100) NOT NULL CHECK("proofMethod"='OIDC_AUTHORIZATION_CODE_PKCE_FRESH_AUTH'),
  "verifiedAt" TIMESTAMPTZ(6) NOT NULL,
  "activatedAt" TIMESTAMPTZ(6),
  CONSTRAINT owner_recovery_verification_identity_fkey FOREIGN KEY("userIdentityId","platformUserId",issuer,subject)
    REFERENCES public.user_identities(id,"userId",issuer,subject) ON DELETE RESTRICT,
  CONSTRAINT owner_recovery_verification_activation_shape CHECK("activatedAt" IS NULL OR "activatedAt">="verifiedAt")
);
CREATE INDEX owner_recovery_verifications_user_idx ON public.owner_recovery_verifications("platformUserId","verifiedAt");

REVOKE ALL ON TYPE public."UserIdentityStatus",public."OwnerRecoveryKitStatus",public."OwnerRecoveryCodeStatus",public."OwnerRecoveryStatus"
  FROM PUBLIC,dbp_runtime,dbp_audit_exporter,dbp_audit_receipt_verifier;
REVOKE ALL ON public.owner_recovery_kits,public.owner_recovery_codes,public.owner_recovery_operations,public.owner_recovery_verifications
  FROM PUBLIC,dbp_runtime,dbp_audit_exporter,dbp_audit_receipt_verifier,dbp_critical_operation_service,dbp_critical_operation_reconciler;
GRANT USAGE ON SCHEMA public TO dbp_owner_recovery_owner,dbp_owner_recovery_operator,dbp_owner_recovery_callback;
GRANT USAGE ON TYPE public."UserIdentityStatus",public."OwnerRecoveryKitStatus",public."OwnerRecoveryCodeStatus",public."OwnerRecoveryStatus"
  TO dbp_owner_recovery_owner;
GRANT SELECT ON public.platform_users,public.user_identities,public.user_identity_verifications,public.owner_recovery_verifications,
  public.platform_owner_designations,public.platform_initialization,public.critical_operations,public.critical_operation_gates,
  public.audit_archive_receipts,public.authorization_audit_events TO dbp_owner_recovery_owner;
GRANT SELECT ON public.owner_recovery_verifications TO dbp_runtime;
GRANT UPDATE(status) ON public.platform_users,public.user_identities TO dbp_owner_recovery_owner;
GRANT SELECT,INSERT,UPDATE ON public.owner_recovery_kits,public.owner_recovery_codes,public.owner_recovery_operations,
  public.owner_recovery_verifications,public.user_identities TO dbp_owner_recovery_owner;
GRANT EXECUTE ON FUNCTION public.append_authorization_audit(JSONB,UUID),
  public.prepare_critical_operation(TEXT,TEXT,TEXT,BYTEA,BYTEA,TEXT),public.critical_operation_receipt(UUID),
  public.resolve_active_platform_owner(UUID),public.constant_time_bytea_equal(BYTEA,BYTEA),public.digest(BYTEA,TEXT)
  TO dbp_owner_recovery_owner;

CREATE FUNCTION public.guard_owner_recovery_kit() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF current_user<>'dbp_owner_recovery_owner' THEN RAISE EXCEPTION 'OWNER_RECOVERY_KIT_WRITE_FORBIDDEN'; END IF;
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'OWNER_RECOVERY_KIT_HISTORY_IS_IMMUTABLE'; END IF;
  IF TG_OP='UPDATE' AND ((NEW.id,NEW."designationId",NEW."platformUserId",NEW."authenticatedIdentityId",NEW."authenticatedIssuer",NEW."authenticatedSubject",NEW.generation,NEW."issuedAt")
    IS DISTINCT FROM (OLD.id,OLD."designationId",OLD."platformUserId",OLD."authenticatedIdentityId",OLD."authenticatedIssuer",OLD."authenticatedSubject",OLD.generation,OLD."issuedAt")
    OR OLD.status<>'ACTIVE' OR NEW.status<>'REPLACED') THEN RAISE EXCEPTION 'INVALID_OWNER_RECOVERY_KIT_TRANSITION'; END IF;
  RETURN NEW;
END; $$;
CREATE TRIGGER owner_recovery_kits_restricted_write BEFORE INSERT OR UPDATE OR DELETE ON public.owner_recovery_kits
FOR EACH ROW EXECUTE FUNCTION public.guard_owner_recovery_kit();

CREATE FUNCTION public.guard_owner_recovery_code() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF current_user<>'dbp_owner_recovery_owner' THEN RAISE EXCEPTION 'OWNER_RECOVERY_CODE_WRITE_FORBIDDEN'; END IF;
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'OWNER_RECOVERY_CODE_HISTORY_IS_IMMUTABLE'; END IF;
  IF TG_OP='UPDATE' AND ((NEW.id,NEW."kitId",NEW."verifierKeyId",NEW.verifier,NEW."createdAt") IS DISTINCT FROM
    (OLD.id,OLD."kitId",OLD."verifierKeyId",OLD.verifier,OLD."createdAt") OR OLD.status<>'UNUSED' OR NEW.status NOT IN ('CONSUMED','REVOKED'))
    THEN RAISE EXCEPTION 'INVALID_OWNER_RECOVERY_CODE_TRANSITION'; END IF;
  RETURN NEW;
END; $$;
CREATE TRIGGER owner_recovery_codes_restricted_write BEFORE INSERT OR UPDATE OR DELETE ON public.owner_recovery_codes
FOR EACH ROW EXECUTE FUNCTION public.guard_owner_recovery_code();

CREATE FUNCTION public.guard_owner_recovery_operation() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE v_valid BOOLEAN:=false;
BEGIN
  IF current_user<>'dbp_owner_recovery_owner' THEN RAISE EXCEPTION 'OWNER_RECOVERY_OPERATION_WRITE_FORBIDDEN'; END IF;
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'OWNER_RECOVERY_HISTORY_IS_IMMUTABLE'; END IF;
  IF TG_OP='UPDATE' THEN
    IF (NEW.id,NEW."designationId",NEW."platformUserId",NEW."recoveryCodeId",NEW."expectedIssuer",NEW."expiresAt",NEW."initiatedAt") IS DISTINCT FROM
       (OLD.id,OLD."designationId",OLD."platformUserId",OLD."recoveryCodeId",OLD."expectedIssuer",OLD."expiresAt",OLD."initiatedAt") OR
       OLD.status IN ('FINALIZED','FAILED','EXPIRED') THEN RAISE EXCEPTION 'INVALID_OWNER_RECOVERY_OPERATION_TRANSITION'; END IF;
    v_valid := (OLD.status='INITIATED' AND NEW.status IN ('CHALLENGE_PREPARED','FAILED','EXPIRED')) OR
      (OLD.status='CHALLENGE_PREPARED' AND NEW.status IN ('OIDC_PROOF_VERIFIED','FAILED','EXPIRED')) OR
      (OLD.status='OIDC_PROOF_VERIFIED' AND NEW.status='PREPARED') OR
      (OLD.status='PREPARED' AND NEW.status IN ('AWAITING_ARCHIVE','READY_TO_FINALIZE','RECONCILIATION_REQUIRED','FAILED')) OR
      (OLD.status='AWAITING_ARCHIVE' AND NEW.status IN ('READY_TO_FINALIZE','RECONCILIATION_REQUIRED','FAILED')) OR
      (OLD.status='READY_TO_FINALIZE' AND NEW.status IN ('FINALIZED','RECONCILIATION_REQUIRED','FAILED')) OR
      (OLD.status='RECONCILIATION_REQUIRED' AND NEW.status='FAILED');
    IF NOT v_valid THEN RAISE EXCEPTION 'INVALID_OWNER_RECOVERY_OPERATION_TRANSITION'; END IF;
  END IF;
  RETURN NEW;
END; $$;
CREATE TRIGGER owner_recovery_operations_restricted_write BEFORE INSERT OR UPDATE OR DELETE ON public.owner_recovery_operations
FOR EACH ROW EXECUTE FUNCTION public.guard_owner_recovery_operation();

CREATE FUNCTION public.guard_owner_recovery_verification() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF current_user<>'dbp_owner_recovery_owner' THEN RAISE EXCEPTION 'OWNER_RECOVERY_PROVENANCE_IS_IMMUTABLE'; END IF;
  IF TG_OP='INSERT' THEN RETURN NEW; END IF;
  IF TG_OP='UPDATE' AND OLD."activatedAt" IS NULL AND NEW."activatedAt" IS NOT NULL AND
    (NEW.id,NEW."recoveryOperationId",NEW."userIdentityId",NEW."platformUserId",NEW.issuer,NEW.subject,NEW."proofMethod",NEW."verifiedAt") IS NOT DISTINCT FROM
    (OLD.id,OLD."recoveryOperationId",OLD."userIdentityId",OLD."platformUserId",OLD.issuer,OLD.subject,OLD."proofMethod",OLD."verifiedAt") THEN RETURN NEW; END IF;
  RAISE EXCEPTION 'OWNER_RECOVERY_PROVENANCE_IS_IMMUTABLE';
END; $$;
CREATE TRIGGER owner_recovery_verifications_immutable BEFORE INSERT OR UPDATE OR DELETE ON public.owner_recovery_verifications
FOR EACH ROW EXECUTE FUNCTION public.guard_owner_recovery_verification();

-- Only the recovery finalizer can move an identity out of its non-authenticating pending state.
CREATE OR REPLACE FUNCTION public.guard_user_identity_link_write() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'IDENTITY_UNLINK_REQUIRES_SEPARATE_AUTHORIZED_PROCESS'; END IF;
  IF TG_OP='INSERT' THEN
    IF current_user='dbp_identity_link_owner' AND NEW.status='ACTIVE' AND NEW."ownerRecoveryOperationId" IS NULL THEN RETURN NEW; END IF;
    IF current_user='dbp_owner_recovery_owner' AND NEW.status='PENDING_OWNER_RECOVERY' AND NEW."ownerRecoveryOperationId" IS NOT NULL THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'IDENTITY_INSERT_FORBIDDEN';
  END IF;
  IF current_user='dbp_owner_recovery_owner' AND
    (NEW.id,NEW."userId",NEW.issuer,NEW.subject,NEW.email,NEW."emailVerified",NEW."ownerRecoveryOperationId",NEW."createdAt") IS NOT DISTINCT FROM
    (OLD.id,OLD."userId",OLD.issuer,OLD.subject,OLD.email,OLD."emailVerified",OLD."ownerRecoveryOperationId",OLD."createdAt") AND
    OLD.status='PENDING_OWNER_RECOVERY' AND NEW.status IN ('ACTIVE','OWNER_RECOVERY_FAILED') THEN RETURN NEW; END IF;
  RAISE EXCEPTION 'IDENTITY_MAPPING_IS_IMMUTABLE';
END; $$;

-- Reuse the platform-owner security boundary to lock authoritative owner rows.
-- Recovery does not receive direct UPDATE privileges over initialization/designation.
CREATE FUNCTION public.lock_active_platform_owner()
RETURNS TABLE(designation_id UUID,platform_user_id UUID)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
  RETURN QUERY SELECT d.id,d."platformUserId" FROM public.platform_initialization i
    JOIN public.platform_owner_designations d ON d.id=i."activeDesignationId" AND d.status='ACTIVE'
    JOIN public.platform_users u ON u.id=d."platformUserId" AND u.status='ACTIVE'
    WHERE i.id=1 AND i.state='INITIALIZED' FOR SHARE OF i,d,u;
END; $$;

CREATE FUNCTION public.issue_or_replace_owner_recovery_kit(
  p_platform_user_id UUID,p_issuer TEXT,p_subject TEXT,p_kit_id UUID,p_codes JSONB
) RETURNS TABLE(kit_id UUID,generation INTEGER,replaced BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_designation public.platform_owner_designations%ROWTYPE; v_identity public.user_identities%ROWTYPE;
        v_generation INTEGER; v_replaced BOOLEAN:=false; v_item JSONB; v_count INTEGER:=0;
BEGIN
  IF NOT pg_catalog.pg_has_role(session_user,'dbp_runtime','member') THEN RAISE EXCEPTION 'OWNER_SESSION_REQUIRED'; END IF;
  IF p_issuer IS NULL OR p_subject IS NULL OR length(p_issuer) NOT BETWEEN 1 AND 1000 OR length(p_subject) NOT BETWEEN 1 AND 1000 OR
    jsonb_typeof(p_codes) IS DISTINCT FROM 'array' OR jsonb_array_length(p_codes)<>10 THEN RAISE EXCEPTION 'INVALID_RECOVERY_KIT'; END IF;
  SELECT d.* INTO v_designation FROM public.lock_active_platform_owner() active
    JOIN public.platform_owner_designations d ON d.id=active.designation_id
    WHERE active.platform_user_id=p_platform_user_id;
  IF NOT FOUND OR public.resolve_active_platform_owner(p_platform_user_id) IS DISTINCT FROM v_designation.id THEN
    RAISE EXCEPTION 'ACTIVE_PLATFORM_OWNER_REQUIRED';
  END IF;
  IF EXISTS(SELECT 1 FROM public.owner_recovery_operations WHERE "designationId"=v_designation.id AND
    status IN ('INITIATED','CHALLENGE_PREPARED','OIDC_PROOF_VERIFIED','PREPARED','AWAITING_ARCHIVE','READY_TO_FINALIZE','RECONCILIATION_REQUIRED')) THEN
    RAISE EXCEPTION 'OWNER_RECOVERY_ALREADY_OPEN';
  END IF;
  SELECT ui.* INTO v_identity FROM public.user_identities ui WHERE ui."userId"=p_platform_user_id AND ui.issuer=p_issuer AND ui.subject=p_subject
    AND ui.status='ACTIVE' AND (EXISTS(SELECT 1 FROM public.user_identity_verifications v WHERE v."userIdentityId"=ui.id)
      OR EXISTS(SELECT 1 FROM public.owner_recovery_verifications rv WHERE rv."userIdentityId"=ui.id AND rv."activatedAt" IS NOT NULL))
    FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'AUTHENTICATED_OWNER_IDENTITY_REQUIRED'; END IF;
  IF EXISTS(SELECT 1 FROM jsonb_array_elements(p_codes) e WHERE jsonb_typeof(e.value)<>'object' OR
    (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(e.value) key) IS DISTINCT FROM ARRAY['id','keyId','verifier']::TEXT[] OR
    (e.value->>'keyId') !~ '^[A-Za-z0-9._-]{1,100}$' OR (e.value->>'verifier') !~ '^[0-9a-f]{64}$' OR
    (e.value->>'id') !~ '^[0-9a-fA-F-]{36}$') THEN RAISE EXCEPTION 'INVALID_RECOVERY_KIT'; END IF;
  IF (SELECT count(DISTINCT e.value->>'id') FROM jsonb_array_elements(p_codes) e)<>10 OR
      (SELECT count(DISTINCT e.value->>'verifier') FROM jsonb_array_elements(p_codes) e)<>10 OR
      (SELECT count(DISTINCT e.value->>'keyId') FROM jsonb_array_elements(p_codes) e)<>1 THEN RAISE EXCEPTION 'INVALID_RECOVERY_KIT'; END IF;

  SELECT coalesce(max(k.generation),0)+1 INTO v_generation FROM public.owner_recovery_kits k WHERE k."designationId"=v_designation.id;
  UPDATE public.owner_recovery_kits SET status='REPLACED',"replacedAt"=clock_timestamp()
    WHERE "designationId"=v_designation.id AND status='ACTIVE';
  v_replaced:=FOUND;
  UPDATE public.owner_recovery_codes SET status='REVOKED'
    WHERE "kitId" IN (SELECT id FROM public.owner_recovery_kits WHERE "designationId"=v_designation.id AND status='REPLACED') AND status='UNUSED';
  INSERT INTO public.owner_recovery_kits(id,"designationId","platformUserId","authenticatedIdentityId","authenticatedIssuer","authenticatedSubject",generation)
    VALUES(p_kit_id,v_designation.id,p_platform_user_id,v_identity.id,p_issuer,p_subject,v_generation);
  FOR v_item IN SELECT value FROM jsonb_array_elements(p_codes) LOOP
    INSERT INTO public.owner_recovery_codes(id,"kitId","verifierKeyId",verifier)
      VALUES((v_item->>'id')::UUID,p_kit_id,v_item->>'keyId',decode(v_item->>'verifier','hex'));
    v_count:=v_count+1;
  END LOOP;
  IF v_count<>10 OR (SELECT count(*) FROM public.owner_recovery_codes WHERE "kitId"=p_kit_id)<>10 THEN RAISE EXCEPTION 'RECOVERY_KIT_INCOMPLETE'; END IF;
  PERFORM public.append_authorization_audit(jsonb_build_object(
    'eventType',CASE WHEN v_replaced THEN 'owner-recovery-kit-replaced' ELSE 'owner-recovery-kit-issued' END,
    'actorType','HUMAN','actorId',p_platform_user_id::text,'targetType','platform-owner-designation','targetId',v_designation.id::text,
    'operation',CASE WHEN v_replaced THEN 'replace-recovery-kit' ELSE 'issue-recovery-kit' END,
    'outcome',CASE WHEN v_replaced THEN 'replaced' ELSE 'issued' END,'correlationId',p_kit_id::text));
  RETURN QUERY SELECT p_kit_id,v_generation,v_replaced;
END; $$;

CREATE FUNCTION public.begin_platform_owner_recovery(
  p_operation_id UUID,p_expected_issuer TEXT,p_verifier_candidates JSONB
) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_designation public.platform_owner_designations%ROWTYPE; v_user public.platform_users%ROWTYPE;
        v_kit public.owner_recovery_kits%ROWTYPE; v_code public.owner_recovery_codes%ROWTYPE;
        v_candidate JSONB; v_match UUID; v_matches INTEGER:=0; v_match_status public."OwnerRecoveryCodeStatus";
        v_existing public.owner_recovery_operations%ROWTYPE;
BEGIN
  IF NOT pg_catalog.pg_has_role(session_user,'dbp_owner_recovery_operator','member') THEN RAISE EXCEPTION 'OWNER_RECOVERY_OPERATOR_REQUIRED'; END IF;
  IF p_expected_issuer IS NULL OR length(p_expected_issuer) NOT BETWEEN 1 AND 1000 OR jsonb_typeof(p_verifier_candidates) IS DISTINCT FROM 'array' OR
    jsonb_array_length(p_verifier_candidates)<1 OR jsonb_array_length(p_verifier_candidates)>16 OR
    EXISTS(SELECT 1 FROM jsonb_array_elements(p_verifier_candidates) c WHERE jsonb_typeof(c.value)<>'object' OR
      (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(c.value) key) IS DISTINCT FROM ARRAY['keyId','verifier']::TEXT[] OR
      (c.value->>'keyId') !~ '^[A-Za-z0-9._-]{1,100}$' OR (c.value->>'verifier') !~ '^[0-9a-f]{64}$') THEN RAISE EXCEPTION 'INVALID_RECOVERY_REQUEST'; END IF;
  SELECT d.* INTO v_designation FROM public.lock_active_platform_owner() active
    JOIN public.platform_owner_designations d ON d.id=active.designation_id;
  IF NOT FOUND THEN RETURN NULL; END IF;
  SELECT k.* INTO v_kit FROM public.owner_recovery_kits k WHERE k."designationId"=v_designation.id AND k.status='ACTIVE' FOR UPDATE;
  IF NOT FOUND THEN RETURN NULL; END IF;
  FOR v_code IN SELECT c.* FROM public.owner_recovery_codes c WHERE c."kitId"=v_kit.id AND c.status IN ('UNUSED','CONSUMED') ORDER BY c.id FOR UPDATE LOOP
    FOR v_candidate IN SELECT value FROM jsonb_array_elements(p_verifier_candidates) LOOP
      IF v_code."verifierKeyId"=v_candidate->>'keyId' AND
        public.constant_time_bytea_equal(v_code.verifier,decode(v_candidate->>'verifier','hex')) THEN
        v_match:=v_code.id; v_match_status:=v_code.status; v_matches:=v_matches+1;
      END IF;
    END LOOP;
  END LOOP;
  IF v_matches<>1 THEN
    PERFORM public.append_authorization_audit(jsonb_build_object(
      'eventType','owner-recovery-code-verification','actorType','SYSTEM','actorId',session_user,
      'targetType','platform-owner-designation','targetId',v_designation.id::text,'operation','verify-recovery-code',
      'outcome','invalid_recovery_code','decision','DENY','decisionReasonCode','invalid_recovery_code','correlationId',p_operation_id::text));
    RETURN NULL;
  END IF;
  IF v_match_status='CONSUMED' THEN
    SELECT * INTO v_existing FROM public.owner_recovery_operations WHERE id=(SELECT "usedByRecoveryOperationId" FROM public.owner_recovery_codes WHERE id=v_match)
      AND "designationId"=v_designation.id AND "expectedIssuer"=p_expected_issuer
      AND status IN ('INITIATED','CHALLENGE_PREPARED','OIDC_PROOF_VERIFIED','PREPARED','AWAITING_ARCHIVE','READY_TO_FINALIZE','RECONCILIATION_REQUIRED') FOR UPDATE;
    IF FOUND THEN
      PERFORM public.append_authorization_audit(jsonb_build_object('eventType','owner-recovery-resumed','actorType','SYSTEM','actorId',session_user,
        'targetType','platform-owner-recovery','targetId',v_existing.id::text,'operation','resume-recovery','outcome','existing_operation',
        'correlationId',v_existing.id::text));
      RETURN v_existing.id;
    END IF;
    PERFORM public.append_authorization_audit(jsonb_build_object('eventType','owner-recovery-code-verification','actorType','SYSTEM','actorId',session_user,
      'targetType','platform-owner-designation','targetId',v_designation.id::text,'operation','verify-recovery-code','outcome','recovery_code_replayed',
      'decision','DENY','decisionReasonCode','recovery_code_replayed','correlationId',p_operation_id::text));
    RETURN NULL;
  END IF;
  SELECT * INTO v_existing FROM public.owner_recovery_operations WHERE "designationId"=v_designation.id
    AND status IN ('INITIATED','CHALLENGE_PREPARED','OIDC_PROOF_VERIFIED','PREPARED','AWAITING_ARCHIVE','READY_TO_FINALIZE','RECONCILIATION_REQUIRED') FOR UPDATE;
  IF FOUND THEN
    PERFORM public.append_authorization_audit(jsonb_build_object(
      'eventType','owner-recovery-initiation-rejected','actorType','SYSTEM','actorId',session_user,
      'targetType','platform-owner-designation','targetId',v_designation.id::text,'operation','begin-recovery',
      'outcome','recovery_already_open','decision','DENY','decisionReasonCode','recovery_already_open','correlationId',p_operation_id::text));
    RETURN NULL;
  END IF;
  INSERT INTO public.owner_recovery_operations(id,"designationId","platformUserId","recoveryCodeId","expectedIssuer","expiresAt")
    VALUES(p_operation_id,v_designation.id,v_designation."platformUserId",v_match,p_expected_issuer,clock_timestamp()+interval '5 minutes');
  UPDATE public.owner_recovery_codes SET status='CONSUMED',"consumedAt"=clock_timestamp(),"usedByRecoveryOperationId"=p_operation_id WHERE id=v_match AND status='UNUSED';
  IF NOT FOUND THEN RAISE EXCEPTION 'RECOVERY_CODE_ALREADY_USED'; END IF;
  PERFORM public.append_authorization_audit(jsonb_build_object(
    'eventType','owner-recovery-initiated','actorType','SYSTEM','actorId',session_user,
    'targetType','platform-owner-designation','targetId',v_designation.id::text,'operation','begin-recovery',
    'outcome','code_accepted','correlationId',p_operation_id::text));
  PERFORM public.append_authorization_audit(jsonb_build_object(
    'eventType','owner-recovery-code-verification','actorType','SYSTEM','actorId',session_user,
    'targetType','platform-owner-designation','targetId',v_designation.id::text,'operation','verify-recovery-code',
    'outcome','valid_recovery_code','correlationId',p_operation_id::text));
  PERFORM public.append_authorization_audit(jsonb_build_object(
    'eventType','owner-recovery-code-consumed','actorType','SYSTEM','actorId',session_user,
    'targetType','platform-owner-designation','targetId',v_designation.id::text,'operation','consume-recovery-code',
    'outcome','consumed','correlationId',p_operation_id::text));
  RETURN p_operation_id;
END; $$;

CREATE FUNCTION public.mark_platform_owner_recovery_challenge_prepared(p_operation_id UUID) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_recovery public.owner_recovery_operations%ROWTYPE;
BEGIN
  IF NOT pg_catalog.pg_has_role(session_user,'dbp_owner_recovery_operator','member') THEN RAISE EXCEPTION 'OWNER_RECOVERY_OPERATOR_REQUIRED'; END IF;
  SELECT * INTO v_recovery FROM public.owner_recovery_operations WHERE id=p_operation_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'RECOVERY_OPERATION_NOT_FOUND'; END IF;
  IF v_recovery.status='CHALLENGE_PREPARED' THEN RETURN; END IF;
  IF v_recovery.status<>'INITIATED' OR v_recovery."expiresAt"<=clock_timestamp() THEN RAISE EXCEPTION 'RECOVERY_CHALLENGE_EXPIRED'; END IF;
  UPDATE public.owner_recovery_operations SET status='CHALLENGE_PREPARED',"challengePreparedAt"=clock_timestamp() WHERE id=p_operation_id;
  PERFORM public.append_authorization_audit(jsonb_build_object(
    'eventType','owner-recovery-challenge-prepared','actorType','SYSTEM','actorId',session_user,
    'targetType','platform-owner-recovery','targetId',p_operation_id::text,'operation','prepare-challenge',
    'outcome','challenge_prepared','correlationId',p_operation_id::text));
END; $$;

CREATE FUNCTION public.complete_platform_owner_recovery(
  p_operation_id UUID,p_issuer TEXT,p_subject TEXT,p_verified_at TIMESTAMPTZ,p_pending_identity_id UUID
) RETURNS TEXT LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_recovery public.owner_recovery_operations%ROWTYPE; v_designation public.platform_owner_designations%ROWTYPE;
        v_user public.platform_users%ROWTYPE; v_identity_id UUID; v_now TIMESTAMPTZ:=clock_timestamp();
        v_operation_id UUID; v_idempotency BYTEA; v_fingerprint BYTEA; v_canonical TEXT;
BEGIN
  IF NOT pg_catalog.pg_has_role(session_user,'dbp_owner_recovery_callback','member') THEN RAISE EXCEPTION 'OWNER_RECOVERY_CALLBACK_REQUIRED'; END IF;
  SELECT * INTO v_recovery FROM public.owner_recovery_operations WHERE id=p_operation_id FOR UPDATE;
  IF NOT FOUND THEN RETURN 'REJECTED'; END IF;
  SELECT d.* INTO v_designation FROM public.lock_active_platform_owner() active
    JOIN public.platform_owner_designations d ON d.id=active.designation_id
    WHERE d.id=v_recovery."designationId" AND active.platform_user_id=v_recovery."platformUserId";
  IF NOT FOUND THEN
    IF v_recovery.status IN ('INITIATED','CHALLENGE_PREPARED') THEN
      UPDATE public.owner_recovery_operations SET status='FAILED',"failedAt"=clock_timestamp(),"outcomeCode"='owner_no_longer_active' WHERE id=p_operation_id;
      PERFORM public.append_authorization_audit(jsonb_build_object('eventType','owner-recovery-oidc-proof','actorType','SYSTEM','actorId',session_user,
        'targetType','platform-owner-recovery','targetId',p_operation_id::text,'operation','verify-new-identity','outcome','owner_no_longer_active',
        'decision','DENY','decisionReasonCode','owner_no_longer_active','correlationId',p_operation_id::text));
    END IF;
    RETURN 'REJECTED';
  END IF;
  IF v_recovery.status IN ('PREPARED','AWAITING_ARCHIVE','READY_TO_FINALIZE','FINALIZED') THEN RETURN v_recovery.status::text; END IF;
  IF v_recovery.status<>'CHALLENGE_PREPARED' OR v_recovery."expiresAt"<=v_now THEN
    IF v_recovery.status IN ('INITIATED','CHALLENGE_PREPARED') THEN
      UPDATE public.owner_recovery_operations SET status='EXPIRED',"failedAt"=v_now,"outcomeCode"='challenge_expired' WHERE id=p_operation_id;
      PERFORM public.append_authorization_audit(jsonb_build_object('eventType','owner-recovery-expired','actorType','SYSTEM','actorId',session_user,
        'targetType','platform-owner-recovery','targetId',p_operation_id::text,'operation','expire-recovery','outcome','challenge_expired','correlationId',p_operation_id::text));
    END IF;
    RETURN 'REJECTED';
  END IF;
  SELECT * INTO v_user FROM public.platform_users WHERE id=v_recovery."platformUserId" FOR SHARE;
  IF v_designation.status<>'ACTIVE' OR v_designation."platformUserId"<>v_recovery."platformUserId" OR
    v_user.status<>'ACTIVE' OR p_issuer IS DISTINCT FROM v_recovery."expectedIssuer" OR
    p_subject IS NULL OR length(p_subject) NOT BETWEEN 1 AND 1000 OR p_verified_at IS NULL OR
    p_verified_at<v_now-interval '5 minutes' OR p_verified_at>v_now+interval '1 minute' THEN
    UPDATE public.owner_recovery_operations SET status='FAILED',"failedAt"=v_now,"outcomeCode"='oidc_proof_rejected' WHERE id=p_operation_id;
    PERFORM public.append_authorization_audit(jsonb_build_object('eventType','owner-recovery-oidc-proof','actorType','SYSTEM','actorId',session_user,
      'targetType','platform-owner-recovery','targetId',p_operation_id::text,'operation','verify-new-identity','outcome','proof_rejected',
      'decision','DENY','decisionReasonCode','oidc_proof_rejected','correlationId',p_operation_id::text));
    RETURN 'REJECTED';
  END IF;
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_issuer||chr(31)||p_subject,3));
  IF EXISTS(SELECT 1 FROM public.user_identities WHERE issuer=p_issuer AND subject=p_subject) THEN
    UPDATE public.owner_recovery_operations SET status='FAILED',"failedAt"=v_now,"outcomeCode"='identity_conflict' WHERE id=p_operation_id;
    PERFORM public.append_authorization_audit(jsonb_build_object('eventType','owner-recovery-identity-conflict','actorType','SYSTEM','actorId',session_user,
      'targetType','platform-owner-recovery','targetId',p_operation_id::text,'operation','verify-new-identity','outcome','identity_already_claimed',
      'decision','DENY','decisionReasonCode','identity_conflict','correlationId',p_operation_id::text));
    RETURN 'REJECTED';
  END IF;
  UPDATE public.owner_recovery_operations SET status='OIDC_PROOF_VERIFIED',"proofVerifiedAt"=v_now WHERE id=p_operation_id;
  PERFORM public.append_authorization_audit(jsonb_build_object('eventType','owner-recovery-oidc-proof','actorType','SYSTEM','actorId',session_user,
    'targetType','platform-owner-recovery','targetId',p_operation_id::text,'operation','verify-new-identity','outcome','proof_verified',
    'correlationId',p_operation_id::text));
  INSERT INTO public.user_identities(id,"userId",issuer,subject,email,"emailVerified",status,"ownerRecoveryOperationId","createdAt","updatedAt")
    VALUES(p_pending_identity_id,v_recovery."platformUserId",p_issuer,p_subject,NULL,false,'PENDING_OWNER_RECOVERY',p_operation_id,v_now,v_now)
    RETURNING id INTO v_identity_id;
  INSERT INTO public.owner_recovery_verifications(id,"recoveryOperationId","userIdentityId","platformUserId",issuer,subject,"proofMethod","verifiedAt")
    VALUES(pg_catalog.gen_random_uuid(),p_operation_id,v_identity_id,v_recovery."platformUserId",p_issuer,p_subject,
      'OIDC_AUTHORIZATION_CODE_PKCE_FRESH_AUTH',p_verified_at);
  PERFORM public.append_authorization_audit(jsonb_build_object('eventType','owner-recovery-pending-identity-created','actorType','SYSTEM','actorId',session_user,
    'targetType','platform-user','targetId',v_recovery."platformUserId"::text,'operation','create-pending-identity','outcome','pending',
    'correlationId',p_operation_id::text));
  v_canonical:=format('{"platformUserId":"%s","recoveryOperationId":"%s"}',v_recovery."platformUserId",p_operation_id);
  v_idempotency:=public.digest(convert_to('DBP-CRITICAL-IDEMPOTENCY-v1','UTF8')||decode('00','hex')||convert_to('owner-recovery:'||p_operation_id::text,'UTF8'),'sha256');
  v_fingerprint:=public.digest(convert_to('DBP-CRITICAL-REQUEST-v1','UTF8')||decode('00','hex')||convert_to(v_canonical,'UTF8'),'sha256');
  v_operation_id:=public.prepare_critical_operation('platform.owner.recovery','PLATFORM_OWNER_RECOVERY',p_operation_id::text,v_idempotency,v_fingerprint,'owner-recovery');
  UPDATE public.owner_recovery_operations SET status='PREPARED',"preparedAt"=v_now,"criticalOperationId"=v_operation_id WHERE id=p_operation_id;
  PERFORM public.append_authorization_audit(jsonb_build_object('eventType','owner-recovery-critical-operation-prepared','actorType','SYSTEM','actorId','owner-recovery',
    'targetType','platform-owner-recovery','targetId',p_operation_id::text,'operation','prepare-critical-operation','outcome','prepared',
    'correlationId',v_operation_id::text));
  RETURN 'PREPARED';
END; $$;

CREATE FUNCTION public.reject_platform_owner_recovery(p_operation_id UUID,p_outcome_code TEXT) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_recovery public.owner_recovery_operations%ROWTYPE; v_now TIMESTAMPTZ:=clock_timestamp();
BEGIN
  IF NOT pg_catalog.pg_has_role(session_user,'dbp_owner_recovery_callback','member') THEN RAISE EXCEPTION 'OWNER_RECOVERY_CALLBACK_REQUIRED'; END IF;
  IF p_outcome_code IS NULL OR p_outcome_code !~ '^[a-z0-9_]{1,100}$' THEN RAISE EXCEPTION 'INVALID_RECOVERY_OUTCOME'; END IF;
  SELECT * INTO v_recovery FROM public.owner_recovery_operations WHERE id=p_operation_id FOR UPDATE;
  IF NOT FOUND OR v_recovery.status IN ('FINALIZED','FAILED','EXPIRED','PREPARED','AWAITING_ARCHIVE','READY_TO_FINALIZE','RECONCILIATION_REQUIRED') THEN RETURN; END IF;
  UPDATE public.owner_recovery_operations SET status='FAILED',"failedAt"=v_now,"outcomeCode"=p_outcome_code WHERE id=p_operation_id;
  PERFORM public.append_authorization_audit(jsonb_build_object('eventType','owner-recovery-failed','actorType','SYSTEM','actorId',session_user,
    'targetType','platform-owner-recovery','targetId',p_operation_id::text,'operation','fail-recovery','outcome',p_outcome_code,
    'decision','DENY','decisionReasonCode',p_outcome_code,'correlationId',p_operation_id::text));
END; $$;

CREATE FUNCTION public.get_platform_owner_recovery_status(p_operation_id UUID)
RETURNS TABLE(recovery_status TEXT,critical_status TEXT,outcome_code TEXT,critical_operation_id UUID)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
  IF NOT pg_catalog.pg_has_role(session_user,'dbp_owner_recovery_operator','member') THEN RAISE EXCEPTION 'OWNER_RECOVERY_OPERATOR_REQUIRED'; END IF;
  RETURN QUERY SELECT r.status::text,op.status::text,r."outcomeCode"::text,op.id FROM public.owner_recovery_operations r
    LEFT JOIN public.critical_operations op ON op.id=r."criticalOperationId" WHERE r.id=p_operation_id;
END; $$;

CREATE FUNCTION public.expire_platform_owner_recoveries(p_limit INTEGER DEFAULT 100) RETURNS INTEGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_recovery RECORD; v_count INTEGER:=0;
BEGIN
  IF NOT pg_catalog.pg_has_role(session_user,'dbp_critical_operation_service','member') THEN RAISE EXCEPTION 'CRITICAL_OPERATION_SERVICE_REQUIRED'; END IF;
  IF p_limit<1 OR p_limit>1000 THEN RAISE EXCEPTION 'INVALID_LIMIT'; END IF;
  FOR v_recovery IN SELECT id,"designationId" FROM public.owner_recovery_operations
    WHERE status IN ('INITIATED','CHALLENGE_PREPARED') AND "expiresAt"<=clock_timestamp()
    ORDER BY "expiresAt" FOR UPDATE SKIP LOCKED LIMIT p_limit LOOP
    UPDATE public.owner_recovery_operations SET status='EXPIRED',"failedAt"=clock_timestamp(),"outcomeCode"='challenge_expired' WHERE id=v_recovery.id;
    PERFORM public.append_authorization_audit(jsonb_build_object('eventType','owner-recovery-expired','actorType','SYSTEM','actorId','critical-operation-worker',
      'targetType','platform-owner-recovery','targetId',v_recovery.id::text,'operation','expire-recovery','outcome','challenge_expired',
      'correlationId',v_recovery.id::text));
    v_count:=v_count+1;
  END LOOP;
  RETURN v_count;
END; $$;

CREATE FUNCTION public.advance_owner_recovery_with_critical_operation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_recovery public.owner_recovery_operations%ROWTYPE; v_event_type TEXT; v_outcome TEXT; v_next public."OwnerRecoveryStatus";
BEGIN
  IF NEW."targetType"<>'PLATFORM_OWNER_RECOVERY' THEN RETURN NEW; END IF;
  IF NEW."targetId" !~ '^[0-9a-fA-F-]{36}$' THEN RAISE EXCEPTION 'RECOVERY_OPERATION_BINDING_REQUIRED'; END IF;
  IF NOT pg_catalog.pg_has_role(session_user,'dbp_critical_operation_service','member') THEN RAISE EXCEPTION 'CRITICAL_OPERATION_SERVICE_REQUIRED'; END IF;
  SELECT * INTO v_recovery FROM public.owner_recovery_operations WHERE id=NEW."targetId"::UUID FOR UPDATE;
  IF NOT FOUND OR v_recovery."criticalOperationId" IS DISTINCT FROM NEW.id THEN RAISE EXCEPTION 'RECOVERY_OPERATION_BINDING_REQUIRED'; END IF;
  IF NEW.status='AWAITING_ARCHIVE' AND OLD.status='PREPARED' AND v_recovery.status='PREPARED' THEN
    v_next:='AWAITING_ARCHIVE'; v_event_type:='owner-recovery-awaiting-archive'; v_outcome:='awaiting_archive';
    UPDATE public.owner_recovery_operations SET status=v_next WHERE id=v_recovery.id;
  ELSIF NEW.status='READY_TO_ACTIVATE' AND OLD.status='AWAITING_ARCHIVE' AND v_recovery.status='AWAITING_ARCHIVE' THEN
    IF NOT EXISTS(SELECT 1 FROM public.critical_operation_receipt(NEW.id)) THEN RAISE EXCEPTION 'RECOVERY_ARCHIVE_RECEIPT_REQUIRED'; END IF;
    v_next:='READY_TO_FINALIZE'; v_event_type:='owner-recovery-archive-qualified'; v_outcome:='receipt_verified';
    UPDATE public.owner_recovery_operations SET status=v_next,"archiveQualifiedAt"=clock_timestamp() WHERE id=v_recovery.id;
  ELSIF NEW.status='RECONCILIATION_REQUIRED' AND OLD.status<>'RECONCILIATION_REQUIRED' AND v_recovery.status NOT IN ('FINALIZED','FAILED','EXPIRED') THEN
    v_next:='RECONCILIATION_REQUIRED'; v_event_type:='owner-recovery-reconciliation-required'; v_outcome:='manual_reconciliation';
    UPDATE public.owner_recovery_operations SET status=v_next,"outcomeCode"='manual_reconciliation' WHERE id=v_recovery.id;
  ELSIF NEW.status='FAILED' AND OLD.status<>'FAILED' AND v_recovery.status='RECONCILIATION_REQUIRED' THEN
    v_next:='FAILED'; v_event_type:='owner-recovery-failed'; v_outcome:='critical_operation_failed';
    UPDATE public.owner_recovery_operations SET status=v_next,"failedAt"=clock_timestamp(),"outcomeCode"=v_outcome WHERE id=v_recovery.id;
    UPDATE public.user_identities SET status='OWNER_RECOVERY_FAILED',"updatedAt"=clock_timestamp()
      WHERE "ownerRecoveryOperationId"=v_recovery.id AND status='PENDING_OWNER_RECOVERY';
  ELSE RETURN NEW;
  END IF;
  PERFORM public.append_authorization_audit(jsonb_build_object('eventType',v_event_type,'actorType','SYSTEM','actorId','critical-operation-worker',
    'targetType','platform-owner-recovery','targetId',v_recovery.id::text,'operation','critical-operation-transition','outcome',v_outcome,
    'correlationId',NEW.id::text));
  RETURN NEW;
END; $$;
CREATE TRIGGER critical_operation_owner_recovery_state AFTER UPDATE OF status ON public.critical_operations
FOR EACH ROW EXECUTE FUNCTION public.advance_owner_recovery_with_critical_operation();

CREATE FUNCTION public.finalize_platform_owner_recovery_from_gate() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_op public.critical_operations%ROWTYPE; v_recovery public.owner_recovery_operations%ROWTYPE;
        v_designation public.platform_owner_designations%ROWTYPE; v_user public.platform_users%ROWTYPE;
        v_identity public.user_identities%ROWTYPE; v_receipt RECORD;
BEGIN
  IF NEW."targetType"<>'PLATFORM_OWNER_RECOVERY' OR NEW.state<>'ACTIVE' OR OLD.state=NEW.state THEN RETURN NEW; END IF;
  IF NEW."targetId" !~ '^[0-9a-fA-F-]{36}$' THEN RAISE EXCEPTION 'RECOVERY_OPERATION_BINDING_REQUIRED'; END IF;
  IF NOT pg_catalog.pg_has_role(session_user,'dbp_critical_operation_service','member') THEN RAISE EXCEPTION 'CRITICAL_OPERATION_SERVICE_REQUIRED'; END IF;
  SELECT * INTO v_op FROM public.critical_operations WHERE id=NEW."operationId";
  IF NOT FOUND OR v_op."operationType"<>'platform.owner.recovery' OR v_op."targetId"<>NEW."targetId" OR
    v_op.status<>'READY_TO_ACTIVATE' THEN RAISE EXCEPTION 'RECOVERY_REQUIRES_READY_CRITICAL_OPERATION'; END IF;
  SELECT * INTO v_receipt FROM public.critical_operation_receipt(v_op.id);
  IF NOT FOUND THEN RAISE EXCEPTION 'RECOVERY_ARCHIVE_RECEIPT_REQUIRED'; END IF;
  SELECT * INTO v_recovery FROM public.owner_recovery_operations WHERE id=NEW."targetId"::UUID FOR UPDATE;
  IF NOT FOUND OR v_recovery."criticalOperationId"<>v_op.id OR v_recovery.status<>'READY_TO_FINALIZE' THEN
    RAISE EXCEPTION 'RECOVERY_OPERATION_NOT_READY';
  END IF;
  SELECT d.* INTO v_designation FROM public.lock_active_platform_owner() active
    JOIN public.platform_owner_designations d ON d.id=active.designation_id
    WHERE d.id=v_recovery."designationId" AND active.platform_user_id=v_recovery."platformUserId";
  IF NOT FOUND THEN RAISE EXCEPTION 'RECOVERY_OWNER_NO_LONGER_ACTIVE'; END IF;
  SELECT * INTO v_user FROM public.platform_users WHERE id=v_recovery."platformUserId" FOR SHARE;
  SELECT * INTO v_identity FROM public.user_identities WHERE "ownerRecoveryOperationId"=v_recovery.id FOR UPDATE;
  IF v_designation.status<>'ACTIVE' OR v_designation."platformUserId"<>v_recovery."platformUserId" OR v_user.status<>'ACTIVE' OR
    v_identity.status<>'PENDING_OWNER_RECOVERY' OR v_identity."userId"<>v_recovery."platformUserId" OR
    v_identity.issuer<>v_recovery."expectedIssuer" OR NOT EXISTS(SELECT 1 FROM public.owner_recovery_verifications ver
      WHERE ver."recoveryOperationId"=v_recovery.id AND ver."userIdentityId"=v_identity.id AND ver."activatedAt" IS NULL) THEN
    RAISE EXCEPTION 'RECOVERY_IDENTITY_BINDING_INVALID';
  END IF;
  UPDATE public.user_identities SET status='ACTIVE',"updatedAt"=clock_timestamp() WHERE id=v_identity.id;
  UPDATE public.owner_recovery_verifications SET "activatedAt"=clock_timestamp() WHERE "recoveryOperationId"=v_recovery.id AND "activatedAt" IS NULL;
  UPDATE public.owner_recovery_operations SET status='FINALIZED',"finalizedAt"=clock_timestamp() WHERE id=v_recovery.id;
  PERFORM public.append_authorization_audit(jsonb_build_object('eventType','owner-recovery-finalized','actorType','SYSTEM','actorId','critical-operation-finalizer',
    'targetType','platform-user','targetId',v_recovery."platformUserId"::text,'operation','finalize-owner-recovery','outcome','identity_activated',
    'correlationId',v_recovery.id::text,'jobId',v_receipt.receipt_id::text));
  RETURN NEW;
END; $$;
CREATE TRIGGER critical_gate_finalize_owner_recovery AFTER UPDATE OF state ON public.critical_operation_gates
FOR EACH ROW EXECUTE FUNCTION public.finalize_platform_owner_recovery_from_gate();

ALTER FUNCTION public.guard_owner_recovery_kit() OWNER TO dbp_owner_recovery_owner;
ALTER FUNCTION public.guard_owner_recovery_code() OWNER TO dbp_owner_recovery_owner;
ALTER FUNCTION public.guard_owner_recovery_operation() OWNER TO dbp_owner_recovery_owner;
ALTER FUNCTION public.guard_owner_recovery_verification() OWNER TO dbp_owner_recovery_owner;
ALTER FUNCTION public.guard_user_identity_link_write() OWNER TO dbp_identity_link_owner;
ALTER FUNCTION public.lock_active_platform_owner() OWNER TO dbp_platform_owner_owner;
ALTER FUNCTION public.issue_or_replace_owner_recovery_kit(UUID,TEXT,TEXT,UUID,JSONB) OWNER TO dbp_owner_recovery_owner;
ALTER FUNCTION public.begin_platform_owner_recovery(UUID,TEXT,JSONB) OWNER TO dbp_owner_recovery_owner;
ALTER FUNCTION public.mark_platform_owner_recovery_challenge_prepared(UUID) OWNER TO dbp_owner_recovery_owner;
ALTER FUNCTION public.complete_platform_owner_recovery(UUID,TEXT,TEXT,TIMESTAMPTZ,UUID) OWNER TO dbp_owner_recovery_owner;
ALTER FUNCTION public.reject_platform_owner_recovery(UUID,TEXT) OWNER TO dbp_owner_recovery_owner;
ALTER FUNCTION public.get_platform_owner_recovery_status(UUID) OWNER TO dbp_owner_recovery_owner;
ALTER FUNCTION public.expire_platform_owner_recoveries(INTEGER) OWNER TO dbp_owner_recovery_owner;
ALTER FUNCTION public.advance_owner_recovery_with_critical_operation() OWNER TO dbp_owner_recovery_owner;
ALTER FUNCTION public.finalize_platform_owner_recovery_from_gate() OWNER TO dbp_owner_recovery_owner;

REVOKE ALL ON FUNCTION public.guard_owner_recovery_kit(),public.guard_owner_recovery_code(),public.guard_owner_recovery_operation(),
  public.guard_owner_recovery_verification(),public.advance_owner_recovery_with_critical_operation(),public.finalize_platform_owner_recovery_from_gate() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.issue_or_replace_owner_recovery_kit(UUID,TEXT,TEXT,UUID,JSONB),
  public.begin_platform_owner_recovery(UUID,TEXT,JSONB),public.mark_platform_owner_recovery_challenge_prepared(UUID),
  public.complete_platform_owner_recovery(UUID,TEXT,TEXT,TIMESTAMPTZ,UUID),public.reject_platform_owner_recovery(UUID,TEXT),
  public.get_platform_owner_recovery_status(UUID),public.expire_platform_owner_recoveries(INTEGER),
  public.lock_active_platform_owner() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.issue_or_replace_owner_recovery_kit(UUID,TEXT,TEXT,UUID,JSONB) TO dbp_runtime;
GRANT EXECUTE ON FUNCTION public.lock_active_platform_owner() TO dbp_owner_recovery_owner;
GRANT EXECUTE ON FUNCTION public.begin_platform_owner_recovery(UUID,TEXT,JSONB),public.mark_platform_owner_recovery_challenge_prepared(UUID),
  public.get_platform_owner_recovery_status(UUID) TO dbp_owner_recovery_operator;
GRANT EXECUTE ON FUNCTION public.complete_platform_owner_recovery(UUID,TEXT,TEXT,TIMESTAMPTZ,UUID),
  public.reject_platform_owner_recovery(UUID,TEXT) TO dbp_owner_recovery_callback;
GRANT EXECUTE ON FUNCTION public.expire_platform_owner_recoveries(INTEGER) TO dbp_critical_operation_service;
COMMIT;
