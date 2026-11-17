BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='dbp_platform_owner_owner') THEN CREATE ROLE dbp_platform_owner_owner NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='dbp_platform_owner_operator') THEN CREATE ROLE dbp_platform_owner_operator NOLOGIN; END IF;
END $$;

CREATE TYPE public."PlatformOwnerDesignationStatus" AS ENUM ('PENDING','ACTIVE','FAILED');
CREATE TYPE public."PlatformInitializationState" AS ENUM ('UNINITIALIZED','INITIALIZED');
CREATE TYPE public."OwnerBootstrapCredentialStatus" AS ENUM ('ACTIVE','CONSUMED','EXPIRED','REVOKED');

CREATE TABLE public.platform_initialization (
  id INTEGER PRIMARY KEY DEFAULT 1 CHECK(id=1),
  state public."PlatformInitializationState" NOT NULL DEFAULT 'UNINITIALIZED',
  "activeDesignationId" UUID UNIQUE,
  "initializedAt" TIMESTAMPTZ(6),
  CONSTRAINT platform_initialization_state_shape CHECK (
    (state='UNINITIALIZED' AND "activeDesignationId" IS NULL AND "initializedAt" IS NULL) OR
    (state='INITIALIZED' AND "activeDesignationId" IS NOT NULL AND "initializedAt" IS NOT NULL)
  )
);
INSERT INTO public.platform_initialization(id,state) VALUES(1,'UNINITIALIZED');

CREATE TABLE public.owner_bootstrap_credentials (
  id UUID PRIMARY KEY,
  "platformUserId" UUID NOT NULL REFERENCES public.platform_users(id) ON DELETE RESTRICT,
  "userIdentityId" UUID NOT NULL,
  "verifierKeyId" VARCHAR(100) NOT NULL,
  verifier BYTEA NOT NULL,
  status public."OwnerBootstrapCredentialStatus" NOT NULL DEFAULT 'ACTIVE',
  "issuedBy" VARCHAR(200) NOT NULL,
  "expiresAt" TIMESTAMPTZ(6) NOT NULL,
  "consumedAt" TIMESTAMPTZ(6),
  "operationId" UUID UNIQUE,
  "createdAt" TIMESTAMPTZ(6) NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT owner_bootstrap_credential_identity_fkey FOREIGN KEY("userIdentityId","platformUserId")
    REFERENCES public.user_identities(id,"userId") ON DELETE RESTRICT,
  CONSTRAINT owner_bootstrap_credential_verifier_length CHECK(octet_length(verifier)=32),
  CONSTRAINT owner_bootstrap_credential_key_id CHECK("verifierKeyId" ~ '^[A-Za-z0-9._-]{1,100}$'),
  CONSTRAINT owner_bootstrap_credential_issuer_valid CHECK(length("issuedBy") BETWEEN 1 AND 200),
  CONSTRAINT owner_bootstrap_credential_state_shape CHECK(
    (status='ACTIVE' AND "consumedAt" IS NULL AND "operationId" IS NULL) OR
    (status='CONSUMED' AND "consumedAt" IS NOT NULL AND "operationId" IS NOT NULL) OR
    (status IN ('EXPIRED','REVOKED') AND "operationId" IS NULL)
  )
);
CREATE UNIQUE INDEX owner_bootstrap_one_active_credential_idx ON public.owner_bootstrap_credentials((true)) WHERE status='ACTIVE';
CREATE INDEX owner_bootstrap_credentials_user_status_idx ON public.owner_bootstrap_credentials("platformUserId",status);

CREATE TABLE public.platform_owner_designations (
  id UUID PRIMARY KEY,
  "platformUserId" UUID NOT NULL REFERENCES public.platform_users(id) ON DELETE RESTRICT,
  "userIdentityId" UUID NOT NULL,
  "criticalOperationId" UUID NOT NULL UNIQUE REFERENCES public.critical_operations(id) ON DELETE RESTRICT,
  status public."PlatformOwnerDesignationStatus" NOT NULL DEFAULT 'PENDING',
  "preparedAt" TIMESTAMPTZ(6) NOT NULL,
  "activatedAt" TIMESTAMPTZ(6),
  CONSTRAINT platform_owner_designation_identity_fkey FOREIGN KEY("userIdentityId","platformUserId")
    REFERENCES public.user_identities(id,"userId") ON DELETE RESTRICT,
  CONSTRAINT platform_owner_designation_state_shape CHECK(
    (status IN ('PENDING','FAILED') AND "activatedAt" IS NULL) OR
    (status='ACTIVE' AND "activatedAt" IS NOT NULL)
  )
);
CREATE UNIQUE INDEX platform_owner_one_live_designation_idx ON public.platform_owner_designations ((true))
  WHERE status IN ('PENDING','ACTIVE');
CREATE INDEX platform_owner_designations_user_status_idx ON public.platform_owner_designations("platformUserId",status);
ALTER TABLE public.owner_bootstrap_credentials ADD CONSTRAINT owner_bootstrap_credential_operation_fkey
  FOREIGN KEY("operationId") REFERENCES public.critical_operations(id) ON DELETE RESTRICT;
ALTER TABLE public.platform_initialization ADD CONSTRAINT platform_initialization_designation_fkey
  FOREIGN KEY("activeDesignationId") REFERENCES public.platform_owner_designations(id) ON DELETE RESTRICT;

REVOKE ALL ON TYPE public."PlatformOwnerDesignationStatus",public."PlatformInitializationState",public."OwnerBootstrapCredentialStatus"
  FROM PUBLIC,dbp_runtime,dbp_audit_exporter,dbp_audit_receipt_verifier;
REVOKE ALL ON public.platform_initialization,public.owner_bootstrap_credentials,public.platform_owner_designations
  FROM PUBLIC,dbp_runtime,dbp_audit_exporter,dbp_audit_receipt_verifier,dbp_critical_operation_service,dbp_critical_operation_reconciler;
GRANT USAGE ON SCHEMA public TO dbp_platform_owner_owner,dbp_platform_owner_operator,dbp_runtime;
GRANT USAGE ON TYPE public."PlatformOwnerDesignationStatus",public."PlatformInitializationState",public."OwnerBootstrapCredentialStatus" TO dbp_platform_owner_owner;
GRANT SELECT ON public.platform_users,public.user_identities,public.user_identity_verifications,
  public.critical_operations,public.audit_archive_receipts,public.authorization_audit_events TO dbp_platform_owner_owner;
-- FOR SHARE checks require UPDATE privilege in PostgreSQL; the non-login owner role
-- needs only the status column to serialize eligibility checks against suspension.
GRANT UPDATE (status) ON public.platform_users TO dbp_platform_owner_owner;
GRANT SELECT,INSERT,UPDATE ON public.owner_bootstrap_credentials,public.platform_owner_designations,public.platform_initialization TO dbp_platform_owner_owner;
GRANT EXECUTE ON FUNCTION public.append_authorization_audit(JSONB,UUID),
  public.prepare_critical_operation(TEXT,TEXT,TEXT,BYTEA,BYTEA,TEXT),
  public.critical_operation_receipt(UUID) TO dbp_platform_owner_owner;
GRANT EXECUTE ON FUNCTION public.digest(BYTEA,TEXT) TO dbp_platform_owner_owner;

CREATE FUNCTION public.constant_time_bytea_equal(p_left BYTEA,p_right BYTEA) RETURNS BOOLEAN
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog,public AS $$
DECLARE v_diff INTEGER:=0; v_index INTEGER;
BEGIN
  IF octet_length(p_left)<>octet_length(p_right) THEN RETURN false; END IF;
  FOR v_index IN 0..octet_length(p_left)-1 LOOP
    v_diff:=v_diff | (pg_catalog.get_byte(p_left,v_index) # pg_catalog.get_byte(p_right,v_index));
  END LOOP;
  RETURN v_diff=0;
END; $$;

CREATE FUNCTION public.guard_platform_owner_credential() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF current_user<>'dbp_platform_owner_owner' THEN RAISE EXCEPTION 'OWNER_BOOTSTRAP_CREDENTIAL_WRITE_FORBIDDEN'; END IF;
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'OWNER_BOOTSTRAP_CREDENTIAL_HISTORY_IS_IMMUTABLE'; END IF;
  IF TG_OP='UPDATE' AND (
    (NEW.id,NEW."platformUserId",NEW."userIdentityId",NEW."verifierKeyId",NEW.verifier,NEW."issuedBy",NEW."expiresAt",NEW."createdAt") IS DISTINCT FROM
    (OLD.id,OLD."platformUserId",OLD."userIdentityId",OLD."verifierKeyId",OLD.verifier,OLD."issuedBy",OLD."expiresAt",OLD."createdAt") OR
    OLD.status<>'ACTIVE' OR NEW.status NOT IN ('CONSUMED','EXPIRED','REVOKED')
  ) THEN RAISE EXCEPTION 'INVALID_OWNER_BOOTSTRAP_CREDENTIAL_TRANSITION'; END IF;
  RETURN NEW;
END; $$;
CREATE TRIGGER owner_bootstrap_credentials_restricted_write BEFORE INSERT OR UPDATE OR DELETE ON public.owner_bootstrap_credentials
FOR EACH ROW EXECUTE FUNCTION public.guard_platform_owner_credential();

CREATE FUNCTION public.guard_platform_owner_designation() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE v_receipt RECORD; v_operation public.critical_operations%ROWTYPE;
BEGIN
  IF current_user<>'dbp_platform_owner_owner' THEN RAISE EXCEPTION 'OWNER_DESIGNATION_WRITE_FORBIDDEN'; END IF;
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'OWNER_DESIGNATION_HISTORY_IS_IMMUTABLE'; END IF;
  IF TG_OP='INSERT' THEN
    IF NEW.status<>'PENDING' OR NEW."activatedAt" IS NOT NULL THEN RAISE EXCEPTION 'OWNER_DESIGNATION_MUST_START_PENDING'; END IF;
    RETURN NEW;
  END IF;
  IF (NEW.id,NEW."platformUserId",NEW."userIdentityId",NEW."criticalOperationId",NEW."preparedAt") IS DISTINCT FROM
     (OLD.id,OLD."platformUserId",OLD."userIdentityId",OLD."criticalOperationId",OLD."preparedAt") OR OLD.status<>'PENDING'
     OR NEW.status NOT IN ('ACTIVE','FAILED') THEN RAISE EXCEPTION 'INVALID_OWNER_DESIGNATION_TRANSITION'; END IF;
  IF NEW.status='ACTIVE' THEN
    SELECT * INTO v_operation FROM public.critical_operations WHERE id=NEW."criticalOperationId";
    IF NOT FOUND OR v_operation."operationType"<>'platform.owner.bootstrap' OR v_operation.status<>'READY_TO_ACTIVATE'
       OR v_operation."targetType"<>'PLATFORM_OWNER_DESIGNATION' OR v_operation."targetId"<>NEW.id::text THEN
      RAISE EXCEPTION 'OWNER_ACTIVATION_REQUIRES_READY_CRITICAL_OPERATION';
    END IF;
    SELECT * INTO v_receipt FROM public.critical_operation_receipt(NEW."criticalOperationId");
    IF NOT FOUND THEN RAISE EXCEPTION 'OWNER_ACTIVATION_REQUIRES_ARCHIVE_RECEIPT'; END IF;
    IF NOT pg_catalog.pg_has_role(session_user,'dbp_critical_operation_service','member') THEN
      RAISE EXCEPTION 'OWNER_ACTIVATION_REQUIRES_CRITICAL_OPERATION_SERVICE';
    END IF;
  END IF;
  RETURN NEW;
END; $$;
CREATE TRIGGER platform_owner_designations_restricted_write BEFORE INSERT OR UPDATE OR DELETE ON public.platform_owner_designations
FOR EACH ROW EXECUTE FUNCTION public.guard_platform_owner_designation();

CREATE FUNCTION public.guard_platform_initialization() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE v_designation public.platform_owner_designations%ROWTYPE;
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PLATFORM_INITIALIZATION_CANNOT_BE_DELETED'; END IF;
  IF current_user<>'dbp_platform_owner_owner' THEN RAISE EXCEPTION 'PLATFORM_INITIALIZATION_WRITE_FORBIDDEN'; END IF;
  IF TG_OP='INSERT' THEN
    IF NEW.id<>1 OR NEW.state<>'UNINITIALIZED' OR NEW."activeDesignationId" IS NOT NULL OR NEW."initializedAt" IS NOT NULL THEN
      RAISE EXCEPTION 'INVALID_PLATFORM_INITIALIZATION_ROW';
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.state<>'UNINITIALIZED' OR NEW.state<>'INITIALIZED' OR NEW.id<>OLD.id OR NEW."initializedAt" IS NULL
     OR NEW."activeDesignationId" IS NULL THEN RAISE EXCEPTION 'PLATFORM_INITIALIZATION_CANNOT_BE_RESET'; END IF;
  SELECT * INTO v_designation FROM public.platform_owner_designations WHERE id=NEW."activeDesignationId" FOR SHARE;
  IF NOT FOUND OR v_designation.status<>'ACTIVE' THEN RAISE EXCEPTION 'ACTIVE_OWNER_DESIGNATION_REQUIRED'; END IF;
  RETURN NEW;
END; $$;
CREATE TRIGGER platform_initialization_restricted_write BEFORE INSERT OR UPDATE OR DELETE ON public.platform_initialization
FOR EACH ROW EXECUTE FUNCTION public.guard_platform_initialization();

CREATE FUNCTION public.activate_platform_owner_from_critical_gate() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_operation public.critical_operations%ROWTYPE; v_designation public.platform_owner_designations%ROWTYPE;
        v_initialization public.platform_initialization%ROWTYPE; v_receipt RECORD; v_user public.platform_users%ROWTYPE;
BEGIN
  IF NEW."targetType"<>'PLATFORM_OWNER_DESIGNATION' THEN RETURN NEW; END IF;
  SELECT * INTO v_operation FROM public.critical_operations WHERE id=NEW."operationId";
  IF NOT FOUND THEN RAISE EXCEPTION 'OWNER_CRITICAL_OPERATION_REQUIRED'; END IF;
  IF NEW.state='REVOKED' THEN RAISE EXCEPTION 'OWNER_REVOCATION_IS_OUT_OF_SCOPE'; END IF;
  IF v_operation."operationType"<>'platform.owner.bootstrap' THEN
    IF NEW.state='ACTIVE' THEN RAISE EXCEPTION 'OWNER_BOOTSTRAP_OPERATION_REQUIRED'; END IF;
    RETURN NEW;
  END IF;
  IF NEW.state='INACTIVE' AND OLD.state='PROPOSED' THEN
    UPDATE public.platform_owner_designations SET status='FAILED' WHERE id=NEW."targetId"::uuid
      AND "criticalOperationId"=v_operation.id AND status='PENDING';
    IF FOUND THEN
      PERFORM public.append_authorization_audit(jsonb_build_object(
        'eventType','platform-owner-bootstrap-failed','actorType','SYSTEM','actorId','critical-operation-failure',
        'targetType','platform-owner-designation','targetId',NEW."targetId",'operation','fail','outcome','critical_operation_failed',
        'correlationId',v_operation.id::text));
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.state<>'ACTIVE' OR OLD.state<>'PROPOSED' OR OLD."operationId"<>NEW."operationId"
     OR v_operation.status<>'READY_TO_ACTIVATE' THEN RAISE EXCEPTION 'INVALID_OWNER_GATE_TRANSITION'; END IF;
  IF NOT pg_catalog.pg_has_role(session_user,'dbp_critical_operation_service','member') THEN
    RAISE EXCEPTION 'OWNER_ACTIVATION_REQUIRES_CRITICAL_OPERATION_SERVICE';
  END IF;
  SELECT * INTO v_receipt FROM public.critical_operation_receipt(v_operation.id);
  IF NOT FOUND THEN RAISE EXCEPTION 'OWNER_ACTIVATION_REQUIRES_ARCHIVE_RECEIPT'; END IF;
  SELECT * INTO v_designation FROM public.platform_owner_designations
    WHERE id=NEW."targetId"::uuid AND "criticalOperationId"=v_operation.id AND status='PENDING' FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'PENDING_OWNER_DESIGNATION_REQUIRED'; END IF;
  SELECT * INTO v_initialization FROM public.platform_initialization WHERE id=1 FOR UPDATE;
  IF NOT FOUND OR v_initialization.state<>'UNINITIALIZED' THEN RAISE EXCEPTION 'PLATFORM_ALREADY_INITIALIZED'; END IF;
  SELECT * INTO v_user FROM public.platform_users WHERE id=v_designation."platformUserId" FOR SHARE;
  IF NOT FOUND OR v_user.status<>'ACTIVE' OR NOT EXISTS (
    SELECT 1 FROM public.user_identity_verifications ver
    WHERE ver."userIdentityId"=v_designation."userIdentityId" AND ver."platformUserId"=v_user.id
  ) THEN RAISE EXCEPTION 'VERIFIED_ACTIVE_OWNER_REQUIRED'; END IF;

  UPDATE public.platform_owner_designations SET status='ACTIVE',"activatedAt"=clock_timestamp() WHERE id=v_designation.id;
  UPDATE public.platform_initialization SET state='INITIALIZED',"activeDesignationId"=v_designation.id,"initializedAt"=clock_timestamp() WHERE id=1;
  PERFORM public.append_authorization_audit(jsonb_build_object(
    'eventType','platform-owner-designation-activated','actorType','SYSTEM','actorId','critical-operation-finalizer',
    'targetType','platform-owner-designation','targetId',v_designation.id::text,'operation','activate','outcome','receipt_confirmed',
    'correlationId',v_operation.id::text,'jobId',v_receipt.receipt_id::text));
  RETURN NEW;
END; $$;
CREATE TRIGGER critical_operation_owner_activation BEFORE UPDATE OF state ON public.critical_operation_gates
FOR EACH ROW WHEN (OLD.state IS DISTINCT FROM NEW.state) EXECUTE FUNCTION public.activate_platform_owner_from_critical_gate();

CREATE FUNCTION public.issue_platform_owner_bootstrap_credential(
  p_credential_id UUID,p_platform_user_id UUID,p_issuer TEXT,p_verifier_key_id TEXT,p_verifier BYTEA
) RETURNS TIMESTAMPTZ LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_identity public.user_identities%ROWTYPE; v_identity_count INTEGER; v_expires TIMESTAMPTZ;
BEGIN
  IF NOT pg_catalog.pg_has_role(session_user,'dbp_platform_owner_operator','member') THEN RAISE EXCEPTION 'PLATFORM_OWNER_OPERATOR_REQUIRED'; END IF;
  IF p_credential_id IS NULL OR p_issuer IS NULL OR p_verifier_key_id IS NULL OR p_verifier IS NULL OR octet_length(p_verifier)<>32
     OR p_verifier_key_id !~ '^[A-Za-z0-9._-]{1,100}$' THEN RAISE EXCEPTION 'INVALID_BOOTSTRAP_CREDENTIAL'; END IF;
  PERFORM 1 FROM public.platform_initialization WHERE id=1 AND state='UNINITIALIZED' FOR UPDATE;
  IF NOT FOUND OR EXISTS(SELECT 1 FROM public.platform_owner_designations WHERE status IN ('PENDING','ACTIVE')) THEN
    RAISE EXCEPTION 'PLATFORM_ALREADY_INITIALIZED_OR_BOOTSTRAP_PENDING';
  END IF;
  UPDATE public.owner_bootstrap_credentials SET status='EXPIRED'
    WHERE status='ACTIVE' AND "expiresAt"<=clock_timestamp();
  IF EXISTS(SELECT 1 FROM public.owner_bootstrap_credentials WHERE status='ACTIVE') THEN RAISE EXCEPTION 'ACTIVE_BOOTSTRAP_CREDENTIAL_EXISTS'; END IF;
  PERFORM 1 FROM public.platform_users WHERE id=p_platform_user_id AND status='ACTIVE' FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'ACTIVE_PLATFORM_USER_REQUIRED'; END IF;
  SELECT count(*) INTO v_identity_count FROM public.user_identities ui JOIN public.user_identity_verifications ver
    ON ver."userIdentityId"=ui.id AND ver."platformUserId"=ui."userId" AND ver.issuer=ui.issuer AND ver.subject=ui.subject
    WHERE ui."userId"=p_platform_user_id AND ui.issuer=p_issuer;
  IF v_identity_count=0 THEN RAISE EXCEPTION 'VERIFIED_IDENTITY_REQUIRED'; END IF;
  IF v_identity_count<>1 THEN RAISE EXCEPTION 'SELECT_UNAMBIGUOUS_VERIFIED_IDENTITY_REQUIRED'; END IF;
  SELECT ui.* INTO v_identity FROM public.user_identities ui JOIN public.user_identity_verifications ver
    ON ver."userIdentityId"=ui.id AND ver."platformUserId"=ui."userId" AND ver.issuer=ui.issuer AND ver.subject=ui.subject
    WHERE ui."userId"=p_platform_user_id AND ui.issuer=p_issuer;
  v_expires:=clock_timestamp()+interval '15 minutes';
  INSERT INTO public.owner_bootstrap_credentials(id,"platformUserId","userIdentityId","verifierKeyId",verifier,"issuedBy","expiresAt")
    VALUES(p_credential_id,p_platform_user_id,v_identity.id,p_verifier_key_id,p_verifier,session_user,v_expires);
  PERFORM public.append_authorization_audit(jsonb_build_object(
    'eventType','platform-owner-bootstrap-credential-issued','actorType','SYSTEM','actorId',session_user,
    'targetType','platform-user','targetId',p_platform_user_id::text,'operation','issue-credential','outcome','credential_issued',
    'correlationId',p_credential_id::text));
  RETURN v_expires;
END; $$;

CREATE FUNCTION public.prepare_platform_owner_bootstrap(
  p_credential_id UUID,p_platform_user_id UUID,p_candidate_verifier BYTEA
) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_credential public.owner_bootstrap_credentials%ROWTYPE; v_designation_id UUID; v_operation_id UUID;
        v_idempotency_digest BYTEA; v_request_fingerprint BYTEA; v_now TIMESTAMPTZ:=clock_timestamp();
BEGIN
  IF NOT pg_catalog.pg_has_role(session_user,'dbp_platform_owner_operator','member') THEN RAISE EXCEPTION 'PLATFORM_OWNER_OPERATOR_REQUIRED'; END IF;
  IF p_credential_id IS NULL OR p_platform_user_id IS NULL OR p_candidate_verifier IS NULL OR octet_length(p_candidate_verifier)<>32 THEN RAISE EXCEPTION 'INVALID_BOOTSTRAP_REQUEST'; END IF;
  PERFORM 1 FROM public.platform_initialization WHERE id=1 FOR UPDATE;
  SELECT * INTO v_credential FROM public.owner_bootstrap_credentials WHERE id=p_credential_id FOR UPDATE;
  IF NOT FOUND OR v_credential."platformUserId"<>p_platform_user_id OR
     NOT public.constant_time_bytea_equal(v_credential.verifier,p_candidate_verifier) THEN RAISE EXCEPTION 'INVALID_BOOTSTRAP_CREDENTIAL'; END IF;
  IF v_credential.status='CONSUMED' THEN RAISE EXCEPTION 'BOOTSTRAP_CREDENTIAL_ALREADY_USED'; END IF;
  IF v_credential.status<>'ACTIVE' OR v_credential."expiresAt"<=v_now THEN RAISE EXCEPTION 'EXPIRED_OR_USED_BOOTSTRAP_CREDENTIAL'; END IF;
  IF EXISTS(SELECT 1 FROM public.platform_initialization WHERE id=1 AND state='INITIALIZED') OR
     EXISTS(SELECT 1 FROM public.platform_owner_designations WHERE status IN ('PENDING','ACTIVE')) THEN
    RAISE EXCEPTION 'PLATFORM_ALREADY_INITIALIZED_OR_BOOTSTRAP_PENDING';
  END IF;
  PERFORM 1 FROM public.platform_users WHERE id=p_platform_user_id AND status='ACTIVE' FOR SHARE;
  IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM public.user_identity_verifications WHERE "userIdentityId"=v_credential."userIdentityId"
    AND "platformUserId"=p_platform_user_id) THEN RAISE EXCEPTION 'VERIFIED_ACTIVE_OWNER_REQUIRED'; END IF;

  v_designation_id:=pg_catalog.gen_random_uuid();
  v_idempotency_digest:=public.digest(convert_to('DBP-OWNER-BOOTSTRAP-IDEMPOTENCY-v1','UTF8')||pg_catalog.uuid_send(p_credential_id),'sha256');
  v_request_fingerprint:=public.digest(convert_to('DBP-OWNER-BOOTSTRAP-REQUEST-v1','UTF8')||pg_catalog.uuid_send(p_platform_user_id)||pg_catalog.uuid_send(v_credential."userIdentityId"),'sha256');
  v_operation_id:=public.prepare_critical_operation('platform.owner.bootstrap','PLATFORM_OWNER_DESIGNATION',v_designation_id::text,
    v_idempotency_digest,v_request_fingerprint,session_user);
  INSERT INTO public.platform_owner_designations(id,"platformUserId","userIdentityId","criticalOperationId",status,"preparedAt")
    VALUES(v_designation_id,p_platform_user_id,v_credential."userIdentityId",v_operation_id,'PENDING',v_now);
  UPDATE public.owner_bootstrap_credentials SET status='CONSUMED',"consumedAt"=v_now,"operationId"=v_operation_id WHERE id=v_credential.id;
  PERFORM public.append_authorization_audit(jsonb_build_object(
    'eventType','platform-owner-designation-prepared','actorType','SYSTEM','actorId',session_user,
    'targetType','platform-owner-designation','targetId',v_designation_id::text,'operation','prepare','outcome','pending',
    'correlationId',v_operation_id::text));
  RETURN v_operation_id;
END; $$;

CREATE FUNCTION public.record_platform_owner_bootstrap_rejection(p_platform_user_id UUID,p_outcome_code TEXT) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
  IF NOT pg_catalog.pg_has_role(session_user,'dbp_platform_owner_operator','member') THEN RAISE EXCEPTION 'PLATFORM_OWNER_OPERATOR_REQUIRED'; END IF;
  IF p_outcome_code IS NULL OR p_outcome_code !~ '^[a-z0-9_]{1,100}$' THEN RAISE EXCEPTION 'INVALID_OUTCOME_CODE'; END IF;
  PERFORM public.append_authorization_audit(jsonb_build_object(
    'eventType','platform-owner-bootstrap-rejected','actorType','SYSTEM','actorId',session_user,
    'targetType','platform-user','targetId',coalesce(p_platform_user_id::text,'unknown'),'operation','bootstrap','outcome',p_outcome_code));
END; $$;

CREATE FUNCTION public.get_platform_owner_bootstrap_status(p_operation_id UUID)
RETURNS TABLE(credential_status TEXT,operation_id UUID,operation_status TEXT,designation_status TEXT,initialization_state TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
  IF NOT pg_catalog.pg_has_role(session_user,'dbp_platform_owner_operator','member') THEN RAISE EXCEPTION 'PLATFORM_OWNER_OPERATOR_REQUIRED'; END IF;
  RETURN QUERY SELECT c.status::text,op.id,op.status::text,d.status::text,i.state::text FROM public.owner_bootstrap_credentials c
    LEFT JOIN public.critical_operations op ON op.id=c."operationId"
    LEFT JOIN public.platform_owner_designations d ON d."criticalOperationId"=op.id
    CROSS JOIN public.platform_initialization i WHERE c.id=p_operation_id AND i.id=1;
END; $$;

CREATE FUNCTION public.resolve_active_platform_owner(p_platform_user_id UUID) RETURNS UUID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_designation_id UUID;
BEGIN
  SELECT d.id INTO v_designation_id FROM public.platform_initialization i
    JOIN public.platform_owner_designations d ON d.id=i."activeDesignationId" AND d.status='ACTIVE'
    JOIN public.platform_users u ON u.id=d."platformUserId" AND u.status='ACTIVE'
    JOIN public.user_identity_verifications ver ON ver."userIdentityId"=d."userIdentityId" AND ver."platformUserId"=u.id
    WHERE i.id=1 AND i.state='INITIALIZED' AND d."platformUserId"=p_platform_user_id
    FOR SHARE OF i,d,u;
  RETURN v_designation_id;
END; $$;

ALTER FUNCTION public.constant_time_bytea_equal(BYTEA,BYTEA) OWNER TO dbp_platform_owner_owner;
ALTER FUNCTION public.issue_platform_owner_bootstrap_credential(UUID,UUID,TEXT,TEXT,BYTEA) OWNER TO dbp_platform_owner_owner;
ALTER FUNCTION public.prepare_platform_owner_bootstrap(UUID,UUID,BYTEA) OWNER TO dbp_platform_owner_owner;
ALTER FUNCTION public.record_platform_owner_bootstrap_rejection(UUID,TEXT) OWNER TO dbp_platform_owner_owner;
ALTER FUNCTION public.get_platform_owner_bootstrap_status(UUID) OWNER TO dbp_platform_owner_owner;
ALTER FUNCTION public.resolve_active_platform_owner(UUID) OWNER TO dbp_platform_owner_owner;
ALTER FUNCTION public.activate_platform_owner_from_critical_gate() OWNER TO dbp_platform_owner_owner;
ALTER FUNCTION public.guard_platform_owner_credential() OWNER TO dbp_platform_owner_owner;
ALTER FUNCTION public.guard_platform_owner_designation() OWNER TO dbp_platform_owner_owner;
ALTER FUNCTION public.guard_platform_initialization() OWNER TO dbp_platform_owner_owner;

REVOKE ALL ON FUNCTION public.constant_time_bytea_equal(BYTEA,BYTEA),
  public.issue_platform_owner_bootstrap_credential(UUID,UUID,TEXT,TEXT,BYTEA),
  public.prepare_platform_owner_bootstrap(UUID,UUID,BYTEA),public.record_platform_owner_bootstrap_rejection(UUID,TEXT),
  public.get_platform_owner_bootstrap_status(UUID),public.resolve_active_platform_owner(UUID),
  public.activate_platform_owner_from_critical_gate(),public.guard_platform_owner_credential(),
  public.guard_platform_owner_designation(),public.guard_platform_initialization() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.constant_time_bytea_equal(BYTEA,BYTEA) TO dbp_platform_owner_owner;
GRANT EXECUTE ON FUNCTION public.issue_platform_owner_bootstrap_credential(UUID,UUID,TEXT,TEXT,BYTEA),
  public.prepare_platform_owner_bootstrap(UUID,UUID,BYTEA),public.record_platform_owner_bootstrap_rejection(UUID,TEXT),
  public.get_platform_owner_bootstrap_status(UUID) TO dbp_platform_owner_operator;
GRANT EXECUTE ON FUNCTION public.resolve_active_platform_owner(UUID) TO dbp_runtime;

COMMIT;
