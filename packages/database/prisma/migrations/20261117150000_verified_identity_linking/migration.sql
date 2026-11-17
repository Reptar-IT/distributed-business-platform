BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_identity_link_owner') THEN CREATE ROLE dbp_identity_link_owner NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_identity_link_operator') THEN CREATE ROLE dbp_identity_link_operator NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_identity_link_callback') THEN CREATE ROLE dbp_identity_link_callback NOLOGIN; END IF;
END $$;

CREATE TYPE public."IdentityLinkChallengeStatus" AS ENUM ('PENDING','COMPLETED','REJECTED','CANCELLED');

ALTER TABLE public.user_identities
  ADD CONSTRAINT user_identities_provenance_binding_key UNIQUE (id, "userId", issuer, subject),
  ADD CONSTRAINT user_identities_id_user_key UNIQUE (id, "userId");

CREATE TABLE public.identity_link_challenges (
  id UUID PRIMARY KEY,
  "platformUserId" UUID NOT NULL REFERENCES public.platform_users(id) ON DELETE RESTRICT,
  "expectedIssuer" TEXT NOT NULL,
  "initiatedBy" VARCHAR(200) NOT NULL,
  status public."IdentityLinkChallengeStatus" NOT NULL DEFAULT 'PENDING',
  "expiresAt" TIMESTAMPTZ(6) NOT NULL,
  "completedAt" TIMESTAMPTZ(6),
  "outcomeCode" VARCHAR(100),
  "createdAt" TIMESTAMPTZ(6) NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT identity_link_challenges_issuer_valid CHECK (length("expectedIssuer") BETWEEN 1 AND 1000),
  CONSTRAINT identity_link_challenges_operator_valid CHECK (length("initiatedBy") BETWEEN 1 AND 200),
  CONSTRAINT identity_link_challenges_outcome_valid CHECK ("outcomeCode" IS NULL OR "outcomeCode" ~ '^[a-z0-9_]{1,100}$'),
  CONSTRAINT identity_link_challenges_state_shape CHECK (
    (status='PENDING' AND "completedAt" IS NULL AND "outcomeCode" IS NULL) OR
    (status='COMPLETED' AND "completedAt" IS NOT NULL AND "outcomeCode" IN ('linked','already_verified')) OR
    (status IN ('REJECTED','CANCELLED') AND "completedAt" IS NOT NULL AND "outcomeCode" IS NOT NULL)
  )
);
CREATE INDEX identity_link_challenges_expiry_idx ON public.identity_link_challenges(status,"expiresAt");

CREATE TABLE public.user_identity_verifications (
  id UUID PRIMARY KEY,
  "userIdentityId" UUID NOT NULL UNIQUE,
  "platformUserId" UUID NOT NULL,
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  "challengeId" UUID NOT NULL UNIQUE REFERENCES public.identity_link_challenges(id) ON DELETE RESTRICT,
  "initiatingOperator" VARCHAR(200) NOT NULL,
  "proofMethod" VARCHAR(100) NOT NULL,
  "verifiedAt" TIMESTAMPTZ(6) NOT NULL,
  CONSTRAINT user_identity_verification_identity_binding_fkey
    FOREIGN KEY ("userIdentityId","platformUserId",issuer,subject)
    REFERENCES public.user_identities(id,"userId",issuer,subject) ON DELETE RESTRICT,
  CONSTRAINT user_identity_verification_user_fkey FOREIGN KEY ("platformUserId") REFERENCES public.platform_users(id) ON DELETE RESTRICT,
  CONSTRAINT user_identity_verification_operator_valid CHECK (length("initiatingOperator") BETWEEN 1 AND 200),
  CONSTRAINT user_identity_verification_method CHECK ("proofMethod"='OIDC_AUTHORIZATION_CODE_PKCE_FRESH_AUTH')
);

REVOKE ALL ON TYPE public."IdentityLinkChallengeStatus" FROM PUBLIC, dbp_runtime, dbp_audit_exporter, dbp_audit_receipt_verifier;
REVOKE ALL ON public.identity_link_challenges, public.user_identity_verifications FROM PUBLIC, dbp_runtime, dbp_audit_exporter, dbp_audit_receipt_verifier;
REVOKE INSERT, UPDATE, DELETE ON public.user_identities FROM PUBLIC, dbp_runtime, dbp_audit_exporter, dbp_audit_receipt_verifier;
GRANT USAGE ON SCHEMA public TO dbp_identity_link_owner, dbp_identity_link_operator, dbp_identity_link_callback;
GRANT USAGE ON TYPE public."IdentityLinkChallengeStatus" TO dbp_identity_link_owner;
GRANT SELECT ON public.platform_users, public.user_identities, public.user_identity_verifications TO dbp_identity_link_owner;
-- PostgreSQL requires UPDATE privilege to take row locks with SELECT ... FOR SHARE.
-- Limit that privilege to status; trusted functions use it only to serialize against suspension.
GRANT UPDATE (status) ON public.platform_users TO dbp_identity_link_owner;
GRANT SELECT, INSERT ON public.user_identities, public.user_identity_verifications TO dbp_identity_link_owner;
GRANT SELECT, INSERT, UPDATE ON public.identity_link_challenges TO dbp_identity_link_owner;
GRANT EXECUTE ON FUNCTION public.append_authorization_audit(JSONB,UUID) TO dbp_identity_link_owner;

CREATE FUNCTION public.guard_user_identity_link_write() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'IDENTITY_UNLINK_REQUIRES_SEPARATE_AUTHORIZED_PROCESS'; END IF;
  IF current_user<>'dbp_identity_link_owner' THEN RAISE EXCEPTION 'IDENTITY_LINK_WRITE_FORBIDDEN'; END IF;
  IF TG_OP='UPDATE' THEN RAISE EXCEPTION 'IDENTITY_MAPPING_IS_IMMUTABLE'; END IF;
  RETURN NEW;
END; $$;
CREATE TRIGGER user_identities_restricted_write BEFORE INSERT OR UPDATE OR DELETE ON public.user_identities
FOR EACH ROW EXECUTE FUNCTION public.guard_user_identity_link_write();

CREATE FUNCTION public.guard_identity_link_provenance() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF TG_OP<>'INSERT' OR current_user<>'dbp_identity_link_owner' THEN RAISE EXCEPTION 'IDENTITY_LINK_PROVENANCE_IS_IMMUTABLE'; END IF;
  RETURN NEW;
END; $$;
CREATE TRIGGER user_identity_verifications_immutable BEFORE INSERT OR UPDATE OR DELETE ON public.user_identity_verifications
FOR EACH ROW EXECUTE FUNCTION public.guard_identity_link_provenance();

CREATE FUNCTION public.guard_identity_link_challenge() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF current_user<>'dbp_identity_link_owner' THEN RAISE EXCEPTION 'IDENTITY_LINK_CHALLENGE_WRITE_FORBIDDEN'; END IF;
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'IDENTITY_LINK_CHALLENGES_ARE_IMMUTABLE_HISTORY'; END IF;
  IF TG_OP='UPDATE' AND (
    (NEW.id,NEW."platformUserId",NEW."expectedIssuer",NEW."initiatedBy",NEW."expiresAt",NEW."createdAt") IS DISTINCT FROM
    (OLD.id,OLD."platformUserId",OLD."expectedIssuer",OLD."initiatedBy",OLD."expiresAt",OLD."createdAt") OR
    OLD.status<>'PENDING' OR NEW.status NOT IN ('COMPLETED','REJECTED','CANCELLED')
  ) THEN RAISE EXCEPTION 'INVALID_IDENTITY_LINK_CHALLENGE_TRANSITION'; END IF;
  RETURN NEW;
END; $$;
CREATE TRIGGER identity_link_challenges_restricted_write BEFORE INSERT OR UPDATE OR DELETE ON public.identity_link_challenges
FOR EACH ROW EXECUTE FUNCTION public.guard_identity_link_challenge();

CREATE FUNCTION public.begin_platform_identity_link(p_platform_user_id UUID,p_expected_issuer TEXT) RETURNS UUID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_id UUID; v_user public.platform_users%ROWTYPE;
BEGIN
  IF NOT pg_catalog.pg_has_role(session_user,'dbp_identity_link_operator','member') THEN RAISE EXCEPTION 'IDENTITY_LINK_OPERATOR_REQUIRED'; END IF;
  IF p_expected_issuer IS NULL OR length(p_expected_issuer) NOT BETWEEN 1 AND 1000 THEN RAISE EXCEPTION 'INVALID_IDENTITY_LINK_REQUEST'; END IF;
  SELECT * INTO v_user FROM public.platform_users WHERE id=p_platform_user_id FOR SHARE;
  IF NOT FOUND OR v_user.status<>'ACTIVE' THEN RAISE EXCEPTION 'ACTIVE_PLATFORM_USER_REQUIRED'; END IF;
  v_id:=pg_catalog.gen_random_uuid();
  INSERT INTO public.identity_link_challenges(id,"platformUserId","expectedIssuer","initiatedBy","expiresAt")
    VALUES(v_id,p_platform_user_id,p_expected_issuer,session_user,clock_timestamp()+interval '5 minutes');
  PERFORM public.append_authorization_audit(jsonb_build_object(
    'eventType','platform-identity-link-challenge-issued','actorType','SYSTEM','actorId',session_user,
    'targetType','platform-user','targetId',p_platform_user_id::text,'operation','identity-link','outcome','challenge_issued',
    'correlationId',v_id::text));
  RETURN v_id;
END; $$;

CREATE FUNCTION public.get_platform_identity_link_confirmation(p_challenge_id UUID)
RETURNS TABLE(platform_user_id UUID)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
  IF NOT pg_catalog.pg_has_role(session_user,'dbp_identity_link_callback','member') THEN
    RAISE EXCEPTION 'IDENTITY_LINK_CALLBACK_REQUIRED';
  END IF;
  RETURN QUERY SELECT c."platformUserId" FROM public.identity_link_challenges c
    JOIN public.platform_users u ON u.id=c."platformUserId" AND u.status='ACTIVE'
    WHERE c.id=p_challenge_id AND c.status='PENDING' AND c."expiresAt">clock_timestamp();
END; $$;

CREATE FUNCTION public.complete_platform_identity_link(
  p_challenge_id UUID,p_expected_platform_user_id UUID,p_issuer TEXT,p_subject TEXT,p_verified_at TIMESTAMPTZ
) RETURNS TEXT LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_challenge public.identity_link_challenges%ROWTYPE; v_user public.platform_users%ROWTYPE;
        v_identity public.user_identities%ROWTYPE; v_outcome TEXT; v_now TIMESTAMPTZ:=clock_timestamp();
BEGIN
  IF NOT pg_catalog.pg_has_role(session_user,'dbp_identity_link_callback','member') THEN RAISE EXCEPTION 'IDENTITY_LINK_CALLBACK_REQUIRED'; END IF;
  SELECT * INTO v_challenge FROM public.identity_link_challenges WHERE id=p_challenge_id FOR UPDATE;
  IF NOT FOUND THEN RETURN 'REJECTED'; END IF;
  IF v_challenge.status<>'PENDING' THEN
    PERFORM public.append_authorization_audit(jsonb_build_object(
      'eventType','platform-identity-link-rejected','actorType','SYSTEM','actorId',v_challenge."initiatedBy",
      'targetType','platform-user','targetId',v_challenge."platformUserId"::text,'operation','identity-link','outcome','challenge_replay',
      'correlationId',p_challenge_id::text));
    RETURN 'REJECTED';
  END IF;
  IF v_challenge."expiresAt"<=v_now THEN v_outcome:='challenge_expired';
  ELSIF p_expected_platform_user_id IS DISTINCT FROM v_challenge."platformUserId" THEN v_outcome:='confirmation_target_mismatch';
  ELSIF p_issuer IS DISTINCT FROM v_challenge."expectedIssuer" OR p_subject IS NULL OR length(p_subject) NOT BETWEEN 1 AND 1000 THEN v_outcome:='identity_claims_mismatch';
  ELSIF p_verified_at IS NULL OR p_verified_at<v_now-interval '5 minutes' OR p_verified_at>v_now+interval '1 minute' THEN v_outcome:='fresh_authentication_required';
  ELSE
    SELECT * INTO v_user FROM public.platform_users WHERE id=v_challenge."platformUserId" FOR SHARE;
    IF NOT FOUND OR v_user.status<>'ACTIVE' THEN
      v_outcome:='platform_user_inactive';
    ELSE
      PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_issuer||chr(31)||p_subject,3));
      -- The issuer/subject advisory transaction lock serializes claims. The
      -- unique identity key remains the final guard without granting UPDATE
      -- privilege on immutable UserIdentity rows merely to lock them.
      SELECT * INTO v_identity FROM public.user_identities WHERE issuer=p_issuer AND subject=p_subject;
      IF FOUND AND v_identity."userId"<>v_challenge."platformUserId" THEN
        v_outcome:='identity_already_linked';
      ELSE
        IF NOT FOUND THEN
          v_identity.id:=pg_catalog.gen_random_uuid();
          v_identity."userId":=v_challenge."platformUserId";
          v_identity.issuer:=p_issuer;
          v_identity.subject:=p_subject;
          INSERT INTO public.user_identities(id,"userId",issuer,subject,email,"emailVerified","createdAt","updatedAt")
            VALUES(v_identity.id,v_identity."userId",p_issuer,p_subject,NULL,false,v_now,v_now);
          v_outcome:='linked';
        ELSE
          IF EXISTS(SELECT 1 FROM public.user_identity_verifications WHERE "userIdentityId"=v_identity.id) THEN
            UPDATE public.identity_link_challenges SET status='COMPLETED',"completedAt"=v_now,"outcomeCode"='already_verified' WHERE id=p_challenge_id;
            PERFORM public.append_authorization_audit(jsonb_build_object(
              'eventType','platform-identity-link-verified','actorType','SYSTEM','actorId',v_challenge."initiatedBy",
              'targetType','platform-user','targetId',v_challenge."platformUserId"::text,'operation','identity-link','outcome','already_verified',
              'correlationId',p_challenge_id::text));
            RETURN 'ALREADY_VERIFIED';
          END IF;
          v_outcome:='linked';
        END IF;
        INSERT INTO public.user_identity_verifications(id,"userIdentityId","platformUserId",issuer,subject,"challengeId","initiatingOperator","proofMethod","verifiedAt")
          VALUES(pg_catalog.gen_random_uuid(),v_identity.id,v_challenge."platformUserId",p_issuer,p_subject,p_challenge_id,
            v_challenge."initiatedBy",'OIDC_AUTHORIZATION_CODE_PKCE_FRESH_AUTH',v_now);
      END IF;
    END IF;
  END IF;
  IF v_outcome='linked' THEN
    UPDATE public.identity_link_challenges SET status='COMPLETED',"completedAt"=v_now,"outcomeCode"='linked' WHERE id=p_challenge_id;
  ELSE
    UPDATE public.identity_link_challenges SET status='REJECTED',"completedAt"=v_now,"outcomeCode"=v_outcome WHERE id=p_challenge_id;
  END IF;
  PERFORM public.append_authorization_audit(jsonb_build_object(
    'eventType',CASE WHEN v_outcome='linked' THEN 'platform-identity-link-verified' ELSE 'platform-identity-link-rejected' END,
    'actorType','SYSTEM','actorId',v_challenge."initiatedBy",'targetType','platform-user','targetId',v_challenge."platformUserId"::text,
    'operation','identity-link','outcome',v_outcome,'correlationId',p_challenge_id::text));
  RETURN CASE WHEN v_outcome='linked' THEN 'LINKED' ELSE 'REJECTED' END;
END; $$;

CREATE FUNCTION public.reject_platform_identity_link(p_challenge_id UUID,p_outcome_code TEXT) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_challenge public.identity_link_challenges%ROWTYPE;
BEGIN
  IF NOT pg_catalog.pg_has_role(session_user,'dbp_identity_link_callback','member') THEN RAISE EXCEPTION 'IDENTITY_LINK_CALLBACK_REQUIRED'; END IF;
  IF p_outcome_code IS NULL OR p_outcome_code !~ '^[a-z0-9_]{1,100}$' THEN RAISE EXCEPTION 'INVALID_OUTCOME_CODE'; END IF;
  SELECT * INTO v_challenge FROM public.identity_link_challenges WHERE id=p_challenge_id FOR UPDATE;
  IF NOT FOUND OR v_challenge.status<>'PENDING' THEN RETURN; END IF;
  UPDATE public.identity_link_challenges SET status='REJECTED',"completedAt"=clock_timestamp(),"outcomeCode"=p_outcome_code WHERE id=p_challenge_id;
  PERFORM public.append_authorization_audit(jsonb_build_object(
    'eventType','platform-identity-link-rejected','actorType','SYSTEM','actorId',v_challenge."initiatedBy",
    'targetType','platform-user','targetId',v_challenge."platformUserId"::text,'operation','identity-link','outcome',p_outcome_code,
    'correlationId',p_challenge_id::text));
END; $$;

ALTER FUNCTION public.begin_platform_identity_link(UUID,TEXT) OWNER TO dbp_identity_link_owner;
ALTER FUNCTION public.get_platform_identity_link_confirmation(UUID) OWNER TO dbp_identity_link_owner;
ALTER FUNCTION public.complete_platform_identity_link(UUID,UUID,TEXT,TEXT,TIMESTAMPTZ) OWNER TO dbp_identity_link_owner;
ALTER FUNCTION public.reject_platform_identity_link(UUID,TEXT) OWNER TO dbp_identity_link_owner;
REVOKE ALL ON FUNCTION public.begin_platform_identity_link(UUID,TEXT),public.get_platform_identity_link_confirmation(UUID),
  public.complete_platform_identity_link(UUID,UUID,TEXT,TEXT,TIMESTAMPTZ),public.reject_platform_identity_link(UUID,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.begin_platform_identity_link(UUID,TEXT) TO dbp_identity_link_operator;
GRANT EXECUTE ON FUNCTION public.get_platform_identity_link_confirmation(UUID),
  public.complete_platform_identity_link(UUID,UUID,TEXT,TEXT,TIMESTAMPTZ),public.reject_platform_identity_link(UUID,TEXT) TO dbp_identity_link_callback;
REVOKE ALL ON FUNCTION public.guard_user_identity_link_write(),public.guard_identity_link_provenance(),public.guard_identity_link_challenge() FROM PUBLIC;

COMMIT;
