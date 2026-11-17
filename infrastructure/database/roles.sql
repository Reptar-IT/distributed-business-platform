-- Run as a database administrator before applying the audit migration.
-- This file defines NOLOGIN function-owner roles only. Provision login identities
-- separately through the deployment secret manager or database IAM; never add passwords here.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_migrator') THEN
    CREATE ROLE dbp_migrator NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_audit_append_owner') THEN
    CREATE ROLE dbp_audit_append_owner NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_audit_batch_owner') THEN
    CREATE ROLE dbp_audit_batch_owner NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_runtime') THEN
    CREATE ROLE dbp_runtime NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_audit_exporter') THEN
    CREATE ROLE dbp_audit_exporter NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_audit_receipt_verifier') THEN
    CREATE ROLE dbp_audit_receipt_verifier NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_audit_receipt_owner') THEN
    CREATE ROLE dbp_audit_receipt_owner NOLOGIN;
  END IF;
END $$;
