-- Run as a database administrator before applying the audit and critical-operation migrations.
-- This file defines NOLOGIN roles only. Provision login identities
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
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_critical_operation_owner') THEN
    CREATE ROLE dbp_critical_operation_owner NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_critical_operation_service') THEN
    CREATE ROLE dbp_critical_operation_service NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_critical_operation_reconciler') THEN
    CREATE ROLE dbp_critical_operation_reconciler NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_identity_link_owner') THEN
    CREATE ROLE dbp_identity_link_owner NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_identity_link_operator') THEN
    CREATE ROLE dbp_identity_link_operator NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_identity_link_callback') THEN
    CREATE ROLE dbp_identity_link_callback NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_platform_owner_owner') THEN
    CREATE ROLE dbp_platform_owner_owner NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbp_platform_owner_operator') THEN
    CREATE ROLE dbp_platform_owner_operator NOLOGIN;
  END IF;
END $$;
