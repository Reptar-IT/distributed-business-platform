# Stage 4: Platform owner recovery

## Status and scope

Stage 4 adds recovery for the existing platform owner. It does not create or transfer an owner, provision a `PlatformUser`, perform general account recovery, or permit identity reassignment. It preserves the existing `PlatformOwnerDesignation` and maps the new OIDC identity to the same active `PlatformUser` using the exact `(issuer, subject)` pair. Email is not used for identity resolution.

The implementation is present in the API, CLI, worker and PostgreSQL migration. Local PostgreSQL 17 integration coverage exercises the full database/archive lifecycle. **This does not make production recovery ready.** Production use still requires separately provisioned capability logins, protected verifier keys, Redis, matching OIDC callback configuration, the recovery-kit UI, operational monitoring, and independently deployed physical and hosted archives. Critical-operation production enablement remains gated by the existing Stage 2 deployment prerequisites.

## Recovery kit

An already authenticated platform owner can issue or replace a kit through `POST /api/v1/auth/owner/recovery-kit`. The API session identity is passed to a restricted SQL function, which independently checks the active owner designation, active user and verified current identity. The route also requires the configured browser origin and session CSRF token. Ordinary administrators and database roles other than the narrowly granted runtime capability cannot execute the kit function.

The server creates exactly ten independent codes using 32 cryptographically random bytes per code (256 bits), encodes them as `dbp-rc-v1.<base64url>`, and computes domain-separated HMAC-SHA-256 verifiers. PostgreSQL stores only each verifier, its key ID, code state, timestamps and operation reference; plaintext codes are returned once with `Cache-Control: no-store` and displayed by the browser without local storage. Operators must save the displayed kit in an approved secure offline store. A lost response means the codes cannot be recovered; issuing a replacement invalidates every unused code from the preceding kit atomically.

`OWNER_RECOVERY_VERIFIER_KEYS_JSON` and `OWNER_RECOVERY_CURRENT_VERIFIER_KEY_ID` configure the API and trusted CLI. Use randomly generated keys of at least 32 bytes from a secrets manager. Keep old key IDs and key material available while any active kit has verifiers under those keys; make a new key current for new kits, then remove old keys only after replacing the outstanding kit. Never place real key values in repository files or audit events. The application clears its in-memory key buffers during shutdown; process environment and secrets-manager handling remain deployment responsibilities.

## Recovery CLI and OIDC flow

Run recovery from a trusted server terminal where `OWNER_RECOVERY_OPERATOR_DATABASE_URL`, `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI`, and `REDIS_URL` are available:

```sh
npm run platform -- owner-recovery run
npm run platform -- owner-recovery status <recovery-operation-uuid>
```

The recovery code is read through hidden terminal input; it is never a command-line argument. The CLI submits only HMAC candidates to PostgreSQL. A valid code is consumed transactionally when the operation is created. Re-running with that same code can resume its existing open operation, but cannot create another operation or consume the code again. The CLI prints the operation ID and the OIDC authorization URL, not the code or verifier key.

The authorization uses the configured OIDC provider's discovery document and Authorization Code flow with PKCE S256, fresh `prompt=login`/`max_age=0`, five-minute Redis state/nonce/verifier data, and a one-use Redis `GETDEL`. The state is bound server-side to the recovery operation. `openid-client` validates the callback state, nonce, PKCE exchange, signature, issuer metadata, audience and expiry; the service additionally requires exact configured issuer, nonempty subject, matching `azp` when present, and a recent `auth_time` no more than five minutes old. The callback path and origin are reconstructed from the configured redirect URI. No email claim is used. Tokens, codes and PKCE material are not included in logs or audit payloads; API request URLs are redacted from logs.

The browser callback is not an unauthenticated recovery initiation endpoint. It accepts only an existing short-lived server-side state transaction previously created by the trusted CLI. A successful callback does not establish a browser session.

## Durable lifecycle and archive gate

The PostgreSQL operation has these durable states:

`INITIATED → CHALLENGE_PREPARED → OIDC_PROOF_VERIFIED → PREPARED → AWAITING_ARCHIVE → READY_TO_FINALIZE → FINALIZED`

Failure/expiry and controlled reconciliation are explicit terminal or recovery states. A partial unique index permits only one open recovery operation for the designation. Database row locks, unique code use, unique recovery-operation references, exact issuer/subject uniqueness, and restricted functions serialize competing operations. An accepted code stays consumed if OIDC or archive services fail.

After fresh proof succeeds, PostgreSQL inserts the new identity as `PENDING_OWNER_RECOVERY` with no email and records verification provenance. The normal identity resolver accepts only `ACTIVE` identities, so the pending mapping cannot authenticate or satisfy owner resolution. The recovery operation then prepares a `PLATFORM_OWNER_RECOVERY` critical operation through the Stage 2 engine. The worker advances it using the existing immutable audit and archive receipt pipeline. A verified qualifying receipt moves recovery to `READY_TO_FINALIZE`; the existing critical-operation gate trigger then activates the identity, marks provenance activated, finalizes recovery, and appends completion audit in the same transaction as critical-operation completion. Audit failure rolls back activation. Archive outage leaves the pending identity and operation durable and safe.

No separate archive receipt mechanism is introduced. A failed operation is not silently reset; inspect its durable status and use the existing critical-operation reconciliation process. The worker expires unprepared challenges after five minutes. Pending operations already prepared for archive are not automatically expired.

## Database capabilities

`infrastructure/database/roles.sql` creates only `NOLOGIN` capability roles. Provision individually attributable login identities through database IAM or the approved secret manager; do not use shared operator logins and do not put passwords in migrations.

| Capability | Database boundary |
| --- | --- |
| Current owner issues/replaces a kit | BFF-authenticated session and CSRF/origin checks, plus `dbp_runtime` execute on the single `issue_or_replace_owner_recovery_kit` function; the function rechecks the active owner and exact verified identity. Runtime has no direct recovery table writes. |
| Start/resume recovery, prepare challenge, inspect status | `dbp_owner_recovery_operator` executes only `begin_platform_owner_recovery`, `mark_platform_owner_recovery_challenge_prepared`, and `get_platform_owner_recovery_status`. It cannot read recovery verifier tables. |
| Record verified OIDC proof or reject a callback | `dbp_owner_recovery_callback` executes the bounded callback functions only. |
| Expire challenges and advance/finalize | Existing `dbp_critical_operation_service` worker invokes challenge expiry and the Stage 2 state machine. Recovery activation occurs only in a restricted database trigger after receipt qualification. |
| Lock authoritative active-owner rows | A `SECURITY DEFINER` helper owned by `dbp_platform_owner_owner` returns and locks the active owner rows; execution is restricted to the recovery owner role. Recovery receives no direct update access to owner designation or initialization state. |

Recovery tables have lifecycle checks, unique constraints and transition guards. Protected `SECURITY DEFINER` functions use fixed `pg_catalog,public` search paths, have `PUBLIC` execution revoked, and are owned by `NOLOGIN` capability owners. Audit writes use the existing `append_authorization_audit` boundary. Recovery provenance is immutable except for its one-time final activation timestamp.

The kit HTTP route is the authenticated user boundary for issuance; PostgreSQL independently checks current owner/user/identity state but does not validate the browser cookie itself. Protect the API runtime credential as a trusted BFF capability and do not grant its database role to operators or machine principals.

## Audit, failure and monitoring

Audit events record kit issue/replacement, verification outcome, code consumption, challenge preparation, OIDC proof outcome, identity conflict, pending identity creation, critical-operation preparation, archive qualification, expiry/failure, reconciliation and finalization. They contain safe identifiers, timestamps, outcome codes and operation references only. Recovery codes, HMAC material, authorization codes, tokens, client secrets, PKCE verifiers and cookies are excluded.

Invalid code attempts are audited with a bounded outcome and no supplied verifier or code. The code space is 256 bits and CLI access is a restricted server-side capability. This milestone does not define an account-wide retry threshold, alert severity, escalation SLA, or a separate per-operator database rate-limit policy. Establish those operational policies before production; any rate limit must avoid a permanent unauthenticated lockout vector. Monitor failed/expired operations, repeated invalid attempts, long-running `AWAITING_ARCHIVE`/`RECONCILIATION_REQUIRED` operations, and archive/worker health through the established operational monitoring system.

## Deployment prerequisites and limitations

- Configure a server-only OIDC confidential client and register the exact `OIDC_REDIRECT_URI`; keep the client secret off the browser.
- Provision separate named database identities with only the operator, callback, runtime and critical-operation memberships their process needs. Do not grant these memberships to ordinary administrators or machine principals.
- Configure Redis with production access controls and persistence appropriate to short-lived OIDC challenge state.
- Store and back up recovery verifier keys and owner-held plaintext kit codes in separate approved secret/recovery systems. Losing all owner-held codes prevents this recovery path; there is deliberately no hidden administrative or succession bypass.
- Deploy independent physical and hosted archives and validate their distinct failure domains before enabling critical-operation activation in production. Local tests use a local archive receiver and do not establish independent production deployment.
- Define alerting and a human reconciliation procedure before production. Do not manually edit recovery tables, directly activate identities, or reset the owner designation.

## Exclusions

Owner transfer, succession, multiple owners, identity unlink/reassignment, ordinary-user account recovery, user provisioning, general recovery administration, machine-principal lifecycle and Stage 5 authorization work are not included.
