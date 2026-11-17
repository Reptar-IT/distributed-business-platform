# Critical-operation engine (Stage 2)

## Scope and security boundary

Stage 2 provides durable, generic operation orchestration for changes that introduce or remove authority. It does not implement owner bootstrap, owner recovery, machine credentials, venture grants, or general authorization evaluation. `CriticalOperationGate` is an authoritative generic gate, not a replacement for domain authorization state.

Every future protected domain operation must call `critical_operation_target_is_active(targetType, targetId)` inside the same PostgreSQL transaction as its sensitive read/write. The function takes a `FOR SHARE` row lock. A revocation takes the same row `FOR UPDATE` and waits for in-flight protected transactions; after revocation commits, new checks return false. Calling the check in a standalone/autocommit statement does not protect later work.

The engine is not production-enabled. The worker flag defaults to false. The worker refuses to start with the flag enabled when `NODE_ENV=production`. Production activation requires independently deployed physical and hosted archives, distinct keys, credentials and durable stores, independent failure domains, and tested failure behavior. Local archive servers are development/test adapters only.

## Operation states and transitions

| State | Meaning | Next states |
|---|---|---|
| `PREPARED` | Intent is durable; activation remains `PROPOSED` and unusable. | `AWAITING_ARCHIVE`, `REVOCATION_PENDING_ARCHIVE`, `FAILED`, `RECONCILIATION_REQUIRED` |
| `AWAITING_ARCHIVE` | Ready event is durable; waiting for a qualifying receipt. | `READY_TO_ACTIVATE`, `FAILED`, `RECONCILIATION_REQUIRED` |
| `READY_TO_ACTIVATE` | A qualifying receipt is available; restricted finalizer may activate. | `COMPLETED`, `FAILED`, `RECONCILIATION_REQUIRED` |
| `REVOCATION_PENDING_ARCHIVE` | Revocation already took effect; waiting for archival confirmation. | `COMPLETED`, `RECONCILIATION_REQUIRED` |
| `COMPLETED` | Receipt-confirmed outcome and completion event are committed. | Terminal |
| `FAILED` | Controlled activation failure is audited; proposed gate becomes inactive. | Terminal |
| `RECONCILIATION_REQUIRED` | State needs explicit review; reservations remain held and activation cannot proceed. | `FAILED` through audited resolution only |

The database partial unique index permits at most one nonterminal operation per target. Database triggers reject illegal status and gate transitions. A failed activation cannot become active; resolving reconciliation for an activation closes it as failed/inactive. Revocation reconciliation never changes the revoked gate back to active.

## Idempotency and audit

The caller supplies an idempotency key of at least 32 characters. The TypeScript service stores only a domain-separated SHA-256 digest. A separately domain-separated SHA-256 fingerprint is computed from recursively key-sorted JSON. The raw key and request body are not persisted. A repeated digest with a matching fingerprint and target resumes the same operation; any mismatch is an idempotency conflict. Advisory transaction locks, unique constraints, and the one-open-target index protect concurrent service processes.

Intent, ready/revocation, failure/reconciliation, and completion events use the Stage 1 append-only audit stream. Audit payloads contain identifiers and bounded reason codes, never credentials or request payloads. Final activation, its completion event, and `COMPLETED` update share one transaction. Failure rolls back all three. Revocation, its audit event, and the pending operation share one transaction so an archive outage cannot keep the gate active.

## Receipt-gated activation

A ready event moves activation to `AWAITING_ARCHIVE`. A batch, network submission, or exporter delivery state alone is insufficient. The operation can progress to `READY_TO_ACTIVATE` only when the Stage 1 verifier has recorded a receipt from a `PHYSICAL` or `HOSTED` destination.

The database helper verifies that the receipt row matches its immutable batch and payload: destination, key ID, batch hash, sequence bounds, and terminal event hash. It requires acknowledged delivery, contiguous destination checkpoint advancement, source event count and hash links, and receipts from the same destination covering both the intent and ready event. Stage 1's trusted verifier validates the pinned destination key and Ed25519 signature before it can call the restricted receipt-recording function. The Stage 2 finalizer rechecks operation state, gate state, receipt qualification, and event references before activation. One independently verified archive is sufficient; delivery to the other destination continues independently.

The verifier's process and database identity remain part of the Stage 1 trusted computing boundary. PostgreSQL does not itself validate Ed25519 cryptography. Compromise of the verifier identity can forge a stored receipt; Stage 2 intentionally reuses this boundary rather than adding another signature verifier.

## Database roles and functions

`infrastructure/database/roles.sql` provisions `dbp_critical_operation_owner`, `dbp_critical_operation_service`, and `dbp_critical_operation_reconciler` as `NOLOGIN` roles. Migrations contain no login credentials.

- `dbp_critical_operation_owner` owns the fixed-search-path `SECURITY DEFINER` functions and has narrowly scoped table access plus execute access to Stage 1 append and batch preparation.
- `dbp_critical_operation_service` can execute preparation, revocation, advancement, and the receipt-checked finalizer. It has no direct operation/gate table writes.
- `dbp_critical_operation_reconciler` can read operations and execute audited reconciliation/failure functions, but cannot finalize or activate.
- `dbp_runtime` can only execute the gate check; it cannot directly write operation or gate rows.
- Stage 1 exporter and receipt-verifier roles do not receive Stage 2 table access.

All Stage 2 `SECURITY DEFINER` functions set `search_path` to `pg_catalog, public`; public execute privileges are revoked. The database owner/superuser remains outside this application-role boundary, as expected.

## Worker, retry, and reconciliation

When explicitly enabled outside production, the worker uses `CRITICAL_OPERATION_DATABASE_URL`, a separate service-role connection. It polls the durable operation table and advances persisted states; a restarted worker resumes without an in-memory queue. `FOR UPDATE SKIP LOCKED` and row locks coordinate multiple workers. Transient lack of receipt leaves the operation pending. Unexpected database errors are logged as a bounded `ADVANCE_FAILED` category and the next poll retries without deleting the operation.

Reconciliation is an explicit reconciler-only operation with a bounded metadata schema and an audit event. An identical retry returns the stored state without appending another event; changed data conflicts. It cannot grant activation without a qualifying receipt. Resolution only fails/closes an operation and leaves revocations revoked. Manual reconciliation and incident response remain operator responsibilities.

## Validation and known limitations

Validated on disposable PostgreSQL 17 databases, never the application database. Stage 2 integration tests use the real local archive and receipt-verifier services with the second archive unavailable. They cover idempotency, concurrent target reservations/finalizers, receipt-gated activation, restart retry, immediate revocation, same-transaction gate locking, direct runtime-write denial, reconciliation, and finalization rollback. Existing Stage 1 audit and exporter/archive integration suites also run against disposable databases.

Known limitations:

- This is a generic engine. No domain lifecycle currently uses its gate; later milestones must integrate and test each protected domain operation transactionally.
- Local archive integration does not establish production deployment independence. Production remains disabled until the deployment prerequisites above are verified.
- The Stage 1 receipt verifier is trusted for signature validation; PostgreSQL verifies metadata and verifier-mediated provenance, not the signature itself.
- Operational monitoring, alerting, production role provisioning, and physical/hosted archive operations remain deployment work.
