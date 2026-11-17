# Authorization audit foundation (Stage 1)

## Scope

This stage adds an append-only PostgreSQL audit stream, a serialized event hash chain, deterministic source batches, independently accepting physical and hosted archive endpoints, signed receipts, and durable destination-specific delivery state. It does not implement owner lifecycle, recovery, machine credentials, or permission evaluation. Production archive infrastructure is not provisioned by this change; `@platform/audit-archive` is a local durable receiver and test/development adapter.

## Serialization and hashes

Serialization version `PG17_JSONB_TEXT_V1` is PostgreSQL 17's `jsonb::text` representation of a fixed, flat object containing every event field; absent optional values become explicit JSON `null`, while `decision` defaults to `NOT_APPLICABLE`. Values are strings or null only. Strings are UTF-8, are not Unicode-normalized, and cannot contain NUL (PostgreSQL text restriction). Timestamps are UTC with six fractional digits. Sequence values are positive signed PostgreSQL `BIGINT`; framing uses unsigned big-endian 64-bit integers. Payload length is the UTF-8 byte length. Field ordering follows PostgreSQL 17 JSONB object-key ordering and is mirrored by the protocol package. The migration pins execution to PostgreSQL 17; a future major version requires a new serialization version and test vectors.

Event SHA-256 input is `DBP-AUTHZ-EVENT\0 || hash_version_u16_be || stream_uuid_16 || sequence_u64_be || previous_hash_32 || payload_length_u64_be || canonical_payload_utf8`.

Batch SHA-256 input is `DBP-AUTHZ-BATCH\0 || protocol_version_u16_be || stream_uuid_16 || first_sequence_u64_be || last_sequence_u64_be || event_count_u64_be || previous_hash_32 || terminal_event_hash_32 || SHA256(ordered_event_hashes_32)`.

Stable vectors in `packages/audit-protocol/src/index.test.ts`:

- Event: `a489b0d9cd4efa50379f87ddad50bf115385b235933e186ea57d1fd1efaa4616`
- Batch: `b08d4b56b42e3b31fcb63e9bcf577ad80212d747c2bddeae3da051e36ff55f24`

Receipt payloads carry version `1`, use a fixed-field JSON representation prefixed by `DBP-AUTHZ-ARCHIVE-RECEIPT\0`, and are signed with Ed25519. The public key is pinned per destination and key ID in the isolated receipt-verifier service.

## Database deployment and privileges

Provision role groups using `infrastructure/database/roles.sql` before applying the Prisma migration. The groups are `NOLOGIN`; administrators provision login users out-of-band and grant only the appropriate group. Never add login passwords or archive signing material to migration SQL. A controlled migrator must apply migrations; PostgreSQL administrator or equivalent extension privilege may be required to install `pgcrypto`.

- `dbp_runtime`: execute only `append_authorization_audit`; no direct event or head access.
- `dbp_audit_append_owner`: owns the `SECURITY DEFINER` append function and can insert events/read the stream/update the head needed to append.
- `dbp_audit_exporter`: execute only `prepare_authorization_audit_batch` to ask PostgreSQL to construct source batches from persisted audit rows; read prepared batches, delivery rows, checkpoints and destination health; update only retry and delivery-health metadata. It cannot insert, update or delete batches or delivery rows.
- `dbp_audit_batch_owner`: owns the restricted batch-preparation function and can read immutable audit source data and atomically insert prepared batches and destination delivery rows.
- `dbp_audit_receipt_verifier`: execute `record_verified_audit_receipt`; it has no direct receipt/checkpoint/delivery writes. Its trusted process verifies destination, pinned key ID, Ed25519 signature, batch hash, sequence range and terminal hash before calling the function.
- `dbp_audit_receipt_owner`: owns that restricted function and can atomically add a receipt, advance one destination checkpoint, and acknowledge its delivery.
- `dbp_migrator`: reserved `NOLOGIN` group for controlled migration access; its production membership/ownership grants are deployment-managed.

The append, batch-preparation and receipt functions use fixed `search_path` values, avoid dynamic SQL, revoke `PUBLIC` execution, and grant only their intended execution roles. Batch preparation recomputes event and batch hashes from source rows; the exporter supplies only stream, first sequence and a maximum batch size. The receipt function validates that its supplied payload matches the stored batch and contiguous checkpoint; cryptographic verification occurs in the isolated verifier process before the function call. The function is not an API for untrusted callers.

The verifier database login (`AUDIT_RECEIPT_VERIFIER_DATABASE_URL`) is exclusive to the receipt-verifier process. It must not be mounted, injected or otherwise made available to the API, exporter/worker, owner CLI or ordinary runtime. The exporter separately holds the HTTP service token used to submit receipts to the verifier; that token grants no database access, and signature/key verification still occurs before the privileged database function is called. The verifier process and its database credential are inside the trusted computing boundary: compromise of either can submit a forged receipt because PostgreSQL checks receipt-to-batch metadata and permissions but does not verify Ed25519 signatures itself.

## Delivery and operations

PostgreSQL is the durable queue. Every source batch has independent `physical` and `hosted` delivery rows and checkpoints. Each destination receives the same batch independently, accepts it against its own contiguous chain, persists it, and signs its own receipt. A receipt from one destination does not gate delivery to the other; a valid receipt from either destination can satisfy the future one-archive quorum. The worker records retry time, bounded error category, consecutive failure count and last successful delivery; outstanding delivery remains pending across restart. Configure separate database identities for export and receipt verification and separate URLs, ingest credentials, and pinned Ed25519 public keys for both archives.

The sample local receiver is only a development/test adapter, not a physical or hosted production archive. Production requires separately deployed physical and hosted archives with separate signing keys, separate durable storage and independent failure domains, independently controlled network endpoints and credentials, and TLS/mTLS or an equivalent secure authenticated network boundary. Do not enable production critical-operation enforcement until independent archive deployment and failure-domain tests have completed. Production retention, storage replication, alerting and key rotation remain deployment work.

## Validation

Protocol tests cover deterministic encoding/hash vectors and receipt signatures. Archive integration tests start actual Fastify receivers on loopback and use temporary durable directories. PostgreSQL integration tests in `packages/database/src/audit.integration.test.ts` and `apps/worker/src/modules/audit-exporter.integration.test.ts` require an explicitly designated disposable database via `DBP_AUDIT_TEST_DATABASE_URL`; the tests reject database names that do not begin `dbp_audit_test`. They never use the application's default database URL. Apply `infrastructure/database/roles.sql` before applying migrations. The batch-provenance migration intentionally fails if any export batches already exist; reconcile those records against immutable source events before applying it. No integration test should point at an application or production database.
