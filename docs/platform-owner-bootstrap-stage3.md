# Stage 3: Platform owner bootstrap

## Scope and security boundary

Stage 3 establishes the first platform owner through an explicitly authorized operator using the server-side `@platform/api` CLI. There is no bootstrap HTTP endpoint, first-user-wins behavior, email matching, user provisioning, ordinary administrator privilege, owner transfer, or recovery flow. The canonical principal is an existing active `PlatformUser`; its OIDC identity is the exact `(issuer, subject)` pair and must have database verification provenance.

Identity linking is a narrowly scoped prerequisite. An operator explicitly selects an existing user and starts a five-minute challenge. The identity holder completes a fresh Authorization Code + PKCE flow directly with the configured OIDC provider. Redis stores one-time state, nonce, and verifier material; callback processing validates state, nonce, PKCE, issuer, subject, and recent `auth_time`. A restricted callback database function records the exact mapping and provenance. Email claims are discarded. The mapping is immutable through this path, and an already-linked identity cannot be reassigned. Identity linking neither sets nor implies owner authority.

The operator login must be explicitly authorized by the platform's DBA/security process for `dbp_identity_link_operator` or `dbp_platform_owner_operator`; migrations create only `NOLOGIN` capability roles and do not grant these capabilities to ordinary administrators. Provision login roles and grant capability membership out of band. Do not put privileged passwords in migrations or ordinary API/worker configuration.

## CLI lifecycle

Run commands only from a trusted server terminal with the relevant narrowly scoped environment variables and OIDC/Redis services configured. The CLI loads its runtime environment through dotenv; operators should use the protected deployment environment and must never paste secrets into shell arguments or logs.

1. Link an identity only when the selected existing user lacks verified provenance:

   ```sh
   npm run platform -- identity-link <existing-platform-user-uuid>
   ```

   The operator confirms with `LINK`. The CLI prints an authorization URL for the identity holder. Complete it within five minutes in that holder's browser. The API callback records success or a bounded rejection outcome and does not create a login session.
2. Issue a one-time owner credential after confirming the intended active user:

   ```sh
   npm run platform -- owner-credential issue <existing-platform-user-uuid>
   ```

   The CLI asks for `ISSUE OWNER CREDENTIAL`, stores only a purpose-bound HMAC verifier and displays the random credential once. Store it in an approved secret channel. It expires after 15 minutes. `PLATFORM_OWNER_VERIFIER_KEY` is external key material (32 or more random bytes, base64url); retain its key id and provide the same key only in the trusted operator environment. Rotation/recovery of that key is not implemented by this milestone.
3. Prepare the one-time designation:

   ```sh
   npm run platform -- owner-bootstrap run <existing-platform-user-uuid>
   ```

   The operator confirms with `BOOTSTRAP OWNER`; the CLI reads the credential without terminal echo. This creates a PENDING designation and a Stage 2 critical operation. The credential is consumed transactionally. A lost response can be checked without resubmitting the credential:

   ```sh
   npm run platform -- owner-bootstrap status <credential-uuid>
   ```

   Status accepts the credential UUID, not the secret. The credential is never accepted as an argument.

Credential issuance is refused when the platform is initialized, another designation is pending/active, another unexpired credential is active, the user is missing/inactive, or exactly one verified identity for the configured issuer cannot be established. Bootstrap is revalidated under database locks; no identity is created or changed by bootstrap.

## Designation and critical-operation lifecycle

`platform_initialization` is a durable singleton seeded UNINITIALIZED. A unique partial index permits at most one live PENDING or ACTIVE designation. The designation begins PENDING and cannot grant authority. The existing Stage 2 engine records the critical operation and advances it through the existing audit, archive receipt, and finalization state machine. The database activation trigger requires the operation to be READY_TO_ACTIVATE, the existing qualifying receipt boundary to return a verified receipt, the critical-operation service role, the pending designation, an uninitialized singleton, an active platform user, and verification provenance.

Designation activation, initialization completion, `platform-owner-designation-activated` audit append, and critical-operation completion occur within the Stage 2 finalization transaction. If any step fails, PostgreSQL rolls back the entire transaction and the operation remains retryable. A failed critical operation moves the pending designation to FAILED with a bounded audit outcome. The one-time initialization row cannot be deleted, reset, or recreated by ordinary roles. There is no owner revocation or transfer path in this milestone.

## Database responsibilities

| Capability | Database boundary |
| --- | --- |
| Start identity link | `dbp_identity_link_operator` executes `begin_platform_identity_link` |
| Complete/reject identity link | `dbp_identity_link_callback` executes completion/rejection functions |
| Issue/prepare owner bootstrap and read status | `dbp_platform_owner_operator` executes the owner operator functions |
| Advance critical operations and activate designation | Existing `dbp_critical_operation_service` flow; owner activation is a restricted trigger in the same finalization transaction |
| Verify and record archive receipts | Existing Stage 1 receipt verifier boundary; no Stage 3 receipt bypass |
| Resolve current owner authority | Runtime may execute `resolve_active_platform_owner`; it receives no direct write privilege on protected owner tables |

The `dbp_platform_owner_owner` and `dbp_identity_link_owner` roles are `NOLOGIN`; migrations assign protected `SECURITY DEFINER` functions to these roles and grant only the table privileges those functions require. Runtime, archive, and ordinary admin roles cannot directly mutate owner designations, initialization, identity verification provenance, or credential lifecycle. Audit events use the existing append-only audit store and hash/archive pipeline. Payloads contain bounded outcomes and safe IDs only, never credentials, verifiers, OIDC tokens, authorization codes, or session identifiers.

## Owner checks

`resolve_active_platform_owner` consults the current initialization singleton, active designation, active user, and verified identity provenance in PostgreSQL. Pending, failed, missing, inconsistent, or inactive-user states do not resolve. Callers performing a sensitive database action must invoke the check and the action in the same database transaction (the API helper `withActivePlatformOwner` provides that transaction shape). A branded TypeScript designation is a compile-time aid only and is not runtime proof. Owner authority remains separate from authentication and does not confer venture authority or override workforce governance.

## Operations, failure and production gate

Required variables are listed as placeholders in `.env.example`: OIDC issuer/client/callback settings, Redis, `IDENTITY_LINK_OPERATOR_DATABASE_URL`, `IDENTITY_LINK_CALLBACK_DATABASE_URL`, `PLATFORM_OWNER_OPERATOR_DATABASE_URL`, `PLATFORM_OWNER_VERIFIER_KEY_ID`, and `PLATFORM_OWNER_VERIFIER_KEY`. Configure them in a protected server environment; never commit actual values. The callback uses the existing OIDC callback route and exact configured issuer. Keycloak redirect URI/web-origin settings must match that established callback configuration.

Use the status command to determine whether a credential was consumed and its operation/designation/initialization states. A credential can be issued only once while live and cannot be replayed after consumption. If a critical operation is awaiting archive, leave it to the existing worker/reconciliation process; do not manually activate a designation or edit initialization state. Stage 2 retry and reconciliation behavior remains authoritative.

The local archive integration suite exercises a real local receiver and receipt verifier, but does not demonstrate independent production archive deployment, credentials, signing keys, or failure domains. Production activation must remain disabled until the physical and hosted archive deployments are separately configured and their independent acceptance, signing, verification, and outage behavior are operationally verified. Local tests do not establish production archive independence.

## Explicitly out of scope

Owner transfer, succession, recovery codes, account recovery, machine principals, venture authority grants, a full policy evaluator, and general-purpose identity administration are future work and are not implemented here.
