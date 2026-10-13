# Account authentication sessions

Identity owns account authentication and login sessions. A session UUID identifies a phone login, not a Desktop. Tunnel Hub owns Desktop registration, membership, online state and connection tickets.

- POST `/api/auth/account/login`: username, password and deviceName; returns schemaVersion, accountId, username, deviceId, deviceName, accessToken, accessTokenExpireAt and deviceToken.
- POST `/api/auth/refresh`: deviceToken; refreshes access and rotates the persistent credential according to the existing rotation configuration.
- GET `/api/auth/me`: validates the current active account and session; exposes accountId and deviceId for Hub authentication checks.
- POST `/api/auth/logout`: revokes only the current login session.

QR login creates a two-minute challenge. The QR contains only challengeId; the separate high-entropy claimToken remains with the claimant. An authenticated account confirms it, and claim atomically checks the confirmer and account are still active before consuming it once. Password and QR login return the same session contract. There are no trust tiers or Desktop device-management APIs here.

Account device credentials are hashed; account access-token audits store only a digest. Legacy local-service app authentication remains separate, and legacy device operations cannot access account-session records.

Schema initialization only adds ACCOUNT_ID_ to the existing DEVICE_ table and creates LOGIN_CHALLENGE_. Existing legacy device records remain unassigned to accounts. No signing-key or issuer migration is performed. The initialization fallback DDL is retained because AUTH_SCHEMA_PATH can still point to a legacy external schema file; both embedded and external initialization must create the account/challenge tables.

## 2026-10-12 call-site audit

| Implementation | Current consumer | Decision |
| --- | --- | --- |
| Account password login and account session credential | Mobile `accountAuth.loginWithAccountCredentials` | Required |
| Refresh and logout of account session | Mobile bootstrap/refresh/logout | Required; invalid, revoked, disabled-account or already-rotated credentials return 401 so the client can clear them |
| Account-bound JWT and `/api/auth/me` | Tunnel Hub `validateAccountSession` for account Desktop access | Required; accountId/deviceId must match and issuedAt reflects the token issue time |
| ACCOUNT_ID_ column migration, account namespace filters and both schema entrypoints | Mobile session ownership and embedded/external Identity startup | Required; old rows stay unassigned, legacy external schema initialization remains supported |
| Login challenge create / confirm / claim | Mobile `AccountChallengeLogin` and `AccountLoginApproval` | Keep existing used flow; no new QR capability |
| Challenge GET detail endpoint | No current mobile, Desktop or Hub consumer | Removed |
| Legacy `/api/auth/pairing/start` and `/api/auth/pairing/claim` | No current mobile, Desktop or Hub consumer; replaced by account login and account challenge | Removed along with the in-memory ticket map, ticket helpers and legacy-only tests |
| Admin-issued App Token, generic legacy device storage and OAuth/OIDC | Identity admin `SecurityPage` / `AppAccessPage`, program CLI and Desktop SSO | Keep; account sessions remain isolated from the legacy device namespace |

Account and challenge secrets share the existing 32-byte random-secret helper. Expired challenge rows are removed by the existing cleanup cron after the configured retention period; there is no new worker or polling system. Failed session revocation returns an error rather than reporting successful logout.

This review modifies Identity source only. It does not change cloud Token authentication, mobile/Hub/Desktop source, live databases, keys, environment configuration, dependency files or deployments. The pre-existing uncommitted account-session implementation and its used login-challenge flow are retained. Local test evidence and cleanup results follow.

## Verification and cleanup

- `make backend-test`: all backend packages pass, including admin-issued App Token and program CLI compatibility, account lifecycle/rotation, disabled accounts, logout write failure, revocation during validation, challenge concurrency, expiry cleanup and embedded/legacy-external schema initialization.
- `go test -race ./internal/app ./internal/store ./internal/db`: passes the account/challenge concurrency and storage checks.
- `go vet ./...`, `gofmt` and `git diff --check`: pass.
- Review baseline: HEAD `f0e009c` and the existing working tree were recorded before mutation. Only the nine reviewed implementation/test/document paths were changed; the legacy pairing test was deliberately removed and its still-used JSON response decoder retained in the existing App Token test fixture.
- Existing schema/model/legacy-store changes, frontend, dependency files, environment files, branch, HEAD and staged contents remain as before this review. No service was deployed or live database changed.
- Go build cache, test temporary paths and network/module flags were process scoped. Task-owned draft copies, patches, build cache and logs were kept under a dedicated temporary directory and removed after the final audit.
