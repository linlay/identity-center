# Account authentication sessions

Identity owns account authentication and login sessions. A session UUID identifies a phone login, not a Desktop. Tunnel Hub owns Desktop registration, membership, online state and connection tickets.

- POST `/api/auth/account/login`: username, password and deviceName; returns schemaVersion, accountId, username, deviceId, deviceName, accessToken, accessTokenExpireAt and deviceToken.
- POST `/api/auth/refresh`: deviceToken; refreshes access and rotates the persistent credential according to the existing rotation configuration.
- GET `/api/auth/me`: validates the current active account and session; exposes accountId and deviceId for Hub authentication checks.
- POST `/api/auth/logout`: revokes only the current login session.

QR login creates a two-minute challenge. The QR contains only challengeId; the separate high-entropy claimToken remains with the claimant. An authenticated account confirms it, and claim atomically checks the confirmer and account are still active before consuming it once. Password and QR login return the same session contract. There are no trust tiers or Desktop device-management APIs here.

Account device credentials are hashed; account access-token audits store only a digest. Legacy local-service app authentication remains separate, and legacy device operations cannot access account-session records.

OIDC userinfo accepts OAuth access tokens only, identified by audience `app-api` and a nonempty `client_id`. Account and legacy App Tokens cannot be used as OAuth tokens, including after account logout.

Both schema entrypoints use the embedded schema to create missing required tables, including login challenges and email authentication. AUTH_SCHEMA_PATH is executed first when configured. The existing DEVICE_ table receives only the missing ACCOUNT_ID_ column and its account index; old rows remain unassigned to accounts. Go does not duplicate challenge-table DDL. A frozen pre-account schema tests first and repeated initialization without changing legacy users or device credentials. No signing-key or issuer migration is performed.

## Consumers and retired endpoints

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

## Review and release boundary

The removed `/api/auth/pairing/start` and `/api/auth/pairing/claim` endpoints return 404. Before deploying, verify that deployed clients have migrated from this legacy pairing protocol to account login/challenges or the current Desktop connection protocol. Updating the backend first does not preserve those old clients' pairing flow. The current mobile, Desktop and Hub source has no callers; no unused compatibility implementation is retained.

Review account sessions, QR login and Desktop access separately from email authentication. First deploy with both email entry switches disabled and verify password/QR login, refresh, me, logout, Hub ownership checks and Desktop ticket validation. Email binding/login and SMTP readiness follow the independent checklist in account-email-api.md. This ordering does not introduce another token format or session store.

Regression commands: `make backend-test`, `go test -race ./internal/app ./internal/store ./internal/db`, `go vet ./...` and `git diff --check`. Tests use temporary databases; real deployment and devices require separate acceptance.
