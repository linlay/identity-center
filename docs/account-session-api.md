# Account authentication sessions

Identity owns account authentication and login sessions. A session UUID identifies a phone login, not a Desktop. Tunnel Hub owns Desktop registration, membership, online state and connection tickets.

- POST `/api/auth/account/login`: username, password and deviceName; returns schemaVersion, accountId, username, deviceId, deviceName, accessToken, accessTokenExpireAt and deviceToken.
- POST `/api/auth/refresh`: deviceToken; refreshes access and rotates the persistent credential according to the existing rotation configuration.
- GET `/api/auth/me`: validates the current active account and session; exposes accountId and deviceId for Hub authentication checks.
- POST `/api/auth/logout`: revokes only the current login session.


Account device credentials are hashed; account access-token audits store only a digest. Legacy local-service app authentication remains separate, and legacy device operations cannot access account-session records.

OIDC userinfo accepts OAuth access tokens only, identified by audience `app-api` and a nonempty `client_id`. Account and legacy App Tokens cannot be used as OAuth tokens, including after account logout.

Both schema entrypoints use the embedded schema to create missing required tables, including email authentication. AUTH_SCHEMA_PATH is executed first when configured. The existing DEVICE_ table receives only the missing ACCOUNT_ID_ column and its account index; old rows remain unassigned to accounts. A frozen pre-account schema tests first and repeated initialization without changing legacy users or device credentials. No signing-key or issuer migration is performed.

## Consumers and retired endpoints

| Implementation | Current consumer | Decision |
| --- | --- | --- |
| Account password login and account session credential | Mobile `accountAuth.loginWithAccountCredentials` | Required |
| Refresh and logout of account session | Mobile bootstrap/refresh/logout | Required; invalid, revoked, disabled-account or already-rotated credentials return 401 so the client can clear them |
| Account-bound JWT and `/api/auth/me` | Tunnel Hub `validateAccountSession` for account Desktop access | Required; accountId/deviceId must match and issuedAt reflects the token issue time |
| ACCOUNT_ID_ column migration, account namespace filters and both schema entrypoints | Mobile session ownership and embedded/external Identity startup | Required; old rows stay unassigned, legacy external schema initialization remains supported |
| Legacy `/api/auth/pairing/start` and `/api/auth/pairing/claim` | No current mobile, Desktop or Hub consumer; replaced by account login and Hub account Desktop access | Removed along with the in-memory ticket map, ticket helpers and legacy-only tests |
| Admin-issued App Token, generic legacy device storage and OAuth/OIDC | Identity admin `SecurityPage` / `AppAccessPage`, program CLI and Desktop SSO | Keep; account sessions remain isolated from the legacy device namespace |

Account session credentials use a 32-byte random secret. No cross-device QR login or login-challenge store is provided. Failed session revocation returns an error rather than reporting successful logout.

## Review and release boundary

The removed `/api/auth/pairing/start` and `/api/auth/pairing/claim` endpoints return 404. Before deploying, verify that deployed clients use password/email account login and the current Hub/Desktop connection protocol. Updating the backend first does not preserve those old clients' pairing flow. The current mobile, Desktop and Hub source has no callers; no unused compatibility implementation is retained.

Review account sessions and Desktop access separately from email authentication. First deploy with both email entry switches disabled and verify password login, refresh, me, logout, Hub ownership checks and Desktop ticket validation. Email binding/login and SMTP readiness follow the independent checklist in account-email-api.md. This ordering does not introduce another token format or session store.

Regression commands: `make backend-test`, `go test -race ./internal/app ./internal/store ./internal/db`, `go vet ./...` and `git diff --check`. Tests use temporary databases; real deployment and devices require separate acceptance.

## Deferred feature: password login attempt limits

Recorded on 2026-10-14 against `aee3a54`. Status: feature backlog; implementation deferred by user decision. This entry does not change current authentication behavior.

The public `POST /api/auth/account/login` handler (`backend/internal/app/server.go`, `handleAccountAppLogin`) and the default Nginx configuration have no password-attempt limit. A local HTTP reproduction made 30 consecutive incorrect-password requests for one active account; every request returned 401, and an immediate correct-password request returned 200. Repeated guessing also incurs bcrypt work for active accounts.

Feature scope: limit password attempts by normalized account identifier and trusted client IP, define a retry window and a 429 response, and preserve normal login and the existing account session contract. Determine thresholds when this feature is scheduled.

Acceptance: requests exceeding the configured threshold return 429; login recovers after the retry window; independent accounts/clients retain their intended quotas; forged forwarding headers cannot bypass the client limit. Cover both direct access and the default Nginx gateway path.
