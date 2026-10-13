# Account email authentication (2026-10-13)

Email login signs into an existing ACTIVE account with a verified binding. It never registers or merges an account. The original password/QR session contract and device credentials are unchanged.

| Method and path | Authentication | JSON body / result |
| --- | --- | --- |
| GET `/api/auth/account/security` | Account bearer | security summary |
| POST `/api/auth/account/email/challenges` | Public | email, requestId → opaque receipt |
| POST `/api/auth/account/email/login` | Public | challengeId, code, deviceName → original AccountSession |
| POST `/api/auth/account/email/bind/challenges` | Account bearer | email, requestId → challenge |
| POST `/api/auth/account/email/bind` | Account bearer | challengeId, code → security summary |
| POST `/api/auth/account/email/unbind/challenges` | Account bearer | requestId → challenge |
| POST `/api/auth/account/email/unbind` | Account bearer | challengeId, code → security summary |
| POST `/admin/api/users/{userId}/email/unbind` | Existing admin session | confirmed: true, reason (1–500 characters) → 204 |

Security: `schemaVersion: 1`, accountId, username, emailBinding (`null` or `{email, boundAt}`). Only this authenticated summary exposes a full email. Challenge/receipt: `schemaVersion: 1`, challengeId (UUID), expiresAt, resendAvailableAt, serverTime (UTC RFC3339). Code is a six-digit **string**, not an integer. requestId is a UUID scoped by purpose, initiating account/device and normalized mailbox. Reusing it never sends again or resets quotas. Consumed login results are not replayed.

Errors: 400 `email_invalid_request`, 401 `email_authentication_failed` (all invalid email verification), 401 account session required (existing middleware), 409 `email_unavailable`, 429 `email_rate_limited` with retryAt/serverTime and Retry-After, 503 `email_unavailable_service`. Application OTP failure is not an expired bearer: clients must not refresh and retry it automatically.

ASCII single mailbox only. Trim outer whitespace; lowercase the entire match key; keep verified delivery spelling, dots and +tags. One account/one mailbox enforced by SQLite uniqueness. Login/unbind recheck ACTIVE user, session where required, purpose, binding ID, expiry, failure count and consumption. Bind challenges require the initiating device. Unbind invalidates unfinished challenges without revoking any device session. Bcrypt device credential preparation and SMTP I/O occur outside the write transaction; challenge consumption and session/binding writes are atomic.

Six digits, five-minute validity, 60-second resend cooldown, five failed verifications per challenge. Accepted resends invalidate the old same-purpose code; failed/unknown sends preserve it and cannot authenticate. HMAC digests protect codes; only the immediate SMTP call sees plaintext. Limits and cooldowns survive restart in SQLite; expired challenges/counters are cleaned by the existing cleanup cron after a fixed retention. Audit retains the actor, action, reason and a keyed mailbox digest; it contains neither plaintext email nor code.

## Public receipt decision

The user approved opaque public receipts on 2026-10-13. Unknown/disabled mailboxes do not send mail. Configured SMTP rejection or unknown final reply still returns the same receipt shape and bounded timing; the unconfirmed challenge cannot be consumed. Receipts and duplicate receipts never reveal delivery status. Public replies wait the configured SMTP timeout (default five seconds), with timestamps set to that fixed completion boundary. Quota/format rejection is immediate and independent of binding. This avoids account enumeration without queues, automatic retries or a delivery-status endpoint. A receipt does **not** mean mail reached the inbox. Authenticated bind/unbind sends can show a service failure and keep the prior valid challenge.

## Deployment and rollback

Email authentication is a separate review and release unit from account sessions and Desktop access. Its scope is the email handlers/SMTP sender, email storage/configuration, four email tables, admin unbind action and corresponding tests. It reuses the existing account session contract; Hub and Desktop protocols require no email-specific changes.

Both `AUTH_EMAIL_LOGIN_ENABLED` and `AUTH_EMAIL_BIND_ENABLED` default false. `.env.example` declares the one SMTP sender and positive quotas. Set TLS to `tls` or `starttls`; certificate verification is mandatory. Timeout is 1–10 seconds. Configure a random digest key of at least 32 bytes, SMTP host/port, username/password, From and display name. Credentials stay in server environment configuration; never send them to the App. The default quotas (email 5/hour, 10/day; account 10/hour, 20/day; peer IP 30/hour, 100/day; failed verification 20/hour) are conservative configurable development defaults, pending provider/traffic validation. Public login uses mailbox/IP sending quotas; the one-to-one binding keeps the stricter mailbox quota effective for its account. All purposes share mailbox quota and cumulative failures.

IP keys use the actual TCP peer, ignoring arbitrary forwarded headers. With the repository's frontend reverse proxy, this is a shared gateway limit; tune it to verified traffic before enabling production. Do not assume forwarded headers are trustworthy or add distributed storage without an actual deployment need.

The two schema files create the new tables idempotently in existing databases. Tests migrate only temporary databases. Repository compose describes one backend and a `/data` mount; production topology, SMTP sender ownership/permission, real recipient tests and App devices have not been verified. Existing website email login is evidence of a deployed email capability, not evidence that its account IDs, SMTP configuration or registration policy match this Identity service. Locate its deployment owner and copy only verified server-side SMTP settings through secure configuration.

Deploy the compatible backend with both switches false, verify migration and existing password/QR/refresh/logout, then publish App and enable each switch deliberately. Rollback disables new login and binding, preserves binding/audit data, existing sessions, user/admin unbinding and password login. No live deployment or real email has been performed by this implementation task.
