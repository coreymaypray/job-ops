# One-Time Admin Setup API

## Problem

SlothJobs uses SQLite on the Railway container. The existing CLI setup script (`setup-admin.ts`) can't access the remote database file. We need an API-based setup flow so the admin account can be created through the browser.

## Design

Two endpoints that auto-disable once an admin exists (return 404).

### `POST /api/auth/setup`

- **Guard:** admin exists → 404
- **Rate limit:** 3 requests / 15 minutes (per IP)
- **Input:** `{ username: string, password: string }`
- **Password validation:** 12+ chars, uppercase, lowercase, number, special character
- **Behavior:**
  1. Generates TOTP secret via `otplib`
  2. Creates QR code data URI (otpauth:// format, issuer "SlothJobs")
  3. Stores pending setup in memory (see Pending State below)
  4. Returns `{ qrCodeDataUri, manualKey, setupToken }`

### `POST /api/auth/setup/verify`

- **Guard:** admin exists → 404
- **Rate limit:** 3 requests / 15 minutes (per IP)
- **Input:** `{ setupToken: string, totpCode: string }`
- **Behavior:**
  1. Looks up pending setup by token
  2. Validates TOTP code against stored secret
  3. On success: bcrypt hash password (12 rounds), encrypt TOTP secret (AES-256-GCM), insert admin row with CUID2 id
  4. Clears pending state
  5. Returns `{ success: true }`

### Pending State

- In-memory `Map<setupToken, PendingSetup>`
- `PendingSetup`: `{ username, password, totpSecret, expiresAt }`
- Token: 32 bytes crypto random (hex)
- Expiry: 5 minutes
- Max 1 pending setup at a time (new request overwrites old)
- Password stored plaintext in memory until verify step (never persisted unhashed)

### Client Flow

1. App loads → calls `GET /api/auth/check`
2. Response `{ exists: false }` → show setup form (username + password)
3. Submit → `POST /api/auth/setup` → receive QR code
4. Display QR code + manual key → user scans with authenticator
5. User enters 6-digit code → `POST /api/auth/setup/verify`
6. Success → redirect to login page

### Security

- Same bcrypt (12 rounds) and AES-256-GCM encryption as CLI script
- Rate limited at 3 req/15 min (stricter than login's 5 req/15 min)
- Endpoints return 404 once admin exists — zero attack surface after setup
- TOTP verification required before admin is created (no partial state in DB)
- Setup token is cryptographically random, single-use, expires in 5 minutes

## Files to Modify

- `orchestrator/src/server/api/routes/auth.ts` — add setup + verify routes
- `orchestrator/src/client/` — add setup page UI (form, QR display, TOTP input)

## Out of Scope

- Multi-admin support
- Password-only setup (TOTP always required)
- Email-based setup
