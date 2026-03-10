# Sloth Jobs Security Hardening Design

**Date:** 2026-03-09
**Status:** Approved
**Approach:** JWT + TOTP + WebAuthn Passkeys (single admin user)

## Problem

Sloth Jobs is deployed on Railway at a public URL with zero authentication. All 40+ API endpoints are accessible to anyone, including destructive operations (`DELETE /api/database`). Sensitive data — job applications, RxResume credentials, Gmail OAuth tokens, API keys — is stored in plain text in SQLite. No security headers, no rate limiting, CORS allows all origins.

## Architecture Overview

```
                    ┌──────────────────────┐
                    │     Login Page       │
                    │  Passkey (primary)   │
                    │  Password+TOTP (fb)  │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │   Auth Middleware     │
                    │  JWT validation      │
                    │  Rate limiting       │
                    │  Security headers    │
                    └──────────┬───────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
     ┌────────▼──────┐ ┌──────▼──────┐ ┌───────▼───────┐
     │  Standard API  │ │  SSE Streams │ │  Dangerous Ops │
     │  JWT required  │ │  JWT via QP  │ │  Re-auth req'd │
     └───────────────┘ └─────────────┘ └───────────────┘
```

## 1. Database Schema

### `admin` table

| Column | Type | Purpose |
|--------|------|---------|
| `id` | text (cuid2) | Primary key |
| `username` | text UNIQUE | Admin username |
| `passwordHash` | text | bcrypt hash (cost factor 12) |
| `totpSecret` | text | AES-256-GCM encrypted TOTP secret |
| `totpVerified` | integer (0/1) | TOTP confirmed during setup |
| `lockedUntil` | text NULL | ISO timestamp if locked out |
| `failedAttempts` | integer DEFAULT 0 | Consecutive failed logins |
| `createdAt` | text | ISO timestamp |

### `passkeys` table

| Column | Type | Purpose |
|--------|------|---------|
| `id` | text | Credential ID (base64url), PK |
| `adminId` | text | FK to admin |
| `publicKey` | blob | COSE public key |
| `counter` | integer | Signature counter (replay protection) |
| `deviceType` | text | `singleDevice` or `multiDevice` |
| `backedUp` | integer (0/1) | Synced (1Password, iCloud) |
| `transports` | text | JSON array of transport types |
| `friendlyName` | text | User-assigned name |
| `createdAt` | text | ISO timestamp |

### `refreshTokens` table

| Column | Type | Purpose |
|--------|------|---------|
| `id` | text | Token JTI (JWT ID), PK |
| `adminId` | text | FK to admin |
| `expiresAt` | text | Auto-cleanup threshold |
| `revoked` | integer (0/1) | Explicit revocation flag |
| `createdAt` | text | ISO timestamp |

### `auditLog` table

| Column | Type | Purpose |
|--------|------|---------|
| `id` | text (cuid2) | Primary key |
| `action` | text | Event type (see Audit Events below) |
| `adminId` | text NULL | FK to admin (null for failed attempts) |
| `ip` | text | Request IP |
| `userAgent` | text | Request user agent |
| `metadata` | text | JSON details |
| `createdAt` | text | ISO timestamp |

**Audit Events:**
- `login.success`, `login.failed`, `login.locked`
- `webauthn.register`, `webauthn.login.success`, `webauthn.login.failed`
- `token.refresh`, `token.revoke`
- `reauth.success`, `reauth.failed`
- `passkey.register`, `passkey.remove`
- `database.clear`, `backup.restore`, `backup.download`
- `settings.credentials.update`

## 2. New Dependencies

```
@simplewebauthn/server    # Server-side WebAuthn verification
@simplewebauthn/browser   # Client-side WebAuthn API
otplib                    # TOTP generation and verification
qrcode-terminal           # QR display in CLI for setup
bcrypt                    # Password hashing
jsonwebtoken              # JWT signing/verification
helmet                    # Security headers
express-rate-limit        # Rate limiting
```

## 3. CLI Setup (`npm run setup:admin`)

Script: `orchestrator/src/server/scripts/setup-admin.ts`

1. Check if admin already exists — fail with message to run `reset:admin`
2. Prompt for username (stdin)
3. Prompt for password (stdin, hidden) — enforce:
   - Minimum 12 characters
   - At least 1 uppercase, 1 lowercase, 1 number, 1 special char
4. Generate `ENCRYPTION_KEY` (32-byte random hex) if not in env
   - Print: "Add this to your Railway env vars: ENCRYPTION_KEY=<hex>"
5. Hash password with bcrypt (cost 12)
6. Generate TOTP secret via `otplib.authenticator.generateSecret()`
7. Display QR code in terminal (`otpauth://totp/SlothJobs:username?secret=xxx&issuer=SlothJobs`)
8. Prompt for TOTP code to verify setup
9. Encrypt TOTP secret with AES-256-GCM using `ENCRYPTION_KEY`
10. Insert into `admin` table
11. Print summary: username, MFA status, passkey instructions

Additional CLI scripts:
- `npm run reset:admin` — Deletes admin + all passkeys + all refresh tokens (requires `ENCRYPTION_KEY`)
- `npm run unlock:admin` — Clears `lockedUntil` and `failedAttempts`
- `npm run rotate:jwt-secret` — Prints instructions for rotating `JWT_SECRET` via Railway env vars

## 4. Environment Variables (New)

| Variable | Required | Purpose |
|----------|----------|---------|
| `JWT_SECRET` | Yes | HS256 signing key (min 32 chars) |
| `JWT_SECRET_PREVIOUS` | No | Graceful rotation — verify against both, sign with new |
| `ENCRYPTION_KEY` | Yes | 32-byte hex for AES-256-GCM (secrets at rest) |
| `ALLOWED_ORIGIN` | Yes (prod) | CORS origin (`https://sloth-jobs-production.up.railway.app`) |
| `WEBAUTHN_RP_ID` | Yes (prod) | Relying Party ID (`sloth-jobs-production.up.railway.app`) |
| `WEBAUTHN_RP_ORIGIN` | Yes (prod) | Relying Party origin (`https://sloth-jobs-production.up.railway.app`) |

## 5. Login Flows

### Path A — WebAuthn Passkey (primary)

1. Client: `POST /api/auth/webauthn/login/options` → server generates challenge, stores in memory (60s TTL)
2. Client: `@simplewebauthn/browser` triggers 1Password / biometric prompt
3. Client: `POST /api/auth/webauthn/login/verify` with assertion response
4. Server: Validates assertion, increments counter, checks `backedUp` flag
5. Server: Issues JWT access token (15min) + httpOnly refresh cookie (7 days)
6. Audit log: `webauthn.login.success`

### Path B — Password + TOTP (fallback)

1. Client: `POST /api/auth/login` with `{ username, password, totpCode }`
2. Server: Check account lockout (`lockedUntil > now` → 423 Locked)
3. Server: Validate password via `bcrypt.compare()`
4. Server: On password fail → increment `failedAttempts`, audit `login.failed`
   - If `failedAttempts >= 5` → set `lockedUntil = now + 15min`, audit `login.locked`
5. Server: Validate TOTP via `otplib.authenticator.check()` (window: 1 step = ±30s)
6. Server: Reset `failedAttempts` to 0 on success
7. Server: Issues JWT access token + httpOnly refresh cookie
8. Audit log: `login.success`

### Token Refresh

1. Client: `POST /api/auth/refresh` (refresh cookie auto-sent)
2. Server: Validate refresh token JWT, check `refreshTokens` table (not revoked, not expired)
3. Server: Revoke old refresh token, issue new access + new refresh token
4. Audit log: `token.refresh`

### Logout

1. Client: `POST /api/auth/logout` (refresh cookie auto-sent)
2. Server: Revoke refresh token in DB, clear cookie
3. Audit log: `token.revoke`

## 6. Passkey Registration (Post-Login, Settings UI)

1. User navigates to Settings → Security → clicks "Register Passkey"
2. Client: `POST /api/auth/webauthn/register/options` (JWT required)
3. Server: Generates registration challenge (60s TTL), returns options with `rp`, `user`, `excludeCredentials`
4. Client: 1Password / browser prompts passkey creation
5. Client: `POST /api/auth/webauthn/register/verify` with attestation
6. Server: Validates, stores credential in `passkeys` table
7. User can name the passkey ("1Password", "MacBook", etc.)
8. Audit log: `passkey.register`

Multiple passkeys supported. Remove passkey requires re-auth.

## 7. Auth Middleware

### JWT Validation Middleware

```
Location: orchestrator/src/server/middleware/auth.ts

requireAuth(req, res, next):
  1. Extract token from Authorization: Bearer <token>
  2. Verify with JWT_SECRET (fall back to JWT_SECRET_PREVIOUS if set)
  3. Attach admin info to req.auth
  4. 401 if missing/invalid/expired

requireReauth(req, res, next):
  1. First run requireAuth
  2. Extract X-Reauth-Token header
  3. Validate it's a short-lived re-auth JWT (5min, issued after password+TOTP)
  4. 403 if missing/invalid
```

### Re-Authentication Flow

For dangerous operations, the client shows a modal requiring password + TOTP:

1. Client: `POST /api/auth/reauth` with `{ password, totpCode }` (JWT required)
2. Server: Validates password + TOTP against stored credentials
3. Server: Issues short-lived re-auth token (5min, single-use claim)
4. Client: Includes `X-Reauth-Token: <token>` on the dangerous request
5. Audit log: `reauth.success` or `reauth.failed`

## 8. Route Protection Matrix

### Public (no auth)

| Route | Purpose |
|-------|---------|
| `GET /health` | Railway health check |
| `GET /cv/:slug` | Tracer link redirects |
| `POST /api/auth/login` | Password + TOTP login |
| `POST /api/auth/webauthn/login/options` | WebAuthn challenge |
| `POST /api/auth/webauthn/login/verify` | WebAuthn verify |
| `POST /api/auth/refresh` | Token refresh (cookie) |
| `POST /api/auth/logout` | Logout (cookie) |
| `GET /*` (static) | SPA HTML/JS/CSS |

### JWT Required (standard)

All `GET/POST/PATCH/DELETE /api/*` routes not listed above.

### Re-Auth Required (dangerous)

| Route | Operation |
|-------|-----------|
| `DELETE /api/database` | Wipe all data |
| `POST /api/backups/:id/restore` | Overwrite current data |
| `GET /api/backups/:id/download` | Exfiltrate full DB |
| `DELETE /api/jobs/status/:status` | Bulk delete by status |
| `DELETE /api/jobs/score/:threshold` | Bulk delete by score |
| `PATCH /api/settings` | Only when updating credentials (RxResume, Gmail) |

## 9. Security Headers (Helmet)

Applied globally via `helmet()` with overrides:

| Header | Value |
|--------|-------|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `X-XSS-Protection` | `0` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` |

## 10. Rate Limiting

| Scope | Window | Max | Action on Exceed |
|-------|--------|-----|------------------|
| `POST /api/auth/login` | 15 min | 5 | 429 + Retry-After header |
| `POST /api/auth/webauthn/*` | 15 min | 10 | 429 |
| `POST /api/auth/reauth` | 15 min | 5 | 429 |
| `/api/*` (authenticated) | 1 min | 120 | 429 |
| `/health` | none | — | Exempt |

Client-side: Exponential backoff on failed login (1s, 2s, 4s, 8s...).

## 11. CORS

```typescript
cors({
  origin: process.env.ALLOWED_ORIGIN || false,
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Reauth-Token'],
})
```

- Production: `ALLOWED_ORIGIN=https://sloth-jobs-production.up.railway.app`
- Development: `ALLOWED_ORIGIN=http://localhost:3005`
- No wildcard ever

## 12. Secrets Encryption at Rest

### Encryption Utility

```
Location: orchestrator/src/server/lib/encryption.ts

encrypt(plaintext: string, key: string): string
  → Returns "iv:ciphertext:authTag" (hex-encoded)
  → AES-256-GCM with random 12-byte IV

decrypt(stored: string, key: string): string
  → Parses "iv:ciphertext:authTag", decrypts
  → Throws on tampered data (GCM auth tag verification)
```

### What Gets Encrypted

| Data | Location | Currently | After |
|------|----------|-----------|-------|
| TOTP secret | `admin.totpSecret` | N/A (new) | AES-256-GCM |
| RxResume password | `settings` table | Plain text | AES-256-GCM |
| Gmail OAuth tokens | `postApplicationIntegrations.credentials` | Plain JSON | AES-256-GCM on token fields |
| Backup files | `/app/data/backups/` | Raw SQLite | AES-256-GCM encrypted archive |

### Migration of Existing Plain Text

On first boot after upgrade, a migration script:
1. Checks if `ENCRYPTION_KEY` is set
2. Reads existing plain text values from settings/integrations
3. Encrypts and writes back
4. Sets a migration flag in settings to prevent re-running

## 13. Additional Hardening

### PDF Path Traversal Prevention

```typescript
// In PDF serving route
const safeName = path.basename(filename); // Strip ../
const resolved = path.resolve(pdfDir, safeName);
if (!resolved.startsWith(pdfDir)) return res.status(403).end();
```

### Timing-Safe Comparisons

All secret comparisons use `crypto.timingSafeEqual()`:
- Webhook secret validation
- Any internal token comparisons

### SSE Authentication

SSE endpoints (`/api/pipeline/progress`, `/api/jobs/actions/stream`):
- Accept JWT via query parameter: `?token=xxx`
- Server validates JWT on connection
- Connection closed if token expires during stream

### Account Lockout

- 5 consecutive failed logins → lock for 15 minutes
- `admin.lockedUntil` timestamp checked before auth attempt
- CLI unlock: `npm run unlock:admin`
- Audit logged: `login.locked`

### Demo Mode Hardening

- Demo mode enforces full auth stack (no bypass)
- `DELETE /api/database` disabled in production regardless of demo mode
- Demo mode flag checked server-side, not client-controlled

### JWT Secret Rotation

- `JWT_SECRET_PREVIOUS` env var for graceful rotation
- Verification: try `JWT_SECRET` first, fall back to `JWT_SECRET_PREVIOUS`
- Signing: always use `JWT_SECRET` (current)
- After rotation, remove `JWT_SECRET_PREVIOUS` once all old tokens expire (max 7 days)

## 14. Login Page UI

```
┌─────────────────────────────────────┐
│         🦥 Sloth Jobs               │
│                                     │
│  ┌─────────────────────────────┐    │
│  │  🔑 Sign in with Passkey   │    │  ← Hidden if no passkeys registered
│  └─────────────────────────────┘    │
│                                     │
│  ────── or sign in manually ──────  │
│                                     │
│  Username                           │
│  ┌─────────────────────────────┐    │
│  │                             │    │
│  └─────────────────────────────┘    │
│  Password                           │
│  ┌─────────────────────────────┐    │
│  │                             │    │
│  └─────────────────────────────┘    │
│  Authentication Code                │
│  ┌──────┐                           │
│  │      │  ← 6-digit TOTP          │
│  └──────┘                           │
│                                     │
│  ┌─────────────────────────────┐    │
│  │        Sign In              │    │
│  └─────────────────────────────┘    │
│                                     │
│  Account locked? Run:               │
│  npm run unlock:admin               │
└─────────────────────────────────────┘
```

Styled with existing Sloth Jobs cyber teal/dark theme.

## 15. Settings → Security Section (New)

```
Settings → Security
├── Passkeys
│   ├── [List registered passkeys with name, created date]
│   ├── [Register New Passkey] button
│   └── [Remove] button per passkey (requires re-auth)
├── Change Password (requires re-auth)
├── Reset TOTP (requires re-auth, shows new QR)
├── Active Sessions
│   ├── [List active refresh tokens with created date, last used]
│   └── [Revoke All Sessions] button
└── Audit Log
    └── [Table of recent auth events with timestamp, action, IP]
```

## 16. File Changes Summary

### New Files

```
orchestrator/src/server/middleware/auth.ts          # JWT + re-auth middleware
orchestrator/src/server/middleware/rateLimiter.ts    # Rate limiting config
orchestrator/src/server/lib/encryption.ts            # AES-256-GCM utility
orchestrator/src/server/lib/tokens.ts                # JWT issue/verify/refresh
orchestrator/src/server/api/auth.ts                  # Auth routes (login, webauthn, refresh, logout, reauth)
orchestrator/src/server/scripts/setup-admin.ts       # CLI setup
orchestrator/src/server/scripts/reset-admin.ts       # CLI reset
orchestrator/src/server/scripts/unlock-admin.ts      # CLI unlock
orchestrator/src/server/db/migrations/XXXX-auth.ts   # Schema migration
orchestrator/src/client/pages/Login.tsx              # Login page
orchestrator/src/client/components/ReauthModal.tsx   # Re-auth modal
orchestrator/src/client/pages/SecuritySettings.tsx   # Security settings section
orchestrator/src/client/lib/auth.ts                  # Client auth utilities (token storage, refresh, interceptors)
```

### Modified Files

```
orchestrator/src/server/app.ts                       # Add helmet, CORS config, auth middleware, rate limiters
orchestrator/src/server/db/schema.ts                 # Add admin, passkeys, refreshTokens, auditLog tables
orchestrator/src/server/api/index.ts                 # Wire auth routes, protect existing routes
orchestrator/src/server/api/settings.ts              # Encrypt credentials on write, decrypt on read
orchestrator/src/server/api/database.ts              # Add re-auth requirement
orchestrator/src/server/api/backups.ts               # Add re-auth for download/restore
orchestrator/src/server/api/jobs.ts                  # Add re-auth for bulk deletes
orchestrator/src/server/services/tracer-links.ts     # No change (already public)
orchestrator/src/client/main.tsx                     # Add auth provider, route guards
orchestrator/src/client/App.tsx                      # Wrap with auth context
orchestrator/package.json                            # Add new dependencies
Dockerfile                                           # No change expected
railway.toml                                         # No change (env vars set in dashboard)
```
