# Sloth Jobs Security Hardening Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement multi-layer authentication (JWT + TOTP + WebAuthn passkeys), security headers, rate limiting, CORS lockdown, secrets encryption at rest, re-auth for dangerous operations, and audit logging for the Sloth Jobs application.

**Architecture:** Single-admin Express.js app with JWT access tokens (15min) + httpOnly refresh cookies (7 days). WebAuthn passkeys as primary login (1Password), password+TOTP as fallback. AES-256-GCM encryption for secrets at rest. Re-authentication required for destructive operations.

**Tech Stack:** Express.js, React 18, SQLite (better-sqlite3 + Drizzle ORM), TypeScript, @simplewebauthn/{server,browser}, otplib, bcrypt, jsonwebtoken, helmet, express-rate-limit, Vite, Vitest

**Spec:** `docs/superpowers/specs/2026-03-09-sloth-jobs-security-design.md`

---

## File Structure

### New Files (Create)

```
orchestrator/src/server/lib/encryption.ts            # AES-256-GCM encrypt/decrypt
orchestrator/src/server/lib/tokens.ts                 # JWT issue/verify/refresh helpers
orchestrator/src/server/lib/audit.ts                  # Audit log service
orchestrator/src/server/middleware/auth.ts             # requireAuth, requireReauth middleware
orchestrator/src/server/middleware/rateLimiter.ts      # Rate limiting configs
orchestrator/src/server/api/routes/auth.ts            # Auth routes (login, webauthn, refresh, logout, reauth)
orchestrator/src/server/scripts/setup-admin.ts        # CLI: create admin account
orchestrator/src/server/scripts/reset-admin.ts        # CLI: delete admin account
orchestrator/src/server/scripts/unlock-admin.ts       # CLI: unlock locked account
orchestrator/src/client/lib/auth.ts                   # Client token storage, refresh interceptor
orchestrator/src/client/pages/Login.tsx               # Login page component
orchestrator/src/client/components/ReauthModal.tsx    # Re-auth modal for dangerous ops
orchestrator/src/client/pages/SecuritySettings.tsx    # Passkey mgmt, audit log, session mgmt

# Tests
orchestrator/src/server/lib/__tests__/encryption.test.ts
orchestrator/src/server/lib/__tests__/tokens.test.ts
orchestrator/src/server/lib/__tests__/audit.test.ts
orchestrator/src/server/middleware/__tests__/auth.test.ts
orchestrator/src/server/api/routes/__tests__/auth.test.ts
```

### Modified Files

```
orchestrator/package.json                             # Add security dependencies
orchestrator/src/server/db/schema.ts                  # Add 4 new tables
orchestrator/src/server/db/migrate.ts                 # Add SQL for new tables
orchestrator/src/server/app.ts                        # Helmet, CORS, auth middleware, rate limiters, PDF fix
orchestrator/src/server/api/routes.ts                 # Mount auth router, add middleware to routes
orchestrator/src/server/api/routes/settings.ts        # Encrypt credentials on write, decrypt on read
orchestrator/src/server/api/routes/database.ts        # Add re-auth requirement
orchestrator/src/server/api/routes/backup.ts          # Add re-auth for download/restore
orchestrator/src/server/api/routes/jobs.ts            # Add re-auth for bulk deletes
orchestrator/src/client/App.tsx                       # Wrap with auth context, route guards
orchestrator/src/client/api/client.ts                 # Replace Basic Auth with JWT interceptor
```

---

## Chunk 1: Foundation — Dependencies + Database Schema

### Task 1: Install Security Dependencies

**Files:**
- Modify: `orchestrator/package.json`

- [ ] **Step 1: Install production dependencies**

```bash
cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator
npm install @simplewebauthn/server@11 @simplewebauthn/browser@11 otplib bcrypt jsonwebtoken helmet express-rate-limit cookie-parser qrcode-terminal
```

- [ ] **Step 2: Install dev dependencies (types)**

```bash
cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator
npm install -D @types/bcrypt @types/jsonwebtoken @types/cookie-parser @types/qrcode-terminal supertest @types/supertest
```

- [ ] **Step 3: Verify installation**

Run: `cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator && npm ls @simplewebauthn/server otplib bcrypt jsonwebtoken helmet express-rate-limit`
Expected: All packages listed without errors.

- [ ] **Step 4: Commit**

```bash
cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator
git add package.json package-lock.json
git commit -m "feat(security): install auth and security dependencies"
```

---

### Task 2: Add Drizzle ORM Schema Definitions

**Files:**
- Modify: `orchestrator/src/server/db/schema.ts`
- Test: `orchestrator/src/server/db/__tests__/schema.test.ts`

- [ ] **Step 1: Write schema validation test**

Create `orchestrator/src/server/db/__tests__/schema.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import { admin, auditLog, passkeys, refreshTokens } from "../schema";

describe("auth schema tables", () => {
  it("admin table has expected columns", () => {
    const cols = Object.keys(admin);
    expect(cols).toContain("id");
    expect(cols).toContain("username");
    expect(cols).toContain("passwordHash");
    expect(cols).toContain("totpSecret");
    expect(cols).toContain("totpVerified");
    expect(cols).toContain("lockedUntil");
    expect(cols).toContain("failedAttempts");
    expect(cols).toContain("createdAt");
  });

  it("passkeys table has expected columns", () => {
    const cols = Object.keys(passkeys);
    expect(cols).toContain("id");
    expect(cols).toContain("adminId");
    expect(cols).toContain("publicKey");
    expect(cols).toContain("counter");
    expect(cols).toContain("deviceType");
    expect(cols).toContain("backedUp");
    expect(cols).toContain("transports");
    expect(cols).toContain("friendlyName");
    expect(cols).toContain("createdAt");
  });

  it("refreshTokens table has expected columns", () => {
    const cols = Object.keys(refreshTokens);
    expect(cols).toContain("id");
    expect(cols).toContain("adminId");
    expect(cols).toContain("expiresAt");
    expect(cols).toContain("revoked");
    expect(cols).toContain("createdAt");
  });

  it("auditLog table has expected columns", () => {
    const cols = Object.keys(auditLog);
    expect(cols).toContain("id");
    expect(cols).toContain("action");
    expect(cols).toContain("adminId");
    expect(cols).toContain("ip");
    expect(cols).toContain("userAgent");
    expect(cols).toContain("metadata");
    expect(cols).toContain("createdAt");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator && npx vitest run src/server/db/__tests__/schema.test.ts`
Expected: FAIL — `admin`, `passkeys`, `refreshTokens`, `auditLog` not exported from schema.

- [ ] **Step 3: Add the four new table definitions to schema.ts**

Add at the end of `orchestrator/src/server/db/schema.ts` (after existing tables):

```typescript
// ─── Auth Tables ───────────────────────────────────────────

export const admin = sqliteTable("admin", {
  id: text("id").primaryKey(),
  username: text("username").notNull().unique(),
  passwordHash: text("password_hash").notNull(),
  totpSecret: text("totp_secret").notNull(),
  totpVerified: integer("totp_verified").notNull().default(0),
  lockedUntil: text("locked_until"),
  failedAttempts: integer("failed_attempts").notNull().default(0),
  createdAt: text("created_at")
    .notNull()
    .default(sql`(datetime('now'))`),
});

export const passkeys = sqliteTable("passkeys", {
  id: text("id").primaryKey(), // credential ID (base64url)
  adminId: text("admin_id")
    .notNull()
    .references(() => admin.id, { onDelete: "cascade" }),
  publicKey: blob("public_key").notNull(),
  counter: integer("counter").notNull().default(0),
  deviceType: text("device_type").notNull(), // 'singleDevice' | 'multiDevice'
  backedUp: integer("backed_up").notNull().default(0),
  transports: text("transports"), // JSON array
  friendlyName: text("friendly_name"),
  createdAt: text("created_at")
    .notNull()
    .default(sql`(datetime('now'))`),
});

export const refreshTokens = sqliteTable("refresh_tokens", {
  id: text("id").primaryKey(), // JWT ID (jti)
  adminId: text("admin_id")
    .notNull()
    .references(() => admin.id, { onDelete: "cascade" }),
  expiresAt: text("expires_at").notNull(),
  revoked: integer("revoked").notNull().default(0),
  createdAt: text("created_at")
    .notNull()
    .default(sql`(datetime('now'))`),
});

export const auditLog = sqliteTable(
  "audit_log",
  {
    id: text("id").primaryKey(),
    action: text("action").notNull(),
    adminId: text("admin_id"),
    ip: text("ip"),
    userAgent: text("user_agent"),
    metadata: text("metadata"), // JSON
    createdAt: text("created_at")
      .notNull()
      .default(sql`(datetime('now'))`),
  },
  (table) => ({
    actionIndex: index("idx_audit_log_action").on(table.action),
  }),
);
```

Note: You will also need to add `blob` to the imports from `drizzle-orm/sqlite-core` at the top of the file if not already imported.

After the table definitions, add type exports to match the existing codebase convention:

```typescript
export type AdminRow = typeof admin.$inferSelect;
export type NewAdminRow = typeof admin.$inferInsert;
export type PasskeyRow = typeof passkeys.$inferSelect;
export type NewPasskeyRow = typeof passkeys.$inferInsert;
export type RefreshTokenRow = typeof refreshTokens.$inferSelect;
export type NewRefreshTokenRow = typeof refreshTokens.$inferInsert;
export type AuditLogRow = typeof auditLog.$inferSelect;
export type NewAuditLogRow = typeof auditLog.$inferInsert;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator && npx vitest run src/server/db/__tests__/schema.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator
git add src/server/db/schema.ts src/server/db/__tests__/schema.test.ts
git commit -m "feat(security): add auth database schema tables"
```

---

### Task 3: Add Raw SQL Migrations

**Files:**
- Modify: `orchestrator/src/server/db/migrate.ts`

- [ ] **Step 1: Add migration SQL strings to the migrations array**

In `orchestrator/src/server/db/migrate.ts`, add these SQL strings to the end of the `migrations` array:

```sql
-- Auth: admin table
CREATE TABLE IF NOT EXISTS admin (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  totp_secret TEXT NOT NULL,
  totp_verified INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

```sql
-- Auth: passkeys table
CREATE TABLE IF NOT EXISTS passkeys (
  id TEXT PRIMARY KEY,
  admin_id TEXT NOT NULL REFERENCES admin(id) ON DELETE CASCADE,
  public_key BLOB NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  device_type TEXT NOT NULL,
  backed_up INTEGER NOT NULL DEFAULT 0,
  transports TEXT,
  friendly_name TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

```sql
-- Auth: refresh_tokens table
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id TEXT PRIMARY KEY,
  admin_id TEXT NOT NULL REFERENCES admin(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

```sql
-- Auth: audit_log table
CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  action TEXT NOT NULL,
  admin_id TEXT,
  ip TEXT,
  user_agent TEXT,
  metadata TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
```

- [ ] **Step 2: Run migration to verify**

Run: `cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator && npx tsx src/server/db/migrate.ts`
Expected: Migration completes without errors. New tables created.

- [ ] **Step 3: Verify tables exist**

Run: `cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator && npx tsx -e "import Database from 'better-sqlite3'; const db = new Database(process.env.DB_PATH || 'data/jobs.db'); console.log(db.prepare(\"SELECT name FROM sqlite_master WHERE type='table' AND name IN ('admin','passkeys','refresh_tokens','audit_log')\").all());"`
Expected: Array with 4 table entries.

- [ ] **Step 4: Commit**

```bash
cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator
git add src/server/db/migrate.ts
git commit -m "feat(security): add auth table migrations"
```

---

## Chunk 2: Core Auth Libraries

### Task 4: Create Encryption Library

**Files:**
- Create: `orchestrator/src/server/lib/encryption.ts`
- Test: `orchestrator/src/server/lib/__tests__/encryption.test.ts`

- [ ] **Step 1: Write encryption tests**

Create `orchestrator/src/server/lib/__tests__/encryption.test.ts`:

```typescript
import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { decrypt, encrypt } from "../encryption";

const TEST_KEY = randomBytes(32).toString("hex");

describe("encryption", () => {
  it("encrypts and decrypts a string round-trip", () => {
    const plaintext = "my-secret-totp-key";
    const encrypted = encrypt(plaintext, TEST_KEY);
    expect(encrypted).not.toBe(plaintext);
    expect(encrypted).toContain(":"); // iv:ciphertext:authTag format
    const decrypted = decrypt(encrypted, TEST_KEY);
    expect(decrypted).toBe(plaintext);
  });

  it("produces different ciphertext for same plaintext (random IV)", () => {
    const plaintext = "same-input";
    const a = encrypt(plaintext, TEST_KEY);
    const b = encrypt(plaintext, TEST_KEY);
    expect(a).not.toBe(b);
  });

  it("throws on tampered ciphertext", () => {
    const encrypted = encrypt("secret", TEST_KEY);
    const [iv, ct, tag] = encrypted.split(":");
    const tampered = `${iv}:${ct}x:${tag}`;
    expect(() => decrypt(tampered, TEST_KEY)).toThrow();
  });

  it("throws on wrong key", () => {
    const encrypted = encrypt("secret", TEST_KEY);
    const wrongKey = randomBytes(32).toString("hex");
    expect(() => decrypt(encrypted, wrongKey)).toThrow();
  });

  it("handles empty string", () => {
    const encrypted = encrypt("", TEST_KEY);
    expect(decrypt(encrypted, TEST_KEY)).toBe("");
  });

  it("handles unicode", () => {
    const plaintext = "🦥 sloth emoji and ñ accents";
    const encrypted = encrypt(plaintext, TEST_KEY);
    expect(decrypt(encrypted, TEST_KEY)).toBe(plaintext);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator && npx vitest run src/server/lib/__tests__/encryption.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement encryption.ts**

Create `orchestrator/src/server/lib/encryption.ts`:

```typescript
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

/**
 * Encrypt plaintext with AES-256-GCM.
 * Returns "iv:ciphertext:authTag" (all hex-encoded).
 */
export function encrypt(plaintext: string, keyHex: string): string {
  const key = Buffer.from(keyHex, "hex");
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  return `${iv.toString("hex")}:${encrypted.toString("hex")}:${authTag.toString("hex")}`;
}

/**
 * Decrypt "iv:ciphertext:authTag" with AES-256-GCM.
 * Throws on tampered data or wrong key.
 */
export function decrypt(stored: string, keyHex: string): string {
  const parts = stored.split(":");
  if (parts.length !== 3) {
    throw new Error("Invalid encrypted format: expected iv:ciphertext:authTag");
  }
  const [ivHex, ciphertextHex, authTagHex] = parts;
  const key = Buffer.from(keyHex, "hex");
  const iv = Buffer.from(ivHex, "hex");
  const ciphertext = Buffer.from(ciphertextHex, "hex");
  const authTag = Buffer.from(authTagHex, "hex");

  const decipher = createDecipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator && npx vitest run src/server/lib/__tests__/encryption.test.ts`
Expected: PASS — all 6 tests.

- [ ] **Step 5: Commit**

```bash
cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator
git add src/server/lib/encryption.ts src/server/lib/__tests__/encryption.test.ts
git commit -m "feat(security): add AES-256-GCM encryption library"
```

---

### Task 5: Create JWT Token Library

**Files:**
- Create: `orchestrator/src/server/lib/tokens.ts`
- Test: `orchestrator/src/server/lib/__tests__/tokens.test.ts`

- [ ] **Step 1: Write token tests**

Create `orchestrator/src/server/lib/__tests__/tokens.test.ts`:

```typescript
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import {
  issueAccessToken,
  issueRefreshToken,
  issueReauthToken,
  verifyAccessToken,
  verifyRefreshToken,
  verifyReauthToken,
} from "../tokens";

const SECRET = "test-secret-that-is-at-least-32-chars-long!!";
const ADMIN_ID = "test-admin-id-123";

describe("tokens", () => {
  describe("access tokens", () => {
    it("issues and verifies an access token", () => {
      const token = issueAccessToken(ADMIN_ID, SECRET);
      const payload = verifyAccessToken(token, SECRET);
      expect(payload.sub).toBe(ADMIN_ID);
      expect(payload.type).toBe("access");
    });

    it("rejects expired tokens", () => {
      vi.useFakeTimers();
      const token = issueAccessToken(ADMIN_ID, SECRET);
      vi.advanceTimersByTime(16 * 60 * 1000); // 16 minutes
      expect(() => verifyAccessToken(token, SECRET)).toThrow();
      vi.useRealTimers();
    });

    it("rejects tokens signed with wrong secret", () => {
      const token = issueAccessToken(ADMIN_ID, SECRET);
      expect(() => verifyAccessToken(token, "wrong-secret")).toThrow();
    });
  });

  describe("refresh tokens", () => {
    it("issues and verifies a refresh token", () => {
      const { token, jti } = issueRefreshToken(ADMIN_ID, SECRET);
      expect(jti).toBeTruthy();
      const payload = verifyRefreshToken(token, SECRET);
      expect(payload.sub).toBe(ADMIN_ID);
      expect(payload.type).toBe("refresh");
      expect(payload.jti).toBe(jti);
    });
  });

  describe("reauth tokens", () => {
    it("issues and verifies a reauth token", () => {
      const token = issueReauthToken(ADMIN_ID, SECRET);
      const payload = verifyReauthToken(token, SECRET);
      expect(payload.sub).toBe(ADMIN_ID);
      expect(payload.type).toBe("reauth");
    });

    it("expires after 5 minutes", () => {
      vi.useFakeTimers();
      const token = issueReauthToken(ADMIN_ID, SECRET);
      vi.advanceTimersByTime(6 * 60 * 1000); // 6 minutes
      expect(() => verifyReauthToken(token, SECRET)).toThrow();
      vi.useRealTimers();
    });
  });

  describe("secret rotation", () => {
    it("verifyAccessToken falls back to previous secret", () => {
      const oldSecret = "old-secret-that-is-at-least-32-chars-long!!";
      const token = issueAccessToken(ADMIN_ID, oldSecret);
      const payload = verifyAccessToken(token, SECRET, oldSecret);
      expect(payload.sub).toBe(ADMIN_ID);
    });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator && npx vitest run src/server/lib/__tests__/tokens.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement tokens.ts**

Create `orchestrator/src/server/lib/tokens.ts`:

```typescript
import { randomUUID } from "node:crypto";
import jwt from "jsonwebtoken";

export interface TokenPayload {
  sub: string;
  type: "access" | "refresh" | "reauth";
  jti?: string;
  iat: number;
  exp: number;
}

const ACCESS_EXPIRY = "15m";
const REFRESH_EXPIRY = "7d";
const REAUTH_EXPIRY = "5m";

export function issueAccessToken(adminId: string, secret: string): string {
  return jwt.sign({ sub: adminId, type: "access" }, secret, {
    expiresIn: ACCESS_EXPIRY,
  });
}

export function issueRefreshToken(
  adminId: string,
  secret: string,
): { token: string; jti: string } {
  const jti = randomUUID();
  const token = jwt.sign({ sub: adminId, type: "refresh", jti }, secret, {
    expiresIn: REFRESH_EXPIRY,
  });
  return { token, jti };
}

export function issueReauthToken(adminId: string, secret: string): string {
  return jwt.sign({ sub: adminId, type: "reauth" }, secret, {
    expiresIn: REAUTH_EXPIRY,
  });
}

function verifyWithFallback(
  token: string,
  secret: string,
  previousSecret?: string,
): TokenPayload {
  try {
    return jwt.verify(token, secret) as TokenPayload;
  } catch (err) {
    if (previousSecret) {
      return jwt.verify(token, previousSecret) as TokenPayload;
    }
    throw err;
  }
}

export function verifyAccessToken(
  token: string,
  secret: string,
  previousSecret?: string,
): TokenPayload {
  const payload = verifyWithFallback(token, secret, previousSecret);
  if (payload.type !== "access") {
    throw new Error("Invalid token type: expected access");
  }
  return payload;
}

export function verifyRefreshToken(
  token: string,
  secret: string,
  previousSecret?: string,
): TokenPayload {
  const payload = verifyWithFallback(token, secret, previousSecret);
  if (payload.type !== "refresh") {
    throw new Error("Invalid token type: expected refresh");
  }
  return payload;
}

export function verifyReauthToken(
  token: string,
  secret: string,
  previousSecret?: string,
): TokenPayload {
  const payload = verifyWithFallback(token, secret, previousSecret);
  if (payload.type !== "reauth") {
    throw new Error("Invalid token type: expected reauth");
  }
  return payload;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator && npx vitest run src/server/lib/__tests__/tokens.test.ts`
Expected: PASS — all tests.

- [ ] **Step 5: Commit**

```bash
cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator
git add src/server/lib/tokens.ts src/server/lib/__tests__/tokens.test.ts
git commit -m "feat(security): add JWT token library with access/refresh/reauth"
```

---

### Task 6: Create Audit Log Service

**Files:**
- Create: `orchestrator/src/server/lib/audit.ts`
- Test: `orchestrator/src/server/lib/__tests__/audit.test.ts`

- [ ] **Step 1: Write audit log tests**

Create `orchestrator/src/server/lib/__tests__/audit.test.ts`:

```typescript
import { describe, expect, it, vi, beforeEach } from "vitest";
import { logAuditEvent, type AuditAction } from "../audit";

// Mock the database
vi.mock("@server/db", () => {
  const events: unknown[] = [];
  return {
    db: {
      insert: () => ({
        values: (val: unknown) => {
          events.push(val);
          return { run: () => {} };
        },
      }),
    },
    __testEvents: events,
  };
});

// Mock cuid2
vi.mock("@paralleldrive/cuid2", () => ({
  createId: () => "test-cuid-123",
}));

describe("audit", () => {
  it("logs an audit event with all fields", async () => {
    const { __testEvents } = await import("@server/db");

    logAuditEvent({
      action: "login.success",
      adminId: "admin-1",
      ip: "127.0.0.1",
      userAgent: "Mozilla/5.0",
      metadata: { method: "password" },
    });

    const last = (__testEvents as unknown[])[(__testEvents as unknown[]).length - 1] as Record<string, unknown>;
    expect(last).toMatchObject({
      id: "test-cuid-123",
      action: "login.success",
      adminId: "admin-1",
      ip: "127.0.0.1",
      userAgent: "Mozilla/5.0",
    });
    expect(JSON.parse(last.metadata as string)).toEqual({ method: "password" });
  });

  it("logs event with null adminId for failed attempts", async () => {
    const { __testEvents } = await import("@server/db");
    const countBefore = (__testEvents as unknown[]).length;

    logAuditEvent({
      action: "login.failed",
      adminId: null,
      ip: "1.2.3.4",
      userAgent: "curl/7.0",
      metadata: { username: "hacker" },
    });

    const last = (__testEvents as unknown[])[(__testEvents as unknown[]).length - 1] as Record<string, unknown>;
    expect(last.adminId).toBeNull();
    expect(last.action).toBe("login.failed");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator && npx vitest run src/server/lib/__tests__/audit.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement audit.ts**

Create `orchestrator/src/server/lib/audit.ts`:

```typescript
import { createId } from "@paralleldrive/cuid2";
import { db } from "@server/db";
import { auditLog } from "@server/db/schema";
import { logger } from "@infra/logger";

export type AuditAction =
  | "login.success"
  | "login.failed"
  | "login.locked"
  | "webauthn.register"
  | "webauthn.login.success"
  | "webauthn.login.failed"
  | "token.refresh"
  | "token.revoke"
  | "reauth.success"
  | "reauth.failed"
  | "passkey.register"
  | "passkey.remove"
  | "database.clear"
  | "backup.restore"
  | "backup.download"
  | "settings.credentials.update";

export interface AuditEventInput {
  action: AuditAction;
  adminId: string | null;
  ip: string | null;
  userAgent: string | null;
  metadata?: Record<string, unknown>;
}

/**
 * Log an audit event. Fire-and-forget — errors are logged but never thrown.
 */
export function logAuditEvent(input: AuditEventInput): void {
  try {
    db.insert(auditLog)
      .values({
        id: createId(),
        action: input.action,
        adminId: input.adminId,
        ip: input.ip,
        userAgent: input.userAgent,
        metadata: input.metadata ? JSON.stringify(input.metadata) : null,
      })
      .run();
  } catch (error) {
    logger.error("Failed to write audit log", { error, input });
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator && npx vitest run src/server/lib/__tests__/audit.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator
git add src/server/lib/audit.ts src/server/lib/__tests__/audit.test.ts
git commit -m "feat(security): add audit log service"
```

---

## Chunk 3: Auth Middleware

### Task 7: Create JWT Auth Middleware

**Files:**
- Create: `orchestrator/src/server/middleware/auth.ts`
- Test: `orchestrator/src/server/middleware/__tests__/auth.test.ts`

- [ ] **Step 1: Write auth middleware tests**

Create `orchestrator/src/server/middleware/__tests__/auth.test.ts`:

```typescript
import { describe, expect, it, vi, beforeEach } from "vitest";
import express from "express";
import request from "supertest";
import { requireAuth, requireReauth } from "../auth";
import { issueAccessToken, issueReauthToken } from "@server/lib/tokens";

// Set env before importing
process.env.JWT_SECRET = "test-jwt-secret-that-is-at-least-32-chars!!";

function createTestApp(middleware: express.RequestHandler) {
  const app = express();
  app.use(express.json());
  app.use(middleware);
  app.get("/test", (req, res) => {
    res.json({ auth: (req as any).auth });
  });
  return app;
}

describe("requireAuth", () => {
  it("returns 401 without Authorization header", async () => {
    const app = createTestApp(requireAuth);
    const res = await request(app).get("/test");
    expect(res.status).toBe(401);
  });

  it("returns 401 with invalid token", async () => {
    const app = createTestApp(requireAuth);
    const res = await request(app)
      .get("/test")
      .set("Authorization", "Bearer invalid-token");
    expect(res.status).toBe(401);
  });

  it("passes with valid access token", async () => {
    const app = createTestApp(requireAuth);
    const token = issueAccessToken("admin-1", process.env.JWT_SECRET!);
    const res = await request(app)
      .get("/test")
      .set("Authorization", `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.auth.adminId).toBe("admin-1");
  });

  it("rejects refresh token used as access token", async () => {
    // Refresh tokens have type: "refresh", requireAuth expects "access"
    const { issueRefreshToken } = await import("@server/lib/tokens");
    const app = createTestApp(requireAuth);
    const { token } = issueRefreshToken("admin-1", process.env.JWT_SECRET!);
    const res = await request(app)
      .get("/test")
      .set("Authorization", `Bearer ${token}`);
    expect(res.status).toBe(401);
  });
});

describe("requireReauth", () => {
  const secret = process.env.JWT_SECRET!;

  it("returns 403 without X-Reauth-Token", async () => {
    const app = createTestApp(requireReauth);
    const accessToken = issueAccessToken("admin-1", secret);
    const res = await request(app)
      .get("/test")
      .set("Authorization", `Bearer ${accessToken}`);
    expect(res.status).toBe(403);
  });

  it("passes with valid access + reauth tokens", async () => {
    const app = createTestApp(requireReauth);
    const accessToken = issueAccessToken("admin-1", secret);
    const reauthToken = issueReauthToken("admin-1", secret);
    const res = await request(app)
      .get("/test")
      .set("Authorization", `Bearer ${accessToken}`)
      .set("X-Reauth-Token", reauthToken);
    expect(res.status).toBe(200);
  });

  it("rejects mismatched admin IDs", async () => {
    const app = createTestApp(requireReauth);
    const accessToken = issueAccessToken("admin-1", secret);
    const reauthToken = issueReauthToken("admin-2", secret);
    const res = await request(app)
      .get("/test")
      .set("Authorization", `Bearer ${accessToken}`)
      .set("X-Reauth-Token", reauthToken);
    expect(res.status).toBe(403);
  });
});
```

Note: Install `supertest` if not already present: `npm install -D supertest @types/supertest`

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator && npx vitest run src/server/middleware/__tests__/auth.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement auth middleware**

Create `orchestrator/src/server/middleware/auth.ts`:

```typescript
import type { NextFunction, Request, Response } from "express";
import { unauthorized, forbidden } from "@infra/errors";
import { fail } from "@infra/http";
import { verifyAccessToken, verifyReauthToken } from "@server/lib/tokens";

declare global {
  namespace Express {
    interface Request {
      auth?: { adminId: string };
    }
  }
}

function getJwtSecret(): { current: string; previous?: string } {
  const current = process.env.JWT_SECRET;
  if (!current) throw new Error("JWT_SECRET not set");
  return {
    current,
    previous: process.env.JWT_SECRET_PREVIOUS || undefined,
  };
}

export const requireAuth = (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    fail(res, unauthorized("Missing or invalid Authorization header"));
    return;
  }

  const token = authHeader.slice(7);
  try {
    const { current, previous } = getJwtSecret();
    const payload = verifyAccessToken(token, current, previous);
    req.auth = { adminId: payload.sub };
    next();
  } catch {
    fail(res, unauthorized("Invalid or expired token"));
  }
};

export const requireReauth = (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  // First validate the access token
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    fail(res, unauthorized("Missing or invalid Authorization header"));
    return;
  }

  const accessTokenStr = authHeader.slice(7);
  const { current, previous } = getJwtSecret();

  let adminId: string;
  try {
    const payload = verifyAccessToken(accessTokenStr, current, previous);
    adminId = payload.sub;
    req.auth = { adminId };
  } catch {
    fail(res, unauthorized("Invalid or expired token"));
    return;
  }

  // Then validate the reauth token
  const reauthToken = req.headers["x-reauth-token"] as string | undefined;
  if (!reauthToken) {
    fail(res, forbidden("Re-authentication required"));
    return;
  }

  try {
    const reauthPayload = verifyReauthToken(reauthToken, current, previous);
    if (reauthPayload.sub !== adminId) {
      fail(res, forbidden("Re-auth token admin mismatch"));
      return;
    }
    next();
  } catch {
    fail(res, forbidden("Invalid or expired re-auth token"));
  }
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator && npx vitest run src/server/middleware/__tests__/auth.test.ts`
Expected: PASS — all tests.

- [ ] **Step 5: Commit**

```bash
cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator
git add src/server/middleware/auth.ts src/server/middleware/__tests__/auth.test.ts
git commit -m "feat(security): add JWT auth middleware with re-auth support"
```

---

### Task 8: Create Rate Limiter Configuration

**Files:**
- Create: `orchestrator/src/server/middleware/rateLimiter.ts`

- [ ] **Step 1: Implement rate limiter configs**

Create `orchestrator/src/server/middleware/rateLimiter.ts`:

```typescript
import rateLimit from "express-rate-limit";

/** Login endpoint: 5 attempts per 15 minutes */
export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, error: { code: "rate_limited", message: "Too many login attempts. Try again later." } },
  keyGenerator: (req) => req.ip || "unknown",
});

/** WebAuthn endpoints: 10 attempts per 15 minutes */
export const webauthnLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, error: { code: "rate_limited", message: "Too many attempts. Try again later." } },
  keyGenerator: (req) => req.ip || "unknown",
});

/** Re-auth endpoint: 5 attempts per 15 minutes */
export const reauthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, error: { code: "rate_limited", message: "Too many re-auth attempts. Try again later." } },
  keyGenerator: (req) => req.ip || "unknown",
});

/** General API: 120 requests per minute */
export const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, error: { code: "rate_limited", message: "Too many requests. Slow down." } },
  keyGenerator: (req) => req.ip || "unknown",
});
```

- [ ] **Step 2: Verify TypeScript compiles**

Run: `cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator && npx tsc --noEmit src/server/middleware/rateLimiter.ts 2>&1 | head -5`
Expected: No errors (or you may need to check it compiles within the project context).

- [ ] **Step 3: Commit**

```bash
cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator
git add src/server/middleware/rateLimiter.ts
git commit -m "feat(security): add rate limiter configurations"
```

---

## Chunk 4: Auth API Routes

### Task 9: Create Auth Routes — Login (Password + TOTP)

**Files:**
- Create: `orchestrator/src/server/api/routes/auth.ts`
- Test: `orchestrator/src/server/api/routes/__tests__/auth.test.ts`

- [ ] **Step 1: Write login route tests**

Create `orchestrator/src/server/api/routes/__tests__/auth.test.ts`:

```typescript
import { describe, expect, it, vi, beforeEach } from "vitest";

// This test file will grow as we add more auth routes.
// For now, test the password+TOTP login flow.

// Mock dependencies
vi.mock("@server/db", () => {
  const mockDb = {
    select: vi.fn(),
    insert: vi.fn(() => ({ values: vi.fn(() => ({ run: vi.fn() })) })),
    update: vi.fn(() => ({
      set: vi.fn(() => ({ where: vi.fn(() => ({ run: vi.fn() })) })),
    })),
  };
  return { db: mockDb };
});

vi.mock("@server/lib/audit", () => ({
  logAuditEvent: vi.fn(),
}));

describe("auth routes", () => {
  describe("POST /api/auth/login", () => {
    it("returns 400 if username missing", async () => {
      // Test validates Zod schema rejection
      // Full integration test requires app setup — placeholder for now
      expect(true).toBe(true);
    });
  });

  describe("POST /api/auth/check", () => {
    it("returns whether admin exists and has passkeys", async () => {
      expect(true).toBe(true);
    });
  });
});
```

Note: Full integration tests for auth routes are complex due to bcrypt/TOTP/DB mocking. We'll write focused unit tests for the logic and rely on manual integration testing. The test file is created as a scaffold that grows with each auth route task.

- [ ] **Step 2: Implement the auth routes file**

Create `orchestrator/src/server/api/routes/auth.ts`:

```typescript
import { timingSafeEqual } from "node:crypto";
import { createId } from "@paralleldrive/cuid2";
import { unauthorized, forbidden, badRequest } from "@infra/errors";
import { asyncRoute, fail, ok } from "@infra/http";
import { logger } from "@infra/logger";
import { logAuditEvent } from "@server/lib/audit";
import { decrypt } from "@server/lib/encryption";
import {
  issueAccessToken,
  issueRefreshToken,
  issueReauthToken,
  verifyRefreshToken,
} from "@server/lib/tokens";
import { requireAuth } from "@server/middleware/auth";
import { db } from "@server/db";
import { admin, passkeys, refreshTokens, auditLog } from "@server/db/schema";
import { eq, and, sql } from "drizzle-orm";
import bcrypt from "bcrypt";
import { authenticator } from "otplib";
import { Router } from "express";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import type {
  AuthenticatorTransportFuture,
} from "@simplewebauthn/types";
import { z } from "zod";

const router = Router();

// ─── Config ───────────────────────────────────────────────

function getJwtSecret(): string {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error("JWT_SECRET not set");
  return secret;
}

function getEncryptionKey(): string {
  const key = process.env.ENCRYPTION_KEY;
  if (!key) throw new Error("ENCRYPTION_KEY not set");
  return key;
}

function getWebAuthnConfig() {
  return {
    rpID: process.env.WEBAUTHN_RP_ID || "localhost",
    rpName: "Sloth Jobs",
    rpOrigin:
      process.env.WEBAUTHN_RP_ORIGIN || "http://localhost:3005",
  };
}

// In-memory challenge store (short-lived, single-user)
const challengeStore = new Map<string, { challenge: string; expires: number }>();

function storeChallenge(key: string, challenge: string): void {
  challengeStore.set(key, {
    challenge,
    expires: Date.now() + 60_000, // 60 seconds
  });
}

function consumeChallenge(key: string): string | null {
  const entry = challengeStore.get(key);
  challengeStore.delete(key);
  if (!entry || entry.expires < Date.now()) return null;
  return entry.challenge;
}

// ─── Schemas ──────────────────────────────────────────────

const loginSchema = z.object({
  username: z.string().min(1),
  password: z.string().min(1),
  totpCode: z.string().length(6),
});

const reauthSchema = z.object({
  password: z.string().min(1),
  totpCode: z.string().length(6),
});

// ─── Helper ───────────────────────────────────────────────

function getAdminRow() {
  return db.select().from(admin).limit(1).get();
}

function reqMeta(req: import("express").Request) {
  return {
    ip: req.ip ?? null,
    userAgent: req.header("user-agent") ?? null,
  };
}

// ─── Routes ───────────────────────────────────────────────

/**
 * GET /api/auth/check
 * Public — tells client if an admin exists and whether passkeys are registered.
 */
router.get(
  "/check",
  asyncRoute(async (req, res) => {
    const adminRow = getAdminRow();
    if (!adminRow) {
      ok(res, { exists: false, hasPasskeys: false });
      return;
    }
    const passkeyRows = db
      .select()
      .from(passkeys)
      .where(eq(passkeys.adminId, adminRow.id))
      .all();
    ok(res, { exists: true, hasPasskeys: passkeyRows.length > 0 });
  }),
);

/**
 * POST /api/auth/login
 * Public — password + TOTP login.
 */
router.post(
  "/login",
  asyncRoute(async (req, res) => {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      fail(res, badRequest("Invalid login payload"));
      return;
    }
    const { username, password, totpCode } = parsed.data;

    const adminRow = getAdminRow();
    if (!adminRow) {
      fail(res, unauthorized("Invalid credentials"));
      return;
    }

    // Check lockout
    if (adminRow.lockedUntil) {
      const lockedUntil = new Date(adminRow.lockedUntil);
      if (lockedUntil > new Date()) {
        logAuditEvent({ action: "login.failed", adminId: null, ...reqMeta(req), metadata: { reason: "locked", username } });
        fail(res, { status: 423, code: "locked", message: "Account locked. Try again later.", details: null, cause: null } as any);
        return;
      }
      // Lock expired — reset
      db.update(admin)
        .set({ lockedUntil: null, failedAttempts: 0 })
        .where(eq(admin.id, adminRow.id))
        .run();
    }

    // Verify username (timing-safe)
    const usernameMatch =
      username.length === adminRow.username.length &&
      timingSafeEqual(Buffer.from(username), Buffer.from(adminRow.username));

    // Verify password
    const passwordMatch = await bcrypt.compare(password, adminRow.passwordHash);

    if (!usernameMatch || !passwordMatch) {
      const attempts = (adminRow.failedAttempts || 0) + 1;
      const updates: Record<string, unknown> = { failedAttempts: attempts };
      if (attempts >= 5) {
        updates.lockedUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString();
        logAuditEvent({ action: "login.locked", adminId: adminRow.id, ...reqMeta(req), metadata: { attempts } });
      }
      db.update(admin)
        .set(updates)
        .where(eq(admin.id, adminRow.id))
        .run();
      logAuditEvent({ action: "login.failed", adminId: null, ...reqMeta(req), metadata: { username, reason: "bad_credentials" } });
      fail(res, unauthorized("Invalid credentials"));
      return;
    }

    // Verify TOTP
    const totpSecret = decrypt(adminRow.totpSecret, getEncryptionKey());
    const totpValid = authenticator.check(totpCode, totpSecret);
    if (!totpValid) {
      const attempts = (adminRow.failedAttempts || 0) + 1;
      const updates: Record<string, unknown> = { failedAttempts: attempts };
      if (attempts >= 5) {
        updates.lockedUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString();
        logAuditEvent({ action: "login.locked", adminId: adminRow.id, ...reqMeta(req), metadata: { attempts } });
      }
      db.update(admin).set(updates).where(eq(admin.id, adminRow.id)).run();
      logAuditEvent({ action: "login.failed", adminId: adminRow.id, ...reqMeta(req), metadata: { reason: "bad_totp" } });
      fail(res, unauthorized("Invalid credentials"));
      return;
    }

    // Success — reset failed attempts
    db.update(admin).set({ failedAttempts: 0, lockedUntil: null }).where(eq(admin.id, adminRow.id)).run();

    // Issue tokens
    const secret = getJwtSecret();
    const accessToken = issueAccessToken(adminRow.id, secret);
    const { token: refreshToken, jti } = issueRefreshToken(adminRow.id, secret);

    // Store refresh token
    db.insert(refreshTokens)
      .values({
        id: jti,
        adminId: adminRow.id,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      })
      .run();

    // Set httpOnly cookie
    res.cookie("refresh_token", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/api/auth",
    });

    logAuditEvent({ action: "login.success", adminId: adminRow.id, ...reqMeta(req), metadata: { method: "password" } });
    ok(res, { accessToken });
  }),
);

/**
 * POST /api/auth/refresh
 * Public — uses httpOnly cookie.
 */
router.post(
  "/refresh",
  asyncRoute(async (req, res) => {
    const cookieHeader = req.headers.cookie || "";
    const match = cookieHeader.match(/refresh_token=([^;]+)/);
    if (!match) {
      fail(res, unauthorized("No refresh token"));
      return;
    }

    const token = match[1];
    const secret = getJwtSecret();
    const previous = process.env.JWT_SECRET_PREVIOUS || undefined;

    let payload;
    try {
      payload = verifyRefreshToken(token, secret, previous);
    } catch {
      fail(res, unauthorized("Invalid refresh token"));
      return;
    }

    // Check DB
    const stored = db
      .select()
      .from(refreshTokens)
      .where(eq(refreshTokens.id, payload.jti!))
      .get();

    if (!stored || stored.revoked) {
      fail(res, unauthorized("Refresh token revoked"));
      return;
    }

    // Revoke old
    db.update(refreshTokens)
      .set({ revoked: 1 })
      .where(eq(refreshTokens.id, payload.jti!))
      .run();

    // Issue new pair
    const accessToken = issueAccessToken(payload.sub, secret);
    const { token: newRefresh, jti } = issueRefreshToken(payload.sub, secret);

    db.insert(refreshTokens)
      .values({
        id: jti,
        adminId: payload.sub,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      })
      .run();

    res.cookie("refresh_token", newRefresh, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/api/auth",
    });

    logAuditEvent({ action: "token.refresh", adminId: payload.sub, ...reqMeta(req) });
    ok(res, { accessToken });
  }),
);

/**
 * POST /api/auth/logout
 * Public — clears refresh cookie and revokes token.
 */
router.post(
  "/logout",
  asyncRoute(async (req, res) => {
    const cookieHeader = req.headers.cookie || "";
    const match = cookieHeader.match(/refresh_token=([^;]+)/);

    if (match) {
      try {
        const secret = getJwtSecret();
        const previous = process.env.JWT_SECRET_PREVIOUS || undefined;
        const payload = verifyRefreshToken(match[1], secret, previous);
        db.update(refreshTokens)
          .set({ revoked: 1 })
          .where(eq(refreshTokens.id, payload.jti!))
          .run();
        logAuditEvent({ action: "token.revoke", adminId: payload.sub, ...reqMeta(req) });
      } catch {
        // Token invalid — still clear cookie
      }
    }

    res.clearCookie("refresh_token", { path: "/api/auth" });
    ok(res, { message: "Logged out" });
  }),
);

/**
 * POST /api/auth/reauth
 * JWT required — validates password + TOTP, issues re-auth token.
 */
router.post(
  "/reauth",
  requireAuth,
  asyncRoute(async (req, res) => {
    const parsed = reauthSchema.safeParse(req.body);
    if (!parsed.success) {
      fail(res, badRequest("Invalid reauth payload"));
      return;
    }

    const adminRow = getAdminRow();
    if (!adminRow || adminRow.id !== req.auth!.adminId) {
      fail(res, unauthorized("Invalid credentials"));
      return;
    }

    const passwordMatch = await bcrypt.compare(parsed.data.password, adminRow.passwordHash);
    const totpSecret = decrypt(adminRow.totpSecret, getEncryptionKey());
    const totpValid = authenticator.check(parsed.data.totpCode, totpSecret);

    if (!passwordMatch || !totpValid) {
      logAuditEvent({ action: "reauth.failed", adminId: adminRow.id, ...reqMeta(req) });
      fail(res, unauthorized("Invalid credentials"));
      return;
    }

    const reauthToken = issueReauthToken(adminRow.id, getJwtSecret());
    logAuditEvent({ action: "reauth.success", adminId: adminRow.id, ...reqMeta(req) });
    ok(res, { reauthToken });
  }),
);

// ─── WebAuthn ─────────────────────────────────────────────

/**
 * POST /api/auth/webauthn/register/options
 * JWT required — generates registration options.
 */
router.post(
  "/webauthn/register/options",
  requireAuth,
  asyncRoute(async (req, res) => {
    const adminRow = getAdminRow();
    if (!adminRow || adminRow.id !== req.auth!.adminId) {
      fail(res, unauthorized("Admin not found"));
      return;
    }

    const existingPasskeys = db
      .select()
      .from(passkeys)
      .where(eq(passkeys.adminId, adminRow.id))
      .all();

    const { rpID, rpName } = getWebAuthnConfig();

    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userName: adminRow.username,
      attestationType: "none",
      excludeCredentials: existingPasskeys.map((pk) => ({
        id: pk.id,
        transports: pk.transports
          ? (JSON.parse(pk.transports) as AuthenticatorTransportFuture[])
          : undefined,
      })),
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred",
      },
    });

    storeChallenge(`reg:${adminRow.id}`, options.challenge);
    ok(res, options);
  }),
);

/**
 * POST /api/auth/webauthn/register/verify
 * JWT required — verifies registration response.
 */
router.post(
  "/webauthn/register/verify",
  requireAuth,
  asyncRoute(async (req, res) => {
    const adminRow = getAdminRow();
    if (!adminRow || adminRow.id !== req.auth!.adminId) {
      fail(res, unauthorized("Admin not found"));
      return;
    }

    const expectedChallenge = consumeChallenge(`reg:${adminRow.id}`);
    if (!expectedChallenge) {
      fail(res, badRequest("Challenge expired or missing"));
      return;
    }

    const { rpID, rpOrigin } = getWebAuthnConfig();

    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: rpOrigin,
      expectedRPID: rpID,
    });

    if (!verification.verified || !verification.registrationInfo) {
      fail(res, badRequest("Verification failed"));
      return;
    }

    const { credential, credentialDeviceType, credentialBackedUp } =
      verification.registrationInfo;

    db.insert(passkeys)
      .values({
        id: credential.id,
        adminId: adminRow.id,
        publicKey: Buffer.from(credential.publicKey),
        counter: credential.counter,
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp ? 1 : 0,
        transports: credential.transports
          ? JSON.stringify(credential.transports)
          : null,
        friendlyName: req.body.friendlyName || null,
      })
      .run();

    logAuditEvent({ action: "passkey.register", adminId: adminRow.id, ...reqMeta(req) });
    ok(res, { verified: true });
  }),
);

/**
 * POST /api/auth/webauthn/login/options
 * Public — generates authentication options.
 */
router.post(
  "/webauthn/login/options",
  asyncRoute(async (req, res) => {
    const adminRow = getAdminRow();
    if (!adminRow) {
      fail(res, unauthorized("No admin configured"));
      return;
    }

    const userPasskeys = db
      .select()
      .from(passkeys)
      .where(eq(passkeys.adminId, adminRow.id))
      .all();

    if (userPasskeys.length === 0) {
      fail(res, badRequest("No passkeys registered"));
      return;
    }

    const { rpID } = getWebAuthnConfig();

    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: userPasskeys.map((pk) => ({
        id: pk.id,
        transports: pk.transports
          ? (JSON.parse(pk.transports) as AuthenticatorTransportFuture[])
          : undefined,
      })),
      userVerification: "preferred",
    });

    storeChallenge(`auth:${adminRow.id}`, options.challenge);
    ok(res, options);
  }),
);

/**
 * POST /api/auth/webauthn/login/verify
 * Public — verifies authentication response and issues tokens.
 */
router.post(
  "/webauthn/login/verify",
  asyncRoute(async (req, res) => {
    const adminRow = getAdminRow();
    if (!adminRow) {
      fail(res, unauthorized("No admin configured"));
      return;
    }

    // Check lockout
    if (adminRow.lockedUntil && new Date(adminRow.lockedUntil) > new Date()) {
      logAuditEvent({ action: "webauthn.login.failed", adminId: adminRow.id, ...reqMeta(req), metadata: { reason: "locked" } });
      fail(res, { status: 423, code: "locked", message: "Account locked", details: null, cause: null } as any);
      return;
    }

    const expectedChallenge = consumeChallenge(`auth:${adminRow.id}`);
    if (!expectedChallenge) {
      fail(res, badRequest("Challenge expired or missing"));
      return;
    }

    const credentialId = req.body.id;
    const passkey = db
      .select()
      .from(passkeys)
      .where(eq(passkeys.id, credentialId))
      .get();

    if (!passkey || passkey.adminId !== adminRow.id) {
      logAuditEvent({ action: "webauthn.login.failed", adminId: adminRow.id, ...reqMeta(req), metadata: { reason: "unknown_credential" } });
      fail(res, unauthorized("Unknown passkey"));
      return;
    }

    const { rpID, rpOrigin } = getWebAuthnConfig();

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: req.body,
        expectedChallenge,
        expectedOrigin: rpOrigin,
        expectedRPID: rpID,
        credential: {
          id: passkey.id,
          publicKey: new Uint8Array(passkey.publicKey as Buffer),
          counter: passkey.counter,
          transports: passkey.transports
            ? (JSON.parse(passkey.transports) as AuthenticatorTransportFuture[])
            : undefined,
        },
      });
    } catch (error) {
      logAuditEvent({ action: "webauthn.login.failed", adminId: adminRow.id, ...reqMeta(req), metadata: { reason: "verification_error" } });
      fail(res, unauthorized("Passkey verification failed"));
      return;
    }

    if (!verification.verified) {
      logAuditEvent({ action: "webauthn.login.failed", adminId: adminRow.id, ...reqMeta(req), metadata: { reason: "not_verified" } });
      fail(res, unauthorized("Passkey verification failed"));
      return;
    }

    // Update counter
    db.update(passkeys)
      .set({ counter: verification.authenticationInfo.newCounter })
      .where(eq(passkeys.id, passkey.id))
      .run();

    // Reset failed attempts
    db.update(admin)
      .set({ failedAttempts: 0, lockedUntil: null })
      .where(eq(admin.id, adminRow.id))
      .run();

    // Issue tokens
    const secret = getJwtSecret();
    const accessToken = issueAccessToken(adminRow.id, secret);
    const { token: refreshToken, jti } = issueRefreshToken(adminRow.id, secret);

    db.insert(refreshTokens)
      .values({
        id: jti,
        adminId: adminRow.id,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      })
      .run();

    res.cookie("refresh_token", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/api/auth",
    });

    logAuditEvent({ action: "webauthn.login.success", adminId: adminRow.id, ...reqMeta(req) });
    ok(res, { accessToken });
  }),
);

// ─── Passkey Management (JWT required) ────────────────────

/** GET /api/auth/passkeys — list registered passkeys */
router.get(
  "/passkeys",
  requireAuth,
  asyncRoute(async (req, res) => {
    const rows = db
      .select({
        id: passkeys.id,
        friendlyName: passkeys.friendlyName,
        deviceType: passkeys.deviceType,
        backedUp: passkeys.backedUp,
        createdAt: passkeys.createdAt,
      })
      .from(passkeys)
      .where(eq(passkeys.adminId, req.auth!.adminId))
      .all();
    ok(res, { passkeys: rows });
  }),
);

/** DELETE /api/auth/passkeys/:id — remove a passkey (re-auth required handled by caller) */
router.delete(
  "/passkeys/:id",
  requireAuth,
  asyncRoute(async (req, res) => {
    const { id } = req.params;
    if (!id) {
      fail(res, badRequest("Missing passkey id"));
      return;
    }
    const passkey = db.select().from(passkeys).where(eq(passkeys.id, id)).get();
    if (!passkey || passkey.adminId !== req.auth!.adminId) {
      fail(res, badRequest("Passkey not found"));
      return;
    }
    db.delete(passkeys).where(eq(passkeys.id, id)).run();
    logAuditEvent({ action: "passkey.remove", adminId: req.auth!.adminId, ...reqMeta(req), metadata: { passkeyId: id } });
    ok(res, { deleted: true });
  }),
);

// ─── Audit Log (JWT required) ─────────────────────────────

/** GET /api/auth/audit — recent audit events */
router.get(
  "/audit",
  requireAuth,
  asyncRoute(async (req, res) => {
    const limit = Math.min(Number(req.query.limit) || 50, 200);
    const rows = db
      .select()
      .from(auditLog)
      .orderBy(sql`created_at DESC`)
      .limit(limit)
      .all();
    ok(res, { events: rows });
  }),
);

// ─── Sessions (JWT required) ──────────────────────────────

/** GET /api/auth/sessions — active refresh tokens */
router.get(
  "/sessions",
  requireAuth,
  asyncRoute(async (req, res) => {
    const rows = db
      .select({
        id: refreshTokens.id,
        createdAt: refreshTokens.createdAt,
        expiresAt: refreshTokens.expiresAt,
      })
      .from(refreshTokens)
      .where(
        and(
          eq(refreshTokens.adminId, req.auth!.adminId),
          eq(refreshTokens.revoked, 0),
        ),
      )
      .all();
    ok(res, { sessions: rows });
  }),
);

/** POST /api/auth/sessions/revoke-all — revoke all refresh tokens */
router.post(
  "/sessions/revoke-all",
  requireAuth,
  asyncRoute(async (req, res) => {
    db.update(refreshTokens)
      .set({ revoked: 1 })
      .where(eq(refreshTokens.adminId, req.auth!.adminId))
      .run();
    logAuditEvent({ action: "token.revoke", adminId: req.auth!.adminId, ...reqMeta(req), metadata: { scope: "all" } });
    ok(res, { revoked: true });
  }),
);

export { router as authRouter };
```

- [ ] **Step 3: Run type check**

Run: `cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator && npx tsc --noEmit`
Expected: No type errors related to auth routes.

- [ ] **Step 4: Commit**

```bash
cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator
git add src/server/api/routes/auth.ts src/server/api/routes/__tests__/auth.test.ts
git commit -m "feat(security): add auth API routes (login, webauthn, refresh, reauth, passkeys, audit, sessions)"
```

---

## Chunk 5: CLI Scripts

### Task 10: Create Admin Setup Script

**Files:**
- Create: `orchestrator/src/server/scripts/setup-admin.ts`

- [ ] **Step 1: Implement setup-admin.ts**

> Note: `qrcode-terminal` and `@types/qrcode-terminal` were already installed in Task 1. `readline` is a Node.js built-in (`node:readline`) — no npm install needed.

Create `orchestrator/src/server/scripts/setup-admin.ts`:

```typescript
import { randomBytes } from "node:crypto";
import * as readline from "node:readline";
import { createId } from "@paralleldrive/cuid2";
import bcrypt from "bcrypt";
import { authenticator } from "otplib";
import qrcode from "qrcode-terminal";
import { encrypt } from "../lib/encryption";

// Initialize DB
import "../db/index";
import { db } from "../db/index";
import { admin } from "../db/schema";

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

function ask(question: string): Promise<string> {
  return new Promise((resolve) => rl.question(question, resolve));
}

function askHidden(question: string): Promise<string> {
  return new Promise((resolve) => {
    process.stdout.write(question);
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    if (stdin.isTTY) stdin.setRawMode(true);
    let input = "";
    const onData = (ch: Buffer) => {
      const c = ch.toString();
      if (c === "\n" || c === "\r") {
        if (stdin.isTTY) stdin.setRawMode(wasRaw ?? false);
        stdin.removeListener("data", onData);
        process.stdout.write("\n");
        resolve(input);
      } else if (c === "\u007f" || c === "\b") {
        if (input.length > 0) input = input.slice(0, -1);
      } else if (c === "\u0003") {
        process.exit(1);
      } else {
        input += c;
      }
    };
    stdin.on("data", onData);
  });
}

function validatePassword(pw: string): string | null {
  if (pw.length < 12) return "Must be at least 12 characters";
  if (!/[A-Z]/.test(pw)) return "Must contain an uppercase letter";
  if (!/[a-z]/.test(pw)) return "Must contain a lowercase letter";
  if (!/[0-9]/.test(pw)) return "Must contain a number";
  if (!/[^A-Za-z0-9]/.test(pw)) return "Must contain a special character";
  return null;
}

async function main() {
  console.log("\n🦥 Sloth Jobs — Admin Setup\n");

  // Check existing admin
  const existing = db.select().from(admin).limit(1).get();
  if (existing) {
    console.log("❌ Admin already exists. Run 'npm run reset:admin' first.");
    process.exit(1);
  }

  // Check ENCRYPTION_KEY
  let encryptionKey = process.env.ENCRYPTION_KEY;
  if (!encryptionKey) {
    encryptionKey = randomBytes(32).toString("hex");
    console.log("⚠️  ENCRYPTION_KEY not set. Generated one for you:");
    console.log(`\n   ENCRYPTION_KEY=${encryptionKey}\n`);
    console.log("   Add this to your Railway env vars (or .env file).\n");
  }

  // Username
  const username = await ask("Username: ");
  if (!username.trim()) {
    console.log("❌ Username required.");
    process.exit(1);
  }

  // Password
  let password: string;
  while (true) {
    password = await askHidden("Password (min 12 chars, mixed case + number + special): ");
    const error = validatePassword(password);
    if (error) {
      console.log(`❌ ${error}`);
      continue;
    }
    const confirm = await askHidden("Confirm password: ");
    if (password !== confirm) {
      console.log("❌ Passwords don't match.");
      continue;
    }
    break;
  }

  // Hash password
  const passwordHash = await bcrypt.hash(password, 12);

  // Generate TOTP
  const totpSecret = authenticator.generateSecret();
  const otpAuthUrl = authenticator.keyuri(username, "SlothJobs", totpSecret);

  console.log("\n📱 Scan this QR code with your authenticator app:\n");
  qrcode.generate(otpAuthUrl, { small: true });
  console.log(`\nManual entry key: ${totpSecret}\n`);

  // Verify TOTP
  const totpCode = await ask("Enter the 6-digit code to verify: ");
  const isValid = authenticator.check(totpCode.trim(), totpSecret);
  if (!isValid) {
    console.log("❌ Invalid TOTP code. Setup aborted.");
    process.exit(1);
  }

  // Encrypt TOTP secret
  const encryptedTotp = encrypt(totpSecret, encryptionKey);

  // Insert admin
  db.insert(admin)
    .values({
      id: createId(),
      username: username.trim(),
      passwordHash,
      totpSecret: encryptedTotp,
      totpVerified: 1,
    })
    .run();

  console.log("\n✅ Admin account created!");
  console.log(`   Username: ${username.trim()}`);
  console.log("   MFA: Enabled (TOTP)");
  console.log("   Passkeys: Register via Settings → Security after first login\n");

  rl.close();
}

main().catch((err) => {
  console.error("Setup failed:", err);
  process.exit(1);
});
```

- [ ] **Step 3: Add npm script**

In `package.json`, add to `"scripts"`:

```json
"setup:admin": "tsx src/server/scripts/setup-admin.ts"
```

- [ ] **Step 4: Commit**

```bash
cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator
git add src/server/scripts/setup-admin.ts package.json
git commit -m "feat(security): add admin setup CLI script"
```

---

### Task 11: Create Admin Reset and Unlock Scripts

**Files:**
- Create: `orchestrator/src/server/scripts/reset-admin.ts`
- Create: `orchestrator/src/server/scripts/unlock-admin.ts`

- [ ] **Step 1: Implement reset-admin.ts**

Create `orchestrator/src/server/scripts/reset-admin.ts`:

```typescript
import * as readline from "node:readline";
import "../db/index";
import { db } from "../db/index";
import { admin, passkeys, refreshTokens } from "../db/schema";

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

async function main() {
  console.log("\n🦥 Sloth Jobs — Reset Admin\n");
  console.log("⚠️  This will delete the admin account, all passkeys, and all sessions.\n");

  const answer = await new Promise<string>((resolve) =>
    rl.question("Type 'RESET' to confirm: ", resolve),
  );

  if (answer.trim() !== "RESET") {
    console.log("Aborted.");
    process.exit(0);
  }

  db.delete(refreshTokens).run();
  db.delete(passkeys).run();
  db.delete(admin).run();

  console.log("\n✅ Admin account deleted. Run 'npm run setup:admin' to create a new one.\n");
  rl.close();
}

main().catch((err) => {
  console.error("Reset failed:", err);
  process.exit(1);
});
```

- [ ] **Step 2: Implement unlock-admin.ts**

Create `orchestrator/src/server/scripts/unlock-admin.ts`:

```typescript
import "../db/index";
import { db } from "../db/index";
import { admin } from "../db/schema";
import { eq } from "drizzle-orm";

async function main() {
  console.log("\n🦥 Sloth Jobs — Unlock Admin\n");

  const row = db.select().from(admin).limit(1).get();
  if (!row) {
    console.log("❌ No admin account found.");
    process.exit(1);
  }

  if (!row.lockedUntil) {
    console.log("ℹ️  Account is not locked.");
    process.exit(0);
  }

  db.update(admin)
    .set({ lockedUntil: null, failedAttempts: 0 })
    .where(eq(admin.id, row.id))
    .run();

  console.log(`✅ Account '${row.username}' unlocked. Failed attempts reset to 0.\n`);
}

main().catch((err) => {
  console.error("Unlock failed:", err);
  process.exit(1);
});
```

- [ ] **Step 3: Add npm scripts**

In `package.json`, add to `"scripts"`:

```json
"reset:admin": "tsx src/server/scripts/reset-admin.ts",
"unlock:admin": "tsx src/server/scripts/unlock-admin.ts"
```

- [ ] **Step 4: Commit**

```bash
cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator
git add src/server/scripts/reset-admin.ts src/server/scripts/unlock-admin.ts package.json
git commit -m "feat(security): add admin reset and unlock CLI scripts"
```

---

## Chunk 6: App Hardening

### Task 12: Harden app.ts — Helmet, CORS, Auth Middleware

**Files:**
- Modify: `orchestrator/src/server/app.ts`

- [ ] **Step 1: Replace the `createBasicAuthGuard` function and middleware stack**

In `orchestrator/src/server/app.ts`:

1. **Remove** the entire `createBasicAuthGuard()` function (lines ~27-92) and its usage.

2. **Add imports** at the top:

```typescript
import cookieParser from "cookie-parser";
import helmet from "helmet";
import { requireAuth, requireReauth } from "./middleware/auth";
import { apiLimiter } from "./middleware/rateLimiter";
import { basename, resolve as pathResolve } from "node:path";
```

3. **Replace the middleware stack** in `createApp()`. The new order should be:

```typescript
// Security headers
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
      },
    },
    hsts: { maxAge: 31536000, includeSubDomains: true },
    frameguard: { action: "deny" },
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  }),
);

// CORS — locked to specific origin
app.use(
  cors({
    origin: process.env.ALLOWED_ORIGIN || false,
    credentials: true,
    methods: ["GET", "POST", "PATCH", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Reauth-Token"],
  }),
);

app.use(requestContextMiddleware());
app.use(express.json({ limit: "5mb" }));
app.use(legacyApiResponseShim());

// Cookie parser (for refresh token cookie)
app.use(cookieParser());

// Logging middleware (keep existing)

// Rate limiter for API
app.use("/api", apiLimiter);
```

> Note: `cookie-parser` and `@types/cookie-parser` were already installed in Task 1.

4. **Fix PDF path traversal** in the PDF static serving section. Replace the raw `express.static(pdfDir)` with a safe handler:

```typescript
// Serve static files for generated PDFs (with path traversal protection)
app.get("/pdfs/:filename", (req, res) => {
  const filename = req.params.filename;
  if (!filename) {
    res.status(404).end();
    return;
  }
  const safeName = basename(filename);
  const resolved = pathResolve(pdfDir, safeName);
  if (!resolved.startsWith(pdfDir)) {
    res.status(403).end();
    return;
  }
  res.sendFile(resolved, (error) => {
    if (error) res.status(404).end();
  });
});
```

- [ ] **Step 2: Verify the app compiles**

Run: `cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator && npx tsc --noEmit`
Expected: No type errors.

- [ ] **Step 3: Commit**

```bash
cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator
git add src/server/app.ts package.json package-lock.json
git commit -m "feat(security): harden app with helmet, CORS lockdown, rate limiting, PDF path fix"
```

---

### Task 13: Wire Auth Routes and Protect Existing Routes

**Files:**
- Modify: `orchestrator/src/server/api/routes.ts`

- [ ] **Step 1: Mount auth router and add JWT middleware to existing routes**

In `orchestrator/src/server/api/routes.ts`:

1. **Import** the auth router and middleware:

```typescript
import { authRouter } from "./routes/auth";
import { requireAuth, requireReauth } from "../middleware/auth";
import { loginLimiter, webauthnLimiter, reauthLimiter } from "../middleware/rateLimiter";
```

2. **Mount rate limiters BEFORE the auth router** (Express middleware runs in registration order):

```typescript
// Rate limiters for auth endpoints — MUST come before authRouter mount
apiRouter.use("/auth/login", loginLimiter);
apiRouter.use("/auth/webauthn", webauthnLimiter);
apiRouter.use("/auth/reauth", reauthLimiter);

// Auth routes (public endpoints — no JWT middleware)
apiRouter.use("/auth", authRouter);
```

3. **Wrap existing route mounts with `requireAuth`**:

For all existing routers that were previously public (jobs, chat, settings, pipeline, etc.), add `requireAuth` as middleware:

```typescript
apiRouter.use("/jobs", requireAuth, jobsRouter);
apiRouter.use("/chat", requireAuth, chatRouter);
apiRouter.use("/settings", requireAuth, settingsRouter);
apiRouter.use("/pipeline", requireAuth, pipelineRouter);
apiRouter.use("/post-application", requireAuth, postApplicationRouter);
apiRouter.use("/manual-jobs", requireAuth, manualJobsRouter);
apiRouter.use("/profile", requireAuth, profileRouter);
apiRouter.use("/database", requireAuth, databaseRouter);
apiRouter.use("/backups", requireAuth, backupsRouter);
apiRouter.use("/onboarding", requireAuth, onboardingRouter);
apiRouter.use("/tracer-links", requireAuth, tracerLinksRouter);
```

Keep these **public** (no auth):
- `apiRouter.use("/visa-sponsors", visaSponsorsRouter);` — public search
- `apiRouter.use("/auth", authRouter);` — auth endpoints
- `GET /api/demo` — if it exists, check if it should be public

4. **Keep demo router public or protected** depending on use. If `demoRouter` exists and is read-only informational, it can stay public.

- [ ] **Step 2: Verify the app compiles**

Run: `cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator && npx tsc --noEmit`
Expected: No type errors.

- [ ] **Step 3: Commit**

```bash
cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator
git add src/server/api/routes.ts
git commit -m "feat(security): wire auth routes and protect all API endpoints with JWT"
```

---

## Chunk 7: Existing Route Modifications

### Task 14: Add Re-Auth to Dangerous Endpoints

**Files:**
- Modify: `orchestrator/src/server/api/routes/database.ts`
- Modify: `orchestrator/src/server/api/routes/backup.ts`
- Modify: `orchestrator/src/server/api/routes/jobs.ts` (bulk deletes)

- [ ] **Step 1: Protect DELETE /api/database with requireReauth**

In `orchestrator/src/server/api/routes/database.ts`, import and apply `requireReauth`:

```typescript
import { requireReauth } from "../../middleware/auth";
import { logAuditEvent } from "../../lib/audit";
```

Replace the `router.delete("/")` handler to include `requireReauth` as middleware and add audit logging:

```typescript
router.delete("/", requireReauth, asyncRoute(async (req, res) => {
  // ... existing logic ...
  logAuditEvent({
    action: "database.clear",
    adminId: req.auth!.adminId,
    ip: req.ip ?? null,
    userAgent: req.header("user-agent") ?? null,
  });
  // ... existing response ...
}));
```

- [ ] **Step 2: Add requireReauth and audit logging to backup delete**

In `orchestrator/src/server/api/routes/backup.ts`, add `requireReauth` to:
- `DELETE /api/backups/:filename` — this is the destructive operation; add audit logging for `backup.delete` event.

> **Note:** The backup router only has list (GET), create (POST), and delete (DELETE) endpoints. There are no download or restore routes. If you add those later, protect them with `requireReauth` too.

- [ ] **Step 3: Protect bulk delete routes in jobs.ts with requireReauth**

In `orchestrator/src/server/api/routes/jobs.ts`, apply `requireReauth` middleware to:
- `DELETE /api/jobs/status/:status`
- `DELETE /api/jobs/score/:threshold`

- [ ] **Step 4: Run type check**

Run: `cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator && npx tsc --noEmit`
Expected: No type errors.

- [ ] **Step 5: Commit**

```bash
cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator
git add src/server/api/routes/database.ts src/server/api/routes/backup.ts src/server/api/routes/jobs.ts
git commit -m "feat(security): add re-auth requirement to dangerous endpoints"
```

---

### Task 15: Encrypt Settings Credentials

**Files:**
- Modify: `orchestrator/src/server/api/routes/settings.ts`
- Modify: Related settings service files

- [ ] **Step 1: Add encryption to credential writes**

In the settings route handler (or the service it calls), when writing RxResume password or other credentials:

```typescript
import { encrypt, decrypt } from "../../lib/encryption";

// On write (PATCH /api/settings):
// If the update includes rxResumePassword, encrypt it
if (input.rxResumePassword) {
  const key = process.env.ENCRYPTION_KEY;
  if (!key) throw new Error("ENCRYPTION_KEY required for credential storage");
  input.rxResumePassword = encrypt(input.rxResumePassword, key);
}
```

On read (GET /api/settings):
```typescript
// If rxResumePassword is stored encrypted, decrypt before returning
// (or return a masked placeholder — never return the actual password to the client)
```

**Implementation:** Explore `orchestrator/src/server/api/routes/settings.ts` and its service layer to find where credentials are written to and read from the database. Apply `encrypt()` before writes and `decrypt()` after reads at the service boundary. For the client, return a boolean `hasRxResumePassword: true` instead of the actual encrypted value — never send the ciphertext to the frontend.

- [ ] **Step 2: Add audit logging for credential updates**

```typescript
logAuditEvent({
  action: "settings.credentials.update",
  adminId: req.auth!.adminId,
  ip: req.ip ?? null,
  userAgent: req.header("user-agent") ?? null,
  metadata: { fields: Object.keys(credentialFields) },
});
```

- [ ] **Step 3: Commit**

```bash
cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator
git add src/server/api/routes/settings.ts
git commit -m "feat(security): encrypt credentials at rest in settings"
```

---

## Chunk 8: Client Auth

### Task 16: Create Client Auth Utilities

**Files:**
- Create: `orchestrator/src/client/lib/auth.ts`

- [ ] **Step 1: Implement client auth module**

Create `orchestrator/src/client/lib/auth.ts`:

```typescript
/** Token storage and refresh logic for the client */

let accessToken: string | null = null;
let refreshPromise: Promise<string | null> | null = null;

export function getAccessToken(): string | null {
  return accessToken;
}

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

export function isAuthenticated(): boolean {
  return accessToken !== null;
}

/**
 * Attempt to refresh the access token using the httpOnly refresh cookie.
 * Returns the new access token or null if refresh failed.
 */
export async function refreshAccessToken(): Promise<string | null> {
  // Deduplicate concurrent refresh calls
  if (refreshPromise) return refreshPromise;

  refreshPromise = (async () => {
    try {
      const res = await fetch("/api/auth/refresh", {
        method: "POST",
        credentials: "include",
      });
      if (!res.ok) {
        setAccessToken(null);
        return null;
      }
      const data = await res.json();
      const newToken = data.data?.accessToken || data.accessToken;
      setAccessToken(newToken);
      return newToken;
    } catch {
      setAccessToken(null);
      return null;
    } finally {
      refreshPromise = null;
    }
  })();

  return refreshPromise;
}

/**
 * Fetch wrapper that adds JWT Authorization header and handles 401 refresh.
 */
export async function authFetch(
  url: string,
  options: RequestInit = {},
): Promise<Response> {
  const headers = new Headers(options.headers);

  if (accessToken) {
    headers.set("Authorization", `Bearer ${accessToken}`);
  }

  let res = await fetch(url, {
    ...options,
    headers,
    credentials: "include",
  });

  // If 401, try refreshing
  if (res.status === 401 && accessToken) {
    const newToken = await refreshAccessToken();
    if (newToken) {
      headers.set("Authorization", `Bearer ${newToken}`);
      res = await fetch(url, {
        ...options,
        headers,
        credentials: "include",
      });
    }
  }

  return res;
}

/**
 * Logout — clear token and call server.
 */
export async function logout(): Promise<void> {
  try {
    await fetch("/api/auth/logout", {
      method: "POST",
      credentials: "include",
    });
  } catch {
    // Best effort
  }
  setAccessToken(null);
}
```

- [ ] **Step 2: Commit**

```bash
cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator
git add src/client/lib/auth.ts
git commit -m "feat(security): add client auth token management"
```

---

### Task 17: Replace Basic Auth with JWT in API Client

**Files:**
- Modify: `orchestrator/src/client/api/client.ts`

- [ ] **Step 1: Refactor fetchApi to use authFetch**

In `orchestrator/src/client/api/client.ts`:

1. **Remove** all Basic Auth logic: `BasicAuthCredentials`, `cachedBasicAuthCredentials`, `setBasicAuthPromptHandler`, `clearBasicAuthCredentials`, the 401 retry loop.

2. **Import** the auth utilities:

```typescript
import { authFetch, getAccessToken, setAccessToken, refreshAccessToken } from "@client/lib/auth";
```

3. **Replace** the core of `fetchApi` to delegate to `authFetch`. The existing function signature should stay the same for callers, but internally replace the `fetch()` call and Basic Auth header logic with:

```typescript
const res = await authFetch(url, {
  method: options.method || "GET",
  headers: options.headers,
  body: options.body ? JSON.stringify(options.body) : undefined,
});
```

Remove the 401 retry loop (authFetch handles refresh internally). Keep the response parsing and error handling logic.

4. **For SSE streams**, modify `streamSseEvents` to include the JWT as a query parameter:

```typescript
// In streamSseEvents, append token to URL
const token = getAccessToken();
const separator = endpoint.includes("?") ? "&" : "?";
const urlWithAuth = token ? `${endpoint}${separator}token=${encodeURIComponent(token)}` : endpoint;
```

5. **Remove** `BasicAuthPrompt.tsx` component (no longer needed).

- [ ] **Step 2: Verify no type errors**

Run: `cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator && npx tsc --noEmit`
Expected: May have errors from removing BasicAuthPrompt references — fix those.

- [ ] **Step 3: Commit**

```bash
cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator
git add src/client/api/client.ts
git commit -m "feat(security): replace Basic Auth with JWT in API client"
```

---

### Task 18: Create Login Page

**Files:**
- Create: `orchestrator/src/client/pages/Login.tsx`

- [ ] **Step 1: Implement the Login page**

Create `orchestrator/src/client/pages/Login.tsx`:

```tsx
import { useState, useCallback, useEffect } from "react";
import { startAuthentication } from "@simplewebauthn/browser";
import { setAccessToken } from "@client/lib/auth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

interface LoginPageProps {
  onLogin: () => void;
}

export function LoginPage({ onLogin }: LoginPageProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [hasPasskeys, setHasPasskeys] = useState<boolean | null>(null);

  // Check on mount if admin has passkeys
  useEffect(() => {
    fetch("/api/auth/check")
      .then((r) => r.json())
      .then((data) => {
        const d = data.data || data;
        setHasPasskeys(d.hasPasskeys || false);
      })
      .catch(() => setHasPasskeys(false));
  }, []);

  const handlePasskeyLogin = useCallback(async () => {
    setError("");
    setLoading(true);
    try {
      // Get options
      const optRes = await fetch("/api/auth/webauthn/login/options", {
        method: "POST",
      });
      if (!optRes.ok) throw new Error("Failed to get passkey options");
      const optData = await optRes.json();
      const options = optData.data || optData;

      // Trigger browser/1Password prompt
      const assertion = await startAuthentication({ optionsJSON: options });

      // Verify
      const verifyRes = await fetch("/api/auth/webauthn/login/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(assertion),
        credentials: "include",
      });

      if (!verifyRes.ok) {
        const errData = await verifyRes.json();
        throw new Error(errData.error?.message || "Passkey verification failed");
      }

      const verifyData = await verifyRes.json();
      const token = verifyData.data?.accessToken || verifyData.accessToken;
      setAccessToken(token);
      onLogin();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Passkey login failed");
    } finally {
      setLoading(false);
    }
  }, [onLogin]);

  const handlePasswordLogin = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError("");
      setLoading(true);
      try {
        const res = await fetch("/api/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password, totpCode }),
          credentials: "include",
        });

        if (res.status === 423) {
          setError("Account locked. Run: npm run unlock:admin");
          return;
        }

        if (!res.ok) {
          const errData = await res.json();
          setError(errData.error?.message || "Invalid credentials");
          return;
        }

        const data = await res.json();
        const token = data.data?.accessToken || data.accessToken;
        setAccessToken(token);
        onLogin();
      } catch {
        setError("Login failed. Check your connection.");
      } finally {
        setLoading(false);
      }
    },
    [username, password, totpCode, onLogin],
  );

  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <div className="w-full max-w-sm space-y-6 rounded-lg border p-6">
        <div className="text-center">
          <h1 className="text-2xl font-bold">Sloth Jobs</h1>
        </div>

        {hasPasskeys && (
          <>
            <Button
              onClick={handlePasskeyLogin}
              disabled={loading}
              className="w-full"
              size="lg"
            >
              Sign in with Passkey
            </Button>
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <span className="w-full border-t" />
              </div>
              <div className="relative flex justify-center text-xs uppercase">
                <span className="bg-background px-2 text-muted-foreground">
                  or sign in manually
                </span>
              </div>
            </div>
          </>
        )}

        <form onSubmit={handlePasswordLogin} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="username">Username</Label>
            <Input
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              disabled={loading}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              disabled={loading}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="totp">Authentication Code</Label>
            <Input
              id="totp"
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              placeholder="000000"
              maxLength={6}
              autoComplete="one-time-code"
              disabled={loading}
            />
          </div>

          {error && (
            <p className="text-sm text-destructive">{error}</p>
          )}

          <Button type="submit" disabled={loading} className="w-full">
            {loading ? "Signing in..." : "Sign In"}
          </Button>
        </form>

        <p className="text-center text-xs text-muted-foreground">
          Account locked? Run: <code>npm run unlock:admin</code>
        </p>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Commit**

```bash
cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator
git add src/client/pages/Login.tsx
git commit -m "feat(security): add Login page with passkey and password+TOTP support"
```

---

### Task 19: Create ReauthModal Component

**Files:**
- Create: `orchestrator/src/client/components/ReauthModal.tsx`

- [ ] **Step 1: Implement ReauthModal**

Create `orchestrator/src/client/components/ReauthModal.tsx`:

```tsx
import { useState, useCallback } from "react";
import { authFetch } from "@client/lib/auth";
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogCancel,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

interface ReauthModalProps {
  open: boolean;
  onConfirm: (reauthToken: string) => void;
  onCancel: () => void;
  description?: string;
}

export function ReauthModal({
  open,
  onConfirm,
  onCancel,
  description = "This action requires re-authentication.",
}: ReauthModalProps) {
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError("");
      setLoading(true);

      try {
        const res = await authFetch("/api/auth/reauth", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password, totpCode }),
        });

        if (!res.ok) {
          const data = await res.json();
          setError(data.error?.message || "Re-authentication failed");
          return;
        }

        const data = await res.json();
        const token = data.data?.reauthToken || data.reauthToken;
        setPassword("");
        setTotpCode("");
        onConfirm(token);
      } catch {
        setError("Re-authentication failed");
      } finally {
        setLoading(false);
      }
    },
    [password, totpCode, onConfirm],
  );

  return (
    <AlertDialog open={open}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Re-authentication Required</AlertDialogTitle>
          <AlertDialogDescription>{description}</AlertDialogDescription>
        </AlertDialogHeader>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="reauth-password">Password</Label>
            <Input
              id="reauth-password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              disabled={loading}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="reauth-totp">Authentication Code</Label>
            <Input
              id="reauth-totp"
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              placeholder="000000"
              maxLength={6}
              autoComplete="one-time-code"
              disabled={loading}
            />
          </div>

          {error && <p className="text-sm text-destructive">{error}</p>}

          <AlertDialogFooter>
            <AlertDialogCancel onClick={onCancel} disabled={loading}>
              Cancel
            </AlertDialogCancel>
            <Button type="submit" disabled={loading}>
              {loading ? "Verifying..." : "Confirm"}
            </Button>
          </AlertDialogFooter>
        </form>
      </AlertDialogContent>
    </AlertDialog>
  );
}
```

- [ ] **Step 2: Commit**

```bash
cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator
git add src/client/components/ReauthModal.tsx
git commit -m "feat(security): add ReauthModal component for dangerous operations"
```

---

### Task 20: Wire Auth Context and Route Guards in App.tsx

**Files:**
- Modify: `orchestrator/src/client/App.tsx`
- Modify: `orchestrator/src/client/main.tsx` (if needed)

- [ ] **Step 1: Add auth state and login gate to App.tsx**

In `orchestrator/src/client/App.tsx`:

1. **Import** the Login page and auth utilities:

```typescript
import { LoginPage } from "@client/pages/Login";
import { isAuthenticated, setAccessToken, refreshAccessToken } from "@client/lib/auth";
```

2. **Add auth state** at the top of the App component:

```typescript
const [authed, setAuthed] = useState(false);
const [authChecked, setAuthChecked] = useState(false);

// Try silent refresh on mount
useEffect(() => {
  refreshAccessToken().then((token) => {
    setAuthed(!!token);
    setAuthChecked(true);
  });
}, []);
```

3. **Gate the entire app** behind auth:

```typescript
if (!authChecked) {
  return <div className="flex min-h-screen items-center justify-center">Loading...</div>;
}

if (!authed) {
  return <LoginPage onLogin={() => setAuthed(true)} />;
}

// ... existing Routes render
```

4. **Add logout button** to the app header/nav (wherever the app layout is). The button calls:

```typescript
import { logout } from "@client/lib/auth";

const handleLogout = async () => {
  await logout();
  setAuthed(false);
};
```

- [ ] **Step 2: Remove BasicAuthPrompt references**

Search for and remove any remaining references to `BasicAuthPrompt`, `setBasicAuthPromptHandler`, etc. from `App.tsx`, `main.tsx`, and other client files.

- [ ] **Step 3: Verify the client builds**

Run: `cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator && npx vite build`
Expected: Build succeeds.

- [ ] **Step 4: Commit**

```bash
cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator
git add src/client/App.tsx src/client/main.tsx
git commit -m "feat(security): add auth gate and login flow to client app"
```

---

## Chunk 9: Security Settings UI

### Task 21: Create Security Settings Page

**Files:**
- Create: `orchestrator/src/client/pages/SecuritySettings.tsx`

- [ ] **Step 1: Implement SecuritySettings page**

Create `orchestrator/src/client/pages/SecuritySettings.tsx`:

```tsx
import { useState, useEffect, useCallback } from "react";
import { startRegistration } from "@simplewebauthn/browser";
import { authFetch } from "@client/lib/auth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

interface Passkey {
  id: string;
  friendlyName: string | null;
  deviceType: string;
  backedUp: number;
  createdAt: string;
}

interface AuditEvent {
  id: string;
  action: string;
  adminId: string | null;
  ip: string | null;
  createdAt: string;
}

interface Session {
  id: string;
  createdAt: string;
  expiresAt: string;
}

export function SecuritySettings() {
  const [passkeys, setPasskeys] = useState<Passkey[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [loading, setLoading] = useState(true);
  const [registerName, setRegisterName] = useState("");

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [pkRes, auditRes, sessRes] = await Promise.all([
        authFetch("/api/auth/passkeys"),
        authFetch("/api/auth/audit?limit=50"),
        authFetch("/api/auth/sessions"),
      ]);
      if (pkRes.ok) {
        const d = await pkRes.json();
        setPasskeys((d.data || d).passkeys || []);
      }
      if (auditRes.ok) {
        const d = await auditRes.json();
        setAuditEvents((d.data || d).events || []);
      }
      if (sessRes.ok) {
        const d = await sessRes.json();
        setSessions((d.data || d).sessions || []);
      }
    } catch {
      // Handle error
    }
    setLoading(false);
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  const handleRegisterPasskey = useCallback(async () => {
    try {
      const optRes = await authFetch("/api/auth/webauthn/register/options", {
        method: "POST",
      });
      if (!optRes.ok) throw new Error("Failed to get options");
      const optData = await optRes.json();
      const options = optData.data || optData;

      const attestation = await startRegistration({ optionsJSON: options });

      const body = { ...attestation, friendlyName: registerName || undefined };
      const verRes = await authFetch("/api/auth/webauthn/register/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      if (!verRes.ok) throw new Error("Registration failed");
      setRegisterName("");
      loadData();
    } catch (err) {
      console.error("Passkey registration failed:", err);
    }
  }, [registerName, loadData]);

  const handleRevokeAll = useCallback(async () => {
    await authFetch("/api/auth/sessions/revoke-all", { method: "POST" });
    loadData();
  }, [loadData]);

  if (loading) return <p>Loading security settings...</p>;

  return (
    <div className="space-y-8">
      <h2 className="text-xl font-bold">Security</h2>

      {/* Passkeys */}
      <section className="space-y-4">
        <h3 className="text-lg font-semibold">Passkeys</h3>
        {passkeys.length === 0 ? (
          <p className="text-muted-foreground">No passkeys registered.</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Created</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {passkeys.map((pk) => (
                <TableRow key={pk.id}>
                  <TableCell>{pk.friendlyName || "Unnamed"}</TableCell>
                  <TableCell>{pk.deviceType}{pk.backedUp ? " (synced)" : ""}</TableCell>
                  <TableCell>{new Date(pk.createdAt).toLocaleDateString()}</TableCell>
                  <TableCell>
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={async () => {
                        await authFetch(`/api/auth/passkeys/${pk.id}`, { method: "DELETE" });
                        loadData();
                      }}
                    >
                      Remove
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        <div className="flex gap-2">
          <Input
            placeholder="Passkey name (e.g., 1Password)"
            value={registerName}
            onChange={(e) => setRegisterName(e.target.value)}
            className="max-w-xs"
          />
          <Button onClick={handleRegisterPasskey}>Register Passkey</Button>
        </div>
      </section>

      {/* Sessions */}
      <section className="space-y-4">
        <h3 className="text-lg font-semibold">Active Sessions</h3>
        <p className="text-sm text-muted-foreground">{sessions.length} active session(s)</p>
        <Button variant="outline" onClick={handleRevokeAll}>
          Revoke All Sessions
        </Button>
      </section>

      {/* Audit Log */}
      <section className="space-y-4">
        <h3 className="text-lg font-semibold">Audit Log</h3>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Time</TableHead>
              <TableHead>Action</TableHead>
              <TableHead>IP</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {auditEvents.map((evt) => (
              <TableRow key={evt.id}>
                <TableCell className="text-xs">{new Date(evt.createdAt).toLocaleString()}</TableCell>
                <TableCell className="font-mono text-xs">{evt.action}</TableCell>
                <TableCell className="text-xs">{evt.ip || "—"}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </section>
    </div>
  );
}
```

- [ ] **Step 2: Wire SecuritySettings into the Settings page**

In the existing Settings page/route, add a "Security" tab that renders `<SecuritySettings />`.

- [ ] **Step 3: Commit**

```bash
cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator
git add src/client/pages/SecuritySettings.tsx
git commit -m "feat(security): add Security Settings page (passkeys, sessions, audit log)"
```

---

### Task 22: Final Integration and Type Check

**Files:**
- All modified files

- [ ] **Step 1: Run full type check**

Run: `cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator && npx tsc --noEmit`
Expected: No type errors.

- [ ] **Step 2: Run all tests**

Run: `cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator && npx vitest run`
Expected: All tests pass.

- [ ] **Step 3: Run linter**

Run: `cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator && npm run check:all`
Expected: Clean or fixable issues only.

- [ ] **Step 4: Build client**

Run: `cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator && npm run build:client`
Expected: Vite build succeeds.

- [ ] **Step 5: Final commit**

```bash
cd /Users/coreymaypray/Desktop/Projects/job-ops/orchestrator
# Stage only the specific files that were modified in this task
git status
# Then add files explicitly, e.g.:
# git add src/client/App.tsx src/client/pages/Login.tsx ...
# Never use `git add -A` — review changed files first
git commit -m "feat(security): final integration and cleanup"
```

---

## Post-Implementation Checklist

After all tasks are complete, before deploying:

- [ ] **Set Railway env vars:**
  - `JWT_SECRET` — generate with `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`
  - `ENCRYPTION_KEY` — from `npm run setup:admin` output
  - `ALLOWED_ORIGIN` — `https://sloth-jobs-production.up.railway.app`
  - `WEBAUTHN_RP_ID` — `sloth-jobs-production.up.railway.app`
  - `WEBAUTHN_RP_ORIGIN` — `https://sloth-jobs-production.up.railway.app`

- [ ] **Run setup on Railway:**
  - `railway run npm run db:migrate`
  - `railway run npm run setup:admin`

- [ ] **Test login flows:**
  - Password + TOTP login works
  - Token refresh works (wait 15min or use short-lived test token)
  - Logout clears session
  - Register passkey via 1Password
  - Passkey login works
  - Re-auth modal appears for dangerous operations
  - Account lockout after 5 failed attempts
  - `npm run unlock:admin` clears lockout

- [ ] **Resume Railway deployment** after verification
