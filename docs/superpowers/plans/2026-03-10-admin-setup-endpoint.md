# Admin Setup Endpoint Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add API-based admin account creation so the admin can be set up through the browser (instead of the CLI), solving the problem of SQLite on Railway being inaccessible to the CLI script.

**Architecture:** Two one-time endpoints (`POST /api/auth/setup` and `POST /api/auth/setup/verify`) that auto-disable (return 404) once an admin exists. An in-memory `Map` stores pending setup state between the two calls, mirroring the existing `challengeStore` pattern in `auth.ts`. A new client `SetupPage` component is shown when `/api/auth/check` returns `{ exists: false }`.

**Tech Stack:** Express, Zod, bcrypt, otplib (TOTP), qrcode (data URI), AES-256-GCM encryption, React 18, Tailwind CSS, shadcn/ui components

**Spec:** `docs/superpowers/specs/2026-03-10-admin-setup-endpoint-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `orchestrator/src/server/middleware/rateLimiter.ts` | Modify | Add `setupLimiter` (3 req / 15 min) |
| `orchestrator/src/server/api/routes.ts` | Modify | Mount `setupLimiter` on `/auth/setup` |
| `orchestrator/src/server/api/routes/auth.ts` | Modify | Add setup + verify endpoints, pending store |
| `orchestrator/src/client/pages/Setup.tsx` | Create | Setup page UI (credentials form, QR display, TOTP verify) |
| `orchestrator/src/client/App.tsx` | Modify | Show `SetupPage` when `exists: false` |
| `orchestrator/src/server/api/routes/__tests__/auth-setup.test.ts` | Create | Tests for setup endpoints |

---

## Chunk 1: Server — Rate Limiter + Setup Endpoints

### Task 1: Add setup rate limiter

**Files:**
- Modify: `orchestrator/src/server/middleware/rateLimiter.ts`
- Modify: `orchestrator/src/server/api/routes.ts`

- [ ] **Step 1: Add `setupLimiter` to rateLimiter.ts**

Add after the existing `reauthLimiter`:

```typescript
/** Admin setup endpoints: 3 attempts per 15 minutes */
export const setupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, error: { code: "rate_limited", message: "Too many setup attempts. Try again later." } },
});
```

- [ ] **Step 2: Mount setupLimiter in routes.ts**

In `orchestrator/src/server/api/routes.ts`, add the import and mount line:

```typescript
// Update import (line 23):
import { loginLimiter, webauthnLimiter, reauthLimiter, setupLimiter } from "../middleware/rateLimiter";

// Add after line 30 (after reauthLimiter mount):
apiRouter.use("/auth/setup", setupLimiter);
```

- [ ] **Step 3: Verify types compile**

Run: `cd orchestrator && npx tsc --noEmit`
Expected: No errors

- [ ] **Step 4: Commit**

```bash
git add orchestrator/src/server/middleware/rateLimiter.ts orchestrator/src/server/api/routes.ts
git commit -m "feat: add setup rate limiter (3 req / 15 min)"
```

---

### Task 2: Add pending setup store and setup schemas

**Files:**
- Modify: `orchestrator/src/server/api/routes/auth.ts`

- [ ] **Step 1: Add imports for setup**

At the top of `auth.ts`, add to the existing imports:

Add/update these imports at the top of `auth.ts`:

```typescript
// Update line 1 — add randomBytes (createHash and timingSafeEqual already present):
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

// Update line 6 — add encrypt (decrypt already present):
import { decrypt, encrypt } from "@server/lib/encryption";

// Update line 18 — add generateSecret and generateURI (verifySync already present):
import { generateSecret, generateURI, verifySync as otpVerifySync } from "otplib";

// Add new imports (bcrypt and createId are already imported; these are net-new):
import qrcode from "qrcode";
```

Notes:
- `bcrypt` is already imported as a default import on line 17. Use `bcrypt.hash()` directly — no additional import needed.
- `createId` is already imported from `@paralleldrive/cuid2` on line 3.

- [ ] **Step 2: Add Zod schemas for setup**

After the existing `reauthSchema` (line 85), add:

```typescript
const setupSchema = z.object({
  username: z.string().min(1, "Username is required").max(50),
  password: z.string().min(12, "Password must be at least 12 characters"),
});

const setupVerifySchema = z.object({
  setupToken: z.string().min(1),
  totpCode: z.string().length(6),
});
```

- [ ] **Step 3: Add password validation function**

After the schemas, add:

```typescript
function validatePassword(pw: string): string | null {
  if (pw.length < 12) return "Must be at least 12 characters";
  if (!/[A-Z]/.test(pw)) return "Must contain an uppercase letter";
  if (!/[a-z]/.test(pw)) return "Must contain a lowercase letter";
  if (!/[0-9]/.test(pw)) return "Must contain a number";
  if (!/[^A-Za-z0-9]/.test(pw)) return "Must contain a special character";
  return null;
}
```

- [ ] **Step 4: Add pending setup store**

After the `consumeChallenge` function (around line 72), add:

```typescript
// ─── Pending Setup Store ─────────────────────────────────

interface PendingSetup {
  username: string;
  password: string;
  totpSecret: string;
  expiresAt: number;
}

/** At most 1 pending setup at a time. New request overwrites old. */
let pendingSetup: { token: string; data: PendingSetup } | null = null;

function storePendingSetup(data: PendingSetup): string {
  const token = randomBytes(32).toString("hex");
  pendingSetup = {
    token,
    data: { ...data, expiresAt: Date.now() + 5 * 60 * 1000 },
  };
  return token;
}

function consumePendingSetup(token: string): PendingSetup | null {
  if (!pendingSetup || pendingSetup.token !== token) return null;
  if (pendingSetup.data.expiresAt < Date.now()) {
    pendingSetup = null;
    return null;
  }
  const data = pendingSetup.data;
  pendingSetup = null;
  return data;
}
```

- [ ] **Step 5: Verify types compile**

Run: `cd orchestrator && npx tsc --noEmit`
Expected: No errors

- [ ] **Step 6: Commit**

```bash
git add orchestrator/src/server/api/routes/auth.ts
git commit -m "feat: add setup schemas, password validation, pending store"
```

---

### Task 3: Add POST /api/auth/setup endpoint

**Files:**
- Modify: `orchestrator/src/server/api/routes/auth.ts`

- [ ] **Step 1: Add the setup endpoint**

After the `/check` route (after line 126), add:

```typescript
/**
 * POST /api/auth/setup
 * Public — one-time admin setup (step 1: credentials + QR code).
 * Returns 404 once an admin exists.
 */
router.post(
  "/setup",
  asyncRoute(async (req, res) => {
    // Guard: if admin exists, this endpoint is gone
    if (getAdminRow()) {
      res.status(404).json({ ok: false, error: { code: "not_found", message: "Not found" } });
      return;
    }

    const parsed = setupSchema.safeParse(req.body);
    if (!parsed.success) {
      fail(res, badRequest("Invalid setup payload"));
      return;
    }

    const { username, password } = parsed.data;

    // Validate password complexity
    const pwError = validatePassword(password);
    if (pwError) {
      fail(res, badRequest(pwError));
      return;
    }

    // Generate TOTP secret
    const totpSecret = generateSecret();
    const otpAuthUrl = generateURI({
      issuer: "SlothJobs",
      label: username.trim(),
      secret: totpSecret,
    });

    // Generate QR code as data URI
    const qrCodeDataUri = await qrcode.toDataURL(otpAuthUrl);

    // Store pending setup (password kept in memory only, never persisted unhashed)
    const setupToken = storePendingSetup({
      username: username.trim(),
      password,
      totpSecret,
      expiresAt: 0, // set by storePendingSetup
    });

    ok(res, {
      qrCodeDataUri,
      manualKey: totpSecret,
      setupToken,
    });
  }),
);
```

- [ ] **Step 2: Verify types compile**

Run: `cd orchestrator && npx tsc --noEmit`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add orchestrator/src/server/api/routes/auth.ts
git commit -m "feat: add POST /api/auth/setup endpoint"
```

---

### Task 4: Add POST /api/auth/setup/verify endpoint

**Files:**
- Modify: `orchestrator/src/server/api/routes/auth.ts`

- [ ] **Step 1: Add the verify endpoint**

Immediately after the `/setup` route, add:

```typescript
/**
 * POST /api/auth/setup/verify
 * Public — one-time admin setup (step 2: verify TOTP + create admin).
 * Returns 404 once an admin exists.
 */
router.post(
  "/setup/verify",
  asyncRoute(async (req, res) => {
    // Guard: if admin exists, this endpoint is gone
    if (getAdminRow()) {
      res.status(404).json({ ok: false, error: { code: "not_found", message: "Not found" } });
      return;
    }

    const parsed = setupVerifySchema.safeParse(req.body);
    if (!parsed.success) {
      fail(res, badRequest("Invalid verification payload"));
      return;
    }

    const { setupToken, totpCode } = parsed.data;

    // Look up pending setup
    const pending = consumePendingSetup(setupToken);
    if (!pending) {
      fail(res, badRequest("Setup session expired or invalid. Please start over."));
      return;
    }

    // Verify TOTP code
    const totpResult = otpVerifySync({ secret: pending.totpSecret, token: totpCode });
    const isValid = typeof totpResult === "object" ? totpResult.valid : totpResult;
    if (!isValid) {
      fail(res, badRequest("Invalid authentication code. Please try again."));
      return;
    }

    // Hash password
    const passwordHash = await bcrypt.hash(pending.password, 12);

    // Encrypt TOTP secret
    const encryptedTotp = encrypt(pending.totpSecret, getEncryptionKey());

    // Insert admin row
    db.insert(admin)
      .values({
        id: createId(),
        username: pending.username,
        passwordHash,
        totpSecret: encryptedTotp,
      })
      .run();

    logger.info("Admin account created via setup endpoint", {
      username: pending.username,
    });

    ok(res, { success: true });
  }),
);
```

- [ ] **Step 2: Verify types compile**

Run: `cd orchestrator && npx tsc --noEmit`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add orchestrator/src/server/api/routes/auth.ts
git commit -m "feat: add POST /api/auth/setup/verify endpoint"
```

---

### Task 5: Write tests for setup endpoints

**Files:**
- Create: `orchestrator/src/server/api/routes/__tests__/auth-setup.test.ts`

- [ ] **Step 1: Write tests**

```typescript
import { describe, expect, it, vi, beforeEach } from "vitest";
import express from "express";
import request from "supertest";

// Mock modules before importing router
vi.mock("@server/db", () => {
  const mockSelect = vi.fn();
  const mockInsert = vi.fn();
  return {
    db: {
      select: mockSelect,
      insert: mockInsert,
    },
  };
});

vi.mock("@server/lib/encryption", () => ({
  decrypt: vi.fn(() => "decrypted-secret"),
  encrypt: vi.fn(() => "iv:ciphertext:tag"),
}));

vi.mock("@server/lib/audit", () => ({
  logAuditEvent: vi.fn(),
}));

vi.mock("@server/lib/tokens", () => ({
  issueAccessToken: vi.fn(() => "mock-access-token"),
  issueRefreshToken: vi.fn(() => ({ token: "mock-refresh-token", jti: "mock-jti" })),
  verifyRefreshToken: vi.fn(),
}));

vi.mock("otplib", () => ({
  generateSecret: vi.fn(() => "MOCK_TOTP_SECRET"),
  generateURI: vi.fn(() => "otpauth://totp/SlothJobs:admin?secret=MOCK_TOTP_SECRET&issuer=SlothJobs"),
  verifySync: vi.fn(() => ({ valid: true, delta: 0 })),
}));

vi.mock("qrcode", () => ({
  default: {
    toDataURL: vi.fn(() => Promise.resolve("data:image/png;base64,mock")),
  },
}));

vi.mock("bcrypt", () => ({
  default: {
    compare: vi.fn(() => Promise.resolve(true)),
    hash: vi.fn(() => Promise.resolve("$2b$12$mockhash")),
  },
}));

vi.mock("@paralleldrive/cuid2", () => ({
  createId: vi.fn(() => "mock-cuid2-id"),
}));

// Import after mocks
import { db } from "@server/db";

// Helper: build a minimal test app with the auth router
async function createApp() {
  // Dynamic import to ensure mocks are applied
  const { authRouter } = await import("../auth");
  const app = express();
  app.use(express.json());
  app.use("/auth", authRouter);
  return app;
}

// Helper to control whether admin "exists"
function mockAdminExists(exists: boolean) {
  const mockChain = {
    from: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    where: vi.fn().mockReturnThis(),
    all: vi.fn().mockReturnValue([]),
    get: vi.fn().mockReturnValue(
      exists
        ? {
            id: "admin-1",
            username: "admin",
            passwordHash: "$2b$12$hash",
            totpSecret: "iv:ct:tag",
            failedAttempts: 0,
            lockedUntil: null,
          }
        : undefined,
    ),
  };
  (db.select as ReturnType<typeof vi.fn>).mockReturnValue(mockChain);
}

function mockInsert() {
  const mockChain = {
    values: vi.fn().mockReturnThis(),
    run: vi.fn(),
  };
  (db.insert as ReturnType<typeof vi.fn>).mockReturnValue(mockChain);
  return mockChain;
}

describe("Admin Setup Endpoints", () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    vi.resetModules();
    process.env.JWT_SECRET = "test-jwt-secret-that-is-long-enough";
    process.env.ENCRYPTION_KEY = "a".repeat(64);
  });

  describe("POST /auth/setup", () => {
    it("returns 404 when admin already exists", async () => {
      mockAdminExists(true);
      const app = await createApp();

      const res = await request(app)
        .post("/auth/setup")
        .send({ username: "admin", password: "Test12345678!" });

      expect(res.status).toBe(404);
    });

    it("returns 400 for weak password", async () => {
      mockAdminExists(false);
      const app = await createApp();

      const res = await request(app)
        .post("/auth/setup")
        .send({ username: "admin", password: "short" });

      expect(res.status).toBe(400);
    });

    it("returns QR code and setup token for valid request", async () => {
      mockAdminExists(false);
      const app = await createApp();

      const res = await request(app)
        .post("/auth/setup")
        .send({ username: "admin", password: "Test12345678!" });

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveProperty("qrCodeDataUri");
      expect(res.body.data).toHaveProperty("manualKey");
      expect(res.body.data).toHaveProperty("setupToken");
      expect(res.body.data.setupToken).toHaveLength(64); // 32 bytes hex
    });
  });

  describe("POST /auth/setup/verify", () => {
    it("returns 404 when admin already exists", async () => {
      mockAdminExists(true);
      const app = await createApp();

      const res = await request(app)
        .post("/auth/setup/verify")
        .send({ setupToken: "abc", totpCode: "123456" });

      expect(res.status).toBe(404);
    });

    it("returns 400 for invalid/expired token", async () => {
      mockAdminExists(false);
      const app = await createApp();

      const res = await request(app)
        .post("/auth/setup/verify")
        .send({ setupToken: "nonexistent-token", totpCode: "123456" });

      expect(res.status).toBe(400);
      expect(res.body.error.message).toContain("expired or invalid");
    });

    it("returns 400 for invalid TOTP code", async () => {
      mockAdminExists(false);
      const { verifySync } = await import("otplib");
      (verifySync as ReturnType<typeof vi.fn>).mockReturnValueOnce({ valid: false, delta: null });
      const app = await createApp();

      // Step 1: initiate setup
      const setupRes = await request(app)
        .post("/auth/setup")
        .send({ username: "admin", password: "Test12345678!" });
      const { setupToken } = setupRes.body.data;

      // Step 2: verify with wrong TOTP
      const res = await request(app)
        .post("/auth/setup/verify")
        .send({ setupToken, totpCode: "000000" });

      expect(res.status).toBe(400);
      expect(res.body.error.message).toContain("Invalid authentication code");
    });

    it("creates admin on valid setup token + TOTP", async () => {
      mockAdminExists(false);
      const insertMock = mockInsert();
      const app = await createApp();

      // Step 1: initiate setup
      const setupRes = await request(app)
        .post("/auth/setup")
        .send({ username: "admin", password: "Test12345678!" });

      expect(setupRes.status).toBe(200);
      const { setupToken } = setupRes.body.data;

      // Step 2: verify TOTP (mocked to always return valid)
      // Need to make getAdminRow return undefined for the verify call too
      const res = await request(app)
        .post("/auth/setup/verify")
        .send({ setupToken, totpCode: "123456" });

      expect(res.status).toBe(200);
      expect(res.body.data).toEqual({ success: true });
      expect(insertMock.values).toHaveBeenCalledWith(
        expect.objectContaining({
          username: "admin",
          passwordHash: "$2b$12$mockhash",
        }),
      );
    });
  });
});
```

- [ ] **Step 2: Run the tests**

Run: `cd orchestrator && npx vitest run src/server/api/routes/__tests__/auth-setup.test.ts`
Expected: All tests pass

- [ ] **Step 3: Fix any failures and re-run until green**

- [ ] **Step 4: Commit**

```bash
git add orchestrator/src/server/api/routes/__tests__/auth-setup.test.ts
git commit -m "test: add setup endpoint tests"
```

---

## Chunk 2: Client — Setup Page + Auth Gate

### Task 6: Create SetupPage component

**Files:**
- Create: `orchestrator/src/client/pages/Setup.tsx`

- [ ] **Step 1: Create the setup page**

The component has three steps:
1. Credentials form (username + password with confirmation)
2. QR code display (scan with authenticator)
3. TOTP verification (enter 6-digit code)

```tsx
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

interface SetupPageProps {
  onSetupComplete: () => void;
}

type Step = "credentials" | "qr" | "verify";

export function SetupPage({ onSetupComplete }: SetupPageProps) {
  const [step, setStep] = useState<Step>("credentials");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  // QR step state
  const [qrCodeDataUri, setQrCodeDataUri] = useState("");
  const [manualKey, setManualKey] = useState("");
  const [setupToken, setSetupToken] = useState("");

  // Verify step state
  const [totpCode, setTotpCode] = useState("");

  const handleCredentialsSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (password !== confirmPassword) {
      setError("Passwords don't match");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch("/api/auth/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim(), password }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => null);
        setError(data?.error?.message || "Setup failed");
        return;
      }

      const data = await res.json();
      const d = data.data ?? data;
      setQrCodeDataUri(d.qrCodeDataUri);
      setManualKey(d.manualKey);
      setSetupToken(d.setupToken);
      setStep("qr");
    } catch {
      setError("Connection failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const res = await fetch("/api/auth/setup/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ setupToken, totpCode }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => null);
        setError(data?.error?.message || "Verification failed");
        return;
      }

      onSetupComplete();
    } catch {
      setError("Connection failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <div className="w-full max-w-sm space-y-6 rounded-lg border p-6">
        <div className="text-center">
          <h1 className="text-2xl font-bold">Sloth Jobs</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {step === "credentials" && "Create your admin account"}
            {step === "qr" && "Set up two-factor authentication"}
            {step === "verify" && "Verify your authenticator"}
          </p>
        </div>

        {step === "credentials" && (
          <form onSubmit={handleCredentialsSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="setup-username">Username</Label>
              <Input
                id="setup-username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                disabled={loading}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="setup-password">Password</Label>
              <Input
                id="setup-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
                disabled={loading}
                required
              />
              <p className="text-xs text-muted-foreground">
                Min 12 chars, uppercase, lowercase, number, special character
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="setup-confirm">Confirm Password</Label>
              <Input
                id="setup-confirm"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                autoComplete="new-password"
                disabled={loading}
                required
              />
            </div>

            {error && (
              <p className="text-sm text-destructive" role="alert">{error}</p>
            )}

            <Button type="submit" disabled={loading} className="w-full">
              {loading ? "Setting up..." : "Continue"}
            </Button>
          </form>
        )}

        {step === "qr" && (
          <div className="space-y-4">
            <div className="flex justify-center">
              <img
                src={qrCodeDataUri}
                alt="TOTP QR Code"
                className="h-48 w-48 rounded-lg border"
              />
            </div>
            <div className="space-y-1">
              <p className="text-xs text-muted-foreground">
                Scan this QR code with your authenticator app (Google Authenticator, 1Password, etc.)
              </p>
              <p className="text-xs text-muted-foreground">
                Manual key: <code className="rounded bg-muted px-1 py-0.5 text-xs">{manualKey}</code>
              </p>
            </div>
            <Button onClick={() => setStep("verify")} className="w-full">
              I've scanned the code
            </Button>
          </div>
        )}

        {step === "verify" && (
          <form onSubmit={handleVerify} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="setup-totp">Authentication Code</Label>
              <Input
                id="setup-totp"
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                placeholder="000000"
                maxLength={6}
                autoComplete="one-time-code"
                disabled={loading}
                required
              />
              <p className="text-xs text-muted-foreground">
                Enter the 6-digit code from your authenticator app
              </p>
            </div>

            {error && (
              <p className="text-sm text-destructive" role="alert">{error}</p>
            )}

            <Button type="submit" disabled={loading || totpCode.length !== 6} className="w-full">
              {loading ? "Verifying..." : "Verify & Create Account"}
            </Button>

            <button
              type="button"
              onClick={() => { setStep("qr"); setError(""); setTotpCode(""); }}
              className="w-full text-center text-xs text-muted-foreground hover:underline"
            >
              Back to QR code
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Verify types compile**

Run: `cd orchestrator && npx tsc --noEmit`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add orchestrator/src/client/pages/Setup.tsx
git commit -m "feat: add SetupPage component for browser-based admin creation"
```

---

### Task 7: Wire SetupPage into App.tsx auth gate

**Files:**
- Modify: `orchestrator/src/client/App.tsx`

- [ ] **Step 1: Add adminExists state and SetupPage import**

Add import (after LoginPage import, around line 16):
```typescript
import { SetupPage } from "./pages/Setup";
```

Add state inside `App` component (after line 52):
```typescript
const [adminExists, setAdminExists] = useState<boolean | null>(null);
```

- [ ] **Step 2: Update useEffect to check admin existence**

Replace the existing `useEffect` (lines 54-64) with:

```typescript
useEffect(() => {
  // First check if admin exists
  fetch("/api/auth/check")
    .then((r) => r.json())
    .then((data) => {
      const d = data.data ?? data;
      setAdminExists(d.exists ?? true);
      if (!d.exists) {
        setAuthChecked(true);
        return;
      }
      // Admin exists — try to refresh token
      return refreshAccessToken().then((token) => {
        setAuthed(!!token);
        setAuthChecked(true);
      });
    })
    .catch(() => {
      setAdminExists(true); // assume exists on error
      setAuthed(false);
      setAuthChecked(true);
    });
}, []);
```

- [ ] **Step 3: Add SetupPage gate before LoginPage gate**

After the loading check (after line 87), add:

```typescript
if (adminExists === false) {
  return (
    <SetupPage
      onSetupComplete={() => {
        setAdminExists(true);
        setAuthed(false); // force login after setup
      }}
    />
  );
}
```

The full auth gate section becomes:
```typescript
if (!authChecked) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <p className="text-sm text-muted-foreground">Loading...</p>
    </div>
  );
}

if (adminExists === false) {
  return (
    <SetupPage
      onSetupComplete={() => {
        setAdminExists(true);
        setAuthed(false);
      }}
    />
  );
}

if (!authed) {
  return <LoginPage onLogin={() => setAuthed(true)} />;
}
```

- [ ] **Step 4: Verify types compile**

Run: `cd orchestrator && npx tsc --noEmit`
Expected: No errors

- [ ] **Step 5: Commit**

```bash
git add orchestrator/src/client/App.tsx
git commit -m "feat: show SetupPage when no admin exists"
```

---

### Task 8: Final verification

- [ ] **Step 1: Run full test suite**

Run: `cd /Users/coreymaypray/Desktop/Projects/job-ops && npm run test:all`
Expected: All auth-related tests pass (pre-existing failures in backup/chart tests are unrelated)

- [ ] **Step 2: Run type check**

Run: `cd orchestrator && npx tsc --noEmit`
Expected: No errors

- [ ] **Step 3: Build client**

Run: `cd orchestrator && npm run build:client`
Expected: Build succeeds

- [ ] **Step 4: Commit any remaining changes and push**

```bash
git push origin main
```

Railway auto-deploys on push. After deploy, navigate to `https://sloth-jobs-production.up.railway.app` — it should show the setup form since no admin exists yet.

- [ ] **Step 5: Create admin account through the browser**

1. Navigate to the Railway URL
2. Fill in username and password
3. Scan QR code with authenticator app
4. Enter 6-digit code
5. Admin created — redirected to login page
6. Login with the credentials just created
