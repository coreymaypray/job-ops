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
