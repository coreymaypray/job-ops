import { randomBytes } from "node:crypto";
import * as readline from "node:readline";
import { createId } from "@paralleldrive/cuid2";
import bcrypt from "bcrypt";
import { generateSecret, generateURI, verifySync } from "otplib";
import qrcode from "qrcode";
import { db } from "../db/index";
import { admin } from "../db/schema";
import { encrypt } from "../lib/encryption";

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
  console.log("\n Sloth Jobs -- Admin Setup\n");

  // Check existing admin
  const existing = db.select().from(admin).limit(1).get();
  if (existing) {
    console.log("Admin already exists. Run 'npm run reset:admin' first.");
    process.exit(1);
  }

  // Check ENCRYPTION_KEY
  let encryptionKey = process.env.ENCRYPTION_KEY;
  if (!encryptionKey) {
    encryptionKey = randomBytes(32).toString("hex");
    console.log("ENCRYPTION_KEY not set. Generated one for you:");
    console.log(`\n   ENCRYPTION_KEY=${encryptionKey}\n`);
    console.log("   Add this to your Railway env vars (or .env file).\n");
  }

  // Username
  const username = await ask("Username: ");
  if (!username.trim()) {
    console.log("Username required.");
    process.exit(1);
  }

  // Password
  let password: string;
  while (true) {
    password = await askHidden(
      "Password (min 12 chars, mixed case + number + special): ",
    );
    const error = validatePassword(password);
    if (error) {
      console.log(`${error}`);
      continue;
    }
    const confirm = await askHidden("Confirm password: ");
    if (password !== confirm) {
      console.log("Passwords don't match.");
      continue;
    }
    break;
  }

  // Hash password
  const passwordHash = await bcrypt.hash(password, 12);

  // Generate TOTP
  const totpSecret = generateSecret();
  const otpAuthUrl = generateURI({
    issuer: "SlothJobs",
    label: username.trim(),
    secret: totpSecret,
  });

  console.log("\nScan this QR code with your authenticator app:\n");
  const qrString = await qrcode.toString(otpAuthUrl, {
    type: "terminal",
    small: true,
  });
  console.log(qrString);
  console.log(`\nManual entry key: ${totpSecret}\n`);

  // Verify TOTP
  const totpCode = await ask("Enter the 6-digit code to verify: ");
  const isValid = verifySync({ secret: totpSecret, token: totpCode.trim() });
  if (!isValid) {
    console.log("Invalid TOTP code. Setup aborted.");
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
    })
    .run();

  console.log("\nAdmin account created!");
  console.log(`   Username: ${username.trim()}`);
  console.log("   MFA: Enabled (TOTP)");
  console.log(
    "   Passkeys: Register via Settings > Security after first login\n",
  );

  rl.close();
}

main().catch((err) => {
  console.error("Setup failed:", err);
  process.exit(1);
});
