#!/usr/bin/env node
/**
 * Seed Corey's cybersecurity-optimized settings directly into the SQLite database.
 * Run once after initial setup: node scripts/seed-settings.mjs
 *
 * This writes to the settings table in jobs.db, inserting or updating each key.
 * Settings applied via the UI/API will override these if changed later.
 */

import Database from "better-sqlite3";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DB_PATH = join(__dirname, "../orchestrator/data/jobs.db");

if (!existsSync(DB_PATH)) {
  console.error(`Database not found at ${DB_PATH}`);
  console.error(
    "Start the server once first to create the database, then run this script.",
  );
  process.exit(1);
}

const db = new Database(DB_PATH);

const upsert = db.prepare(`
  INSERT INTO settings (key, value, created_at, updated_at)
  VALUES (?, ?, datetime('now'), datetime('now'))
  ON CONFLICT(key) DO UPDATE SET
    value = excluded.value,
    updated_at = datetime('now')
`);

// =============================================================================
// Corey Maypray — Cybersecurity Profile Settings
// =============================================================================

const settings = {
  // --- Search Terms (cybersecurity focus) ---
  searchTerms: JSON.stringify([
    "cybersecurity analyst",
    "security engineer",
    "threat intelligence analyst",
    "SOC analyst",
    "information security",
    "cybersecurity consultant",
    "penetration tester",
    "security operations",
    "GRC analyst",
    "cloud security engineer",
  ]),

  // --- Location ---
  searchCities: "Indianapolis, IN",
  jobspyCountryIndeed: "USA",

  // --- Scoring Instructions (AI suitability scoring) ---
  scoringInstructions: [
    "Prioritize roles in cybersecurity, information security, and threat intelligence.",
    "Strong fit: SIEM, SOAR, threat hunting, incident response, penetration testing,",
    "vulnerability management, GRC, NIST frameworks, MITRE ATT&CK, cloud security (AWS/Azure).",
    "Bonus: AI/ML security, agentic AI, consulting roles, remote-friendly.",
    "Penalize: Entry-level help desk, pure networking/sysadmin with no security focus,",
    "roles requiring 10+ years experience, clearance-required roles.",
    "Location preference: Indianapolis IN, remote, or hybrid within reasonable commute.",
  ].join("\n"),

  // --- Blocked Company Keywords (staffing agencies) ---
  blockedCompanyKeywords: JSON.stringify([
    "TEKsystems",
    "Robert Half",
    "Insight Global",
    "Randstad",
    "Apex Systems",
    "Kforce",
    "Hays",
    "Modis",
    "staffing",
    "recruiting agency",
  ]),

  // --- Auto-skip threshold ---
  autoSkipScoreThreshold: "25",

  // --- Salary penalty ---
  penalizeMissingSalary: "1",
  missingSalaryPenalty: "15",

  // --- Sponsor info (US citizen, not needed) ---
  showSponsorInfo: "0",

  // --- Chat style ---
  chatStyleTone: "professional",
  chatStyleFormality: "balanced",
};

console.log("Seeding settings into jobs.db...\n");

const insertMany = db.transaction(() => {
  for (const [key, value] of Object.entries(settings)) {
    upsert.run(key, value);
    console.log(`  ✓ ${key}`);
  }
});

insertMany();

console.log(`\n✅ ${Object.keys(settings).length} settings applied successfully.`);
console.log("Restart the server to pick up changes.\n");

db.close();
