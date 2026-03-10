import { eq } from "drizzle-orm";
import { db } from "../db/index";
import { admin } from "../db/schema";

async function main() {
  console.log("\n Sloth Jobs -- Unlock Admin\n");

  const row = db.select().from(admin).limit(1).get();
  if (!row) {
    console.log("No admin account found.");
    process.exit(1);
  }

  if (!row.lockedUntil) {
    console.log("Account is not locked.");
    process.exit(0);
  }

  db.update(admin)
    .set({ lockedUntil: null, failedAttempts: 0 })
    .where(eq(admin.id, row.id))
    .run();

  console.log(`Account '${row.username}' unlocked. Failed attempts reset to 0.\n`);
}

main().catch((err) => {
  console.error("Unlock failed:", err);
  process.exit(1);
});
