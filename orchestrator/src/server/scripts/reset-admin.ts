import * as readline from "node:readline";
import { db } from "../db/index";
import { admin, passkeys, refreshTokens } from "../db/schema";

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

async function main() {
  console.log("\n Sloth Jobs -- Reset Admin\n");
  console.log(
    "  This will delete the admin account, all passkeys, and all sessions.\n",
  );

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

  console.log(
    "\n Admin account deleted. Run 'npm run setup:admin' to create a new one.\n",
  );
  rl.close();
}

main().catch((err) => {
  console.error("Reset failed:", err);
  process.exit(1);
});
