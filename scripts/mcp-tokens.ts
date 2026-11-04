// Personal access tokens for MCP, on the server (run as the server's account, with its environment: DATA_DIR,
// PAT_ENABLED, MCP_ALLOWED_USER_IDS). Who may run this is who may read the database: there is no HTTP way to make one.
//
//   bun scripts/mcp-tokens.ts create --user-id <id> --name <device> --out <file>   the secret goes to <file> (new, 0600)
//   bun scripts/mcp-tokens.ts list   --user-id <id>                                an account's tokens, no secrets
//   bun scripts/mcp-tokens.ts revoke --user-id <id> --id <token-id>                works from the next request
//
// The secret is never printed. A PAT works only at /mcp, for 90 days from creation (or until 90 days idle, or revoked).
import { Database } from "bun:sqlite";
import { closeSync, constants, existsSync, fsyncSync, lstatSync, openSync, writeSync } from "node:fs";
import { join, resolve } from "node:path";
import { config } from "../src/server/config.ts";
import { ACCOUNT_ID, mcpAllowed, PAT_PREFIX, PAT_TTL_MS, patProblem, randomToken } from "../src/server/auth.ts";
import { newId, sha256 } from "../src/server/ids.ts";

const USAGE = "usage: mcp-tokens.ts create --user-id <id> --name <device> --out <file> | list --user-id <id> | revoke --user-id <id> --id <token-id>";
const NAME = /^[a-z0-9][a-z0-9-]{0,63}$/;

function die(message: string, code = 1): never {
  console.error(`mcp-tokens: ${message}`);
  process.exit(code);
}

const [command, ...rest] = process.argv.slice(2);
const flags: Record<string, string> = {};
for (let i = 0; i < rest.length; i += 2) {
  const k = rest[i]!;
  if (!k.startsWith("--") || rest[i + 1] === undefined) die(USAGE, 2);
  flags[k.slice(2)] = rest[i + 1]!;
}
const userId = flags["user-id"] ?? "";
if (!command || !["create", "list", "revoke"].includes(command) || !ACCOUNT_ID.test(userId)) die(USAGE, 2);

// The server's database, never a new one.
const file = join(config.dataDir, "grimoire.sqlite");
if (!existsSync(file)) die(`no database at ${file}: set DATA_DIR to the server's`);
const db = new Database(file, { readwrite: true, create: false });
db.exec("PRAGMA busy_timeout = 5000");
const cols = (db.query("PRAGMA table_info(app_tokens)").all() as Array<{ name: string }>).map((c) => c.name);
if (!cols.includes("kind") || !cols.includes("expires_at")) die("this database has no PAT columns yet: start the upgraded server once first");

const iso = (ms: number | null) => (ms ? new Date(ms).toISOString().slice(0, 16) + "Z" : "-");

if (command === "list") {
  const rows = db
    .query("SELECT id, label, kind, audience, created_at, expires_at, last_used_at, revoked_at FROM app_tokens WHERE user_id = ? ORDER BY created_at")
    .all(userId) as Array<{ id: string; label: string; kind: string | null; audience: string | null; created_at: number; expires_at: number | null; last_used_at: number | null; revoked_at: number | null }>;
  for (const r of rows) {
    const type = r.kind === "pat" ? "pat" : r.audience === "mcp" ? "oauth-mcp" : "app";
    const state = r.revoked_at ? `revoked ${iso(r.revoked_at)}` : r.expires_at && r.expires_at <= Date.now() ? "expired" : "active";
    console.log(`${r.id}  ${type.padEnd(9)}  ${state.padEnd(24)}  created ${iso(r.created_at)}  expires ${iso(r.expires_at)}  used ${iso(r.last_used_at)}  ${JSON.stringify(r.label)}`);
  }
  if (!rows.length) console.log(`no tokens for ${userId}`);
} else if (command === "revoke") {
  const id = flags.id ?? "";
  if (!id) die(USAGE, 2);
  const { changes } = db.query("UPDATE app_tokens SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL").run(Date.now(), id, userId);
  if (!changes) die(`no active token ${id} for ${userId}`);
  console.log(`revoked ${id}`);
} else {
  const name = flags.name ?? "";
  const out = flags.out ? resolve(flags.out) : "";
  if (!NAME.test(name) || !out) die(USAGE, 2);
  const problem = patProblem();
  if (problem) die(problem);
  if (!config.patEnabled) die("PAT_ENABLED is off");
  if (!db.query("SELECT 1 FROM users WHERE id = ?").get(userId)) die(`no account ${userId}`);
  if (!mcpAllowed(userId)) die(`${userId} is not in MCP_ALLOWED_USER_IDS`);
  let exists = true;
  try {
    lstatSync(out);
  } catch {
    exists = false;
  }
  if (exists) die(`${out} exists: give a new path`);

  const id = newId("t_");
  const token = `${PAT_PREFIX}${randomToken(32)}`;
  const now = Date.now();
  let written = false;
  try {
    // One transaction: the row commits only once the secret is safely in its file (a failure leaves no active token).
    db.transaction(() => {
      db.query("INSERT INTO app_tokens (id, user_id, token_hash, label, created_at, audience, kind, expires_at) VALUES (?, ?, ?, ?, ?, 'mcp', 'pat', ?)").run(id, userId, sha256(token), name, now, now + PAT_TTL_MS);
      const fd = openSync(out, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      written = true;
      try {
        writeSync(fd, `${token}\n`);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
    })();
  } catch (e) {
    const why = /UNIQUE/i.test(String((e as Error).message)) ? `an active PAT named ${name} exists (revoke it first, or pick another name)` : String((e as Error).message).replaceAll(token, "<secret>");
    die(`${why}${written ? `; ${out} holds a secret that never became active: trash it` : ""}`);
  }
  console.log(`created ${id} ${JSON.stringify(name)} for ${userId}, expires ${iso(now + PAT_TTL_MS)}; secret in ${out} (0600)`);
}
db.close();
