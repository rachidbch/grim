// Personal access tokens for MCP (PAT_ENABLED, MCP_ALLOWED_USER_IDS): made on the server by scripts/mcp-tokens.ts
// (the secret goes to a 0600 file, never to the terminal), good only at /mcp, never cached, revoked on the next request.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readdirSync, readFileSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { isolate } from "./helpers.ts";

process.env.POLL_MS = "60000";
const { config } = await import("../../src/server/config.ts");
const { db } = await import("../../src/server/db.ts");
const restore = isolate(config, db);
Object.assign(config, { storage: "local", allowDevLogin: true, signIn: true, quietMs: 100 });
config.github.clientId = "";
const { startServer } = await import("../../src/server/index.ts");
const { APP_TOKEN_IDLE_MS, PAT_PREFIX, PAT_TTL_MS, authenticate, patProblem } = await import("../../src/server/auth.ts");
const { createAppToken, MCP_AUDIENCE } = await import("../../src/server/tokens.ts");
const { bunDb } = await import("../../src/server/bun/db-bun.ts");
const { sha256 } = await import("../../src/server/ids.ts");

const ROOT = join(import.meta.dir, "../..");
let base = "";
let app: Awaited<ReturnType<typeof startServer>>;
let alice = "";
let aliceId = "";
const out = mkdtempSync(join(config.dataDir, "pat-out-"));

async function login(name: string): Promise<string> {
  const res = await fetch(`${base}/auth/dev`, { method: "POST", headers: { origin: base }, body: new URLSearchParams({ name }), redirect: "manual" });
  return res.headers.getSetCookie().find((s) => s.startsWith("np_session="))!.split(";")[0]!;
}
const idOf = async (cookie: string) => (await (await fetch(`${base}/api/me`, { headers: { cookie } })).json()).id as string;

/** The operator command, as the server's account would run it (its env: this test's DATA_DIR and PAT policy). */
async function cli(args: string[], env: Record<string, string> = {}) {
  const proc = Bun.spawn([process.execPath, join(ROOT, "scripts/mcp-tokens.ts"), ...args], {
    cwd: ROOT,
    env: { ...process.env, DATA_DIR: config.dataDir, SIGN_IN: "on", PAT_ENABLED: "on", MCP_ALLOWED_USER_IDS: aliceId, ...env },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);
  return { stdout, stderr, code };
}

let n = 0;
/** A new PAT for Alice: its file path and secret. */
async function create(name = `dev-${n}`, env: Record<string, string> = {}) {
  const file = join(out, `${name}-${++n}.token`);
  const r = await cli(["create", "--user-id", aliceId, "--name", name, "--out", file], env);
  if (r.code !== 0) throw new Error(`mcp-tokens create failed: ${r.stderr}`);
  return { file, token: readFileSync(file, "utf8").trim(), ...r };
}

const rpc = (token: string, body: unknown, headers: Record<string, string> = {}) =>
  fetch(`${base}/mcp`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json", accept: "application/json, text/event-stream", ...headers },
    body: JSON.stringify(body),
  });
const init = (token: string) => rpc(token, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "kelivo", version: "1" } } });

beforeAll(async () => {
  app = await startServer({ port: 0, quiet: true });
  base = `http://localhost:${app.server.port}`;
  config.publicUrl = base;
  alice = await login("Alice");
  aliceId = await idOf(alice);
  config.patEnabled = true;
  config.mcpAllowedUserIds = new Set([aliceId]);
});

afterAll(async () => {
  await app?.stop();
  restore();
});

describe("PATs", () => {
  test("made by the operator command, the token reaches /mcp", async () => {
    const { token, file, stdout, stderr } = await create("kelivo-windows");
    expect(token).toMatch(/^gmp_[A-Za-z0-9_-]{43}$/);
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(stdout + stderr).not.toContain(token);
    expect((await init(token)).status).toBe(200);
  });

  test("tools work; list shows it without secrets; revoke ends it on the next request, session or not", async () => {
    const { token } = await create("phone");
    const res = await init(token);
    const sid = res.headers.get("mcp-session-id")!;
    const tools = await (await rpc(token, { jsonrpc: "2.0", id: 2, method: "tools/list" }, { "mcp-session-id": sid })).json();
    expect(tools.result.tools.map((t: { name: string }) => t.name)).toEqual(["list_workspaces", "changes", "command"]);
    const listed = await cli(["list", "--user-id", aliceId]);
    expect(listed.code).toBe(0);
    const line = listed.stdout.split("\n").find((l) => l.includes('"phone"'))!;
    expect(line).toMatch(/^t_\S+\s+pat\s+active/);
    expect(listed.stdout).not.toContain(PAT_PREFIX + "");
    const id = line.split(/\s+/)[0]!;
    expect((await cli(["revoke", "--user-id", aliceId, "--id", id])).code).toBe(0);
    expect((await rpc(token, { jsonrpc: "2.0", id: 3, method: "tools/list" }, { "mcp-session-id": sid })).status).toBe(401);
    expect((await cli(["list", "--user-id", aliceId])).stdout).toMatch(new RegExp(`${id}\\s+pat\\s+revoked`));
  });

  test("never cached: with AUTH_CACHE on, a revoke still counts on the next request", async () => {
    config.authCache = true;
    try {
      const { token } = await create("cached");
      expect((await init(token)).status).toBe(200);
      db.query("UPDATE app_tokens SET revoked_at = ? WHERE token_hash = ?").run(Date.now(), sha256(token));
      expect((await init(token)).status).toBe(401);
    } finally {
      config.authCache = false;
    }
  });

  test("good only at /mcp: the API, sockets and the workspace URL refuse a PAT", async () => {
    const { token } = await create("doors");
    const auth = { authorization: `Bearer ${token}` };
    expect((await fetch(`${base}/api/me`, { headers: auth })).status).toBe(401);
    expect((await fetch(`${base}/app/anything`, { method: "POST", headers: { ...auth, "content-type": "text/plain" }, body: "ls" })).status).toBe(401);
    expect(await authenticate(bunDb(db), new Request(`${base}/ws?repo=x`), token)).toBeNull();
  });

  test("PAT_ENABLED off refuses PATs and leaves OAuth tokens alone", async () => {
    const { token } = await create("switch");
    const oauth = (await createAppToken(bunDb(db), aliceId, "Some client (MCP)", MCP_AUDIENCE)).token;
    config.patEnabled = false;
    try {
      expect((await init(token)).status).toBe(401);
      expect((await init(oauth)).status).toBe(200);
    } finally {
      config.patEnabled = true;
    }
    expect((await init(token)).status).toBe(200);
  });

  test("MCP_ALLOWED_USER_IDS gates OAuth tokens too, at /mcp and the workspace URL", async () => {
    const bobId = await idOf(await login("Bob"));
    const bob = (await createAppToken(bunDb(db), bobId, "Bob's client (MCP)", MCP_AUDIENCE)).token;
    expect((await init(bob)).status).toBe(401);
    expect((await fetch(`${base}/app/anything`, { method: "POST", headers: { authorization: `Bearer ${bob}`, "content-type": "text/plain" }, body: "ls" })).status).toBe(401);
    const r = await cli(["create", "--user-id", bobId, "--name", "bob", "--out", join(out, "bob.token")]);
    expect(r.code).toBe(1);
    expect(r.stderr).toContain("not in MCP_ALLOWED_USER_IDS");
    const saved = config.mcpAllowedUserIds;
    config.mcpAllowedUserIds = new Set();
    try {
      // no allowlist (PATs off): upstream's behavior, every account's token
      config.patEnabled = false;
      expect((await init(bob)).status).toBe(200);
    } finally {
      config.mcpAllowedUserIds = saved;
      config.patEnabled = true;
    }
  });

  test("expiry: 90 days after creation even when used, and 90 days idle", async () => {
    const { token } = await create("old");
    const hash = sha256(token);
    const row = db.query("SELECT created_at, expires_at FROM app_tokens WHERE token_hash = ?").get(hash) as { created_at: number; expires_at: number };
    expect(row.expires_at - row.created_at).toBe(PAT_TTL_MS);
    db.query("UPDATE app_tokens SET expires_at = ?, last_used_at = ? WHERE token_hash = ?").run(Date.now() + 1000, Date.now(), hash);
    expect((await init(token)).status).toBe(200);
    db.query("UPDATE app_tokens SET expires_at = ? WHERE token_hash = ?").run(Date.now(), hash);
    expect((await init(token)).status).toBe(401);
    const idle = await create("idle");
    db.query("UPDATE app_tokens SET created_at = ?, last_used_at = NULL WHERE token_hash = ?").run(Date.now() - APP_TOKEN_IDLE_MS - 1, sha256(idle.token));
    expect((await init(idle.token)).status).toBe(401);
  });

  test("a deleted account's PATs stop at once", async () => {
    const carol = await login("Carol");
    const carolId = await idOf(carol);
    config.mcpAllowedUserIds = new Set([aliceId, carolId]);
    const file = join(out, "carol.token");
    expect((await cli(["create", "--user-id", carolId, "--name", "carol", "--out", file], { MCP_ALLOWED_USER_IDS: `${aliceId},${carolId}` })).code).toBe(0);
    const token = readFileSync(file, "utf8").trim();
    expect((await init(token)).status).toBe(200);
    expect((await fetch(`${base}/api/me`, { method: "DELETE", headers: { cookie: carol, origin: base } })).status).toBe(200);
    expect((await init(token)).status).toBe(401);
    config.mcpAllowedUserIds = new Set([aliceId]);
  });

  test("kind and prefix must agree: a gmp_ secret on an OAuth row, or a PAT row behind a gmt_ secret, fails", async () => {
    const now = Date.now();
    const gmp = `${PAT_PREFIX}${"a".repeat(43)}`;
    const gmt = `gmt_${"b".repeat(43)}`;
    db.query("INSERT INTO app_tokens (id, user_id, token_hash, label, created_at, audience) VALUES ('t_mix1', ?, ?, 'x', ?, 'mcp')").run(aliceId, sha256(gmp), now);
    db.query("INSERT INTO app_tokens (id, user_id, token_hash, label, created_at, audience, kind, expires_at) VALUES ('t_mix2', ?, ?, 'y', ?, 'mcp', 'pat', ?)").run(aliceId, sha256(gmt), now, now + PAT_TTL_MS);
    expect((await init(gmp)).status).toBe(401);
    expect((await init(gmt)).status).toBe(401);
  });
});

describe("the operator command", () => {
  test("one active name per account; a revoked name can be used again, its old token stays dead", async () => {
    const first = await create("kelivo-android");
    const dup = await cli(["create", "--user-id", aliceId, "--name", "kelivo-android", "--out", join(out, "dup.token")]);
    expect(dup.code).toBe(1);
    expect(dup.stderr).toContain("an active PAT named kelivo-android exists");
    expect(existsSync(join(out, "dup.token"))).toBe(false);
    const id = (db.query("SELECT id FROM app_tokens WHERE token_hash = ?").get(sha256(first.token)) as { id: string }).id;
    expect((await cli(["revoke", "--user-id", aliceId, "--id", id])).code).toBe(0);
    const second = await create("kelivo-android");
    expect((await init(second.token)).status).toBe(200);
    expect((await init(first.token)).status).toBe(401);
    expect((db.query("SELECT count(*) AS n FROM app_tokens WHERE user_id = ? AND label = 'kelivo-android'").get(aliceId) as { n: number }).n).toBe(2);
  });

  test("revoke is owner-scoped", async () => {
    const { token } = await create("mine");
    const id = (db.query("SELECT id FROM app_tokens WHERE token_hash = ?").get(sha256(token)) as { id: string }).id;
    const r = await cli(["revoke", "--user-id", "someone-else", "--id", id]);
    expect(r.code).toBe(1);
    expect((await init(token)).status).toBe(200);
  });

  test("the secret file must be new: an existing file or a symlink is refused", async () => {
    const taken = join(out, "taken.token");
    writeFileSync(taken, "keep me\n");
    const link = join(out, "link.token");
    symlinkSync(join(out, "nowhere"), link);
    for (const path of [taken, link]) {
      const r = await cli(["create", "--user-id", aliceId, "--name", "refused", "--out", path]);
      expect(r.code).toBe(1);
      expect(r.stderr).toContain("exists");
    }
    expect(readFileSync(taken, "utf8")).toBe("keep me\n");
    expect(existsSync(join(out, "nowhere"))).toBe(false);
  });

  test("a failed write leaves no active token", async () => {
    const r = await cli(["create", "--user-id", aliceId, "--name", "lost", "--out", join(out, "no-such-dir", "lost.token")]);
    expect(r.code).toBe(1);
    expect(db.query("SELECT 1 FROM app_tokens WHERE user_id = ? AND label = 'lost'").get(aliceId)).toBeNull();
  });

  test("PATs off: no create, but list and revoke still work", async () => {
    const { token } = await create("before-off");
    const id = (db.query("SELECT id FROM app_tokens WHERE token_hash = ?").get(sha256(token)) as { id: string }).id;
    const off = { PAT_ENABLED: "off", MCP_ALLOWED_USER_IDS: "" };
    expect((await cli(["create", "--user-id", aliceId, "--name", "while-off", "--out", join(out, "off.token")], off)).code).toBe(1);
    expect((await cli(["list", "--user-id", aliceId], off)).stdout).toContain(id);
    expect((await cli(["revoke", "--user-id", aliceId, "--id", id], off)).code).toBe(0);
  });

  test("never makes a database: a wrong DATA_DIR is refused", async () => {
    const empty = mkdtempSync(join(config.dataDir, "pat-empty-"));
    const r = await cli(["list", "--user-id", aliceId], { DATA_DIR: empty });
    expect(r.code).toBe(1);
    expect(r.stderr).toContain("no database");
    expect(readdirSync(empty)).toEqual([]);
  });

  test("bad settings are refused at startup too", () => {
    const saved = { signIn: config.signIn, patEnabled: config.patEnabled, ids: config.mcpAllowedUserIds };
    try {
      config.mcpAllowedUserIds = new Set();
      expect(patProblem()).toContain("needs MCP_ALLOWED_USER_IDS");
      config.mcpAllowedUserIds = new Set(["bad id!"]);
      expect(patProblem()).toContain("invalid account id");
      config.mcpAllowedUserIds = saved.ids;
      config.signIn = false;
      expect(patProblem()).toContain("needs SIGN_IN=on");
    } finally {
      Object.assign(config, { signIn: saved.signIn, patEnabled: saved.patEnabled, mcpAllowedUserIds: saved.ids });
    }
  });
});
