// The demo turned off (DEMO_ENABLED=off): no room is allocated (POST /api/demo/room 404s like on a server without
// sign-in), /api/server says so, a made-up demo room id leaks nothing, and the rest is untouched: sign-in works and
// an account still gets its own persistent workspace (POST /api/workspaces/personal).
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { isolate } from "./helpers.ts";

process.env.POLL_MS = "60000";
const { config } = await import("../../src/server/config.ts");
const { db } = await import("../../src/server/db.ts");
const restore = isolate(config, db);
Object.assign(config, { storage: "local", allowDevLogin: true, signIn: true, quietMs: 100, demoEnabled: false });
config.github.clientId = "";
config.github.appSlug = "";
const { startServer } = await import("../../src/server/index.ts");

let base = "";
let app: Awaited<ReturnType<typeof startServer>>;
let alice = "";

const GUEST = { "x-grimoire-guest": "demoGuest01", "x-grimoire-guest-name": "lumpy-llama" };

async function api(cookie: string, method: string, path: string, body?: unknown) {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { cookie, origin: base, "content-type": "application/json", ...(cookie ? {} : GUEST) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, data: text ? (JSON.parse(text) as any) : null };
}

beforeAll(async () => {
  app = await startServer({ port: 0, quiet: true });
  base = `http://localhost:${app.server.port}`;
  const res = await fetch(`${base}/auth/dev`, { method: "POST", headers: { origin: base }, body: new URLSearchParams({ name: "Alice" }), redirect: "manual" });
  alice = res.headers.getSetCookie().find((s) => s.startsWith("np_session="))!.split(";")[0]!;
});

afterAll(async () => {
  await app?.stop();
  restore();
});

describe("demo off", () => {
  test("no demo room is allocated; /api/server says the demo is off with sign-in on", async () => {
    expect(await api("", "POST", "/api/demo/room")).toEqual({ status: 404, data: { error: "this server has no demo" } });
    const server = await api("", "GET", "/api/server");
    expect(server.status).toBe(200);
    expect(server.data.demoEnabled).toBe(false);
    expect(server.data.signIn).toBe(true);
  });

  test("a made-up demo room id leaks nothing (no row, no seed)", async () => {
    expect((await api("", "GET", "/api/workspace/demo.0123456789/tree")).status).toBe(404);
    expect((await api("", "GET", "/api/workspace/demo/tree")).status).toBe(404);
    expect((db.query("SELECT count(*) AS n FROM repos WHERE id LIKE 'demo.%'").get() as { n: number }).n).toBe(0);
  });

  test("sign-in and the personal workspace are untouched", async () => {
    const made = await api(alice, "POST", "/api/workspaces/personal");
    expect([200, 201]).toContain(made.status);
    expect(made.data.kind).toBe("notes");
    expect(made.data.canRemove).toBe(true);
    const list = await api(alice, "GET", "/api/workspaces");
    expect(list.status).toBe(200);
    expect((list.data as { id: string }[]).some((w) => w.id === made.data.id)).toBe(true);
  });
});
