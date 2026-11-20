import os from "node:os";
import path from "node:path";
import { writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { finalizeEvent, generateSecretKey, getPublicKey, nip19 } from "@nostr/tools";
import { openWebSocket, WsClient } from "../utils/websocketClient.js";
import { cleanDb, config, runRelaySuite, runStrfry, writeConfig } from "../utils/relay.js";

const workDir = path.join(os.tmpdir(), "strfry-tests");
const dbDir = path.join(workDir, "admin-db");
const cfgPath = path.join(workDir, "admin.conf");
const port = 40559;
const httpUrl = `http://127.0.0.1:${port}/`;
const serviceUrl = "wss://relay.test";

const now = () => Math.floor(Date.now() / 1000);
const pass = (msg) => console.log(`Pass: ${msg}`);

function expect(cond, msg) {
  if (!cond) throw new Error(msg);
}

function newUser() {
  const sk = generateSecretKey();
  return { sk, pub: getPublicKey(sk) };
}

const admin = newUser();
const alice = newUser();
const bob = newUser();
const carol = newUser();

function sign(user, { kind = 1, tags = [], content = "", created_at = now() } = {}) {
  return finalizeEvent({ kind, tags, content, created_at }, user.sk);
}

function authHeader(user, body, { url = "https://relay.test/", method = "POST", created_at = now(), payload } = {}) {
  const ev = sign(user, {
    kind: 27235,
    created_at,
    tags: [
      ["u", url],
      ["method", method],
      ["payload", payload ?? createHash("sha256").update(body).digest("hex")],
    ],
  });
  return `Nostr ${Buffer.from(JSON.stringify(ev)).toString("base64")}`;
}

async function rpc(method, params = [], { as = admin, auth } = {}) {
  const body = JSON.stringify({ method, params });
  const res = await fetch(httpUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/nostr+json+rpc",
      Authorization: auth ?? authHeader(as, body),
    },
    body,
  });
  return { status: res.status, ...(await res.json()) };
}

async function call(method, params = []) {
  const res = await rpc(method, params);
  expect(res.status === 200 && res.error === undefined, `${method} failed: ${res.status} ${res.error}`);
  return res.result;
}

async function relayInfo() {
  const res = await fetch(httpUrl, { headers: { Accept: "application/nostr+json" } });
  return await res.json();
}

let wsUrl;

async function connect() {
  const client = new WsClient(await openWebSocket(wsUrl));
  const auth = await client.waitFor((m) => m[0] === "AUTH");
  client.challenge = auth[1];
  return client;
}

async function authAs(client, user) {
  const ev = sign(user, {
    kind: 22242,
    tags: [
      ["relay", serviceUrl],
      ["challenge", client.challenge],
    ],
  });
  client.send(["AUTH", ev]);
  return await client.waitFor((m) => m[0] === "OK" && m[1] === ev.id);
}

async function publish(client, ev) {
  client.send(["EVENT", ev]);
  return await client.waitFor((m) => m[0] === "OK" && m[1] === ev.id);
}

async function query(client, subId, ...filters) {
  client.send(["REQ", subId, ...filters]);
  const msgs = await client.collectUntil((m) => (m[0] === "EOSE" || m[0] === "CLOSED") && m[1] === subId);
  if (msgs[msgs.length - 1][0] === "EOSE") client.send(["CLOSE", subId]);
  return msgs.filter((m) => m[0] === "EVENT" && m[1] === subId).map((m) => m[2]);
}

async function closed(client, timeoutMs = 2_000) {
  if (client.ws.readyState === client.ws.CLOSED) return true;
  return await Promise.race([
    new Promise((resolve) => client.ws.addEventListener("close", () => resolve(true), { once: true })),
    delay(timeoutMs).then(() => false),
  ]);
}

async function testHttpEndpoints() {
  const info = await relayInfo();
  expect(info.supported_nips.includes(86), "NIP-11 must list NIP-86 when admins are configured");

  const page = await fetch(`${httpUrl}admin`);
  expect(page.status === 200, "/admin must be served");
  expect((await page.text()).includes("<html"), "/admin must return the admin page");
  expect(page.headers.get("x-frame-options") === "DENY", "/admin must not be framed");

  const preflight = await fetch(httpUrl, { method: "OPTIONS" });
  expect(preflight.status === 204, `CORS preflight must answer 204, got ${preflight.status}`);
  expect(
    preflight.headers.get("access-control-allow-headers").includes("Authorization"),
    "CORS preflight must allow the Authorization header",
  );

  pass("testHttpEndpoints");
}

async function testOnlyAdminsCanCall() {
  const body = JSON.stringify({ method: "supportedmethods", params: [] });

  const cases = [
    ["missing header", ""],
    ["non-admin signer", authHeader(alice, body)],
    ["other relay", authHeader(admin, body, { url: "https://other.relay/" })],
    ["wrong method", authHeader(admin, body, { method: "GET" })],
    ["wrong payload", authHeader(admin, body, { payload: "00".repeat(32) })],
    ["stale event", authHeader(admin, body, { created_at: now() - 120 })],
  ];

  for (const [name, auth] of cases) {
    const res = await rpc("supportedmethods", [], { auth });
    expect(res.status === 401 && res.error, `${name} must be refused with 401, got ${res.status}`);
  }

  const methods = await call("supportedmethods");
  for (const m of ["banpubkey", "allowpubkey", "blockip", "changerelayname", "stats", "erasepubkey", "backup", "import"]) {
    expect(methods.includes(m), `supportedmethods must list ${m}`);
  }

  const unknown = await rpc("allowkind", [1]);
  expect(unknown.status === 200 && unknown.error.includes("unsupported"), "unknown methods must return an error");

  pass("testOnlyAdminsCanCall");
}

async function testStats(conns) {
  await authAs(conns.alice, alice);
  await authAs(conns.bob, bob);

  for (let i = 0; i < 3; i++) {
    const ok = await publish(conns.alice, sign(alice, { content: `alice ${i}` }));
    expect(ok[2] === true, `alice should store her event: ${ok[3]}`);
  }
  expect((await publish(conns.bob, sign(bob, { content: "bob" })))[2] === true, "bob should store his event");

  // A wrap signed by a throwaway key belongs to its recipient
  const wrap = sign(newUser(), { kind: 1059, tags: [["p", alice.pub]], content: "wrapped" });
  expect((await publish(conns.alice, wrap))[2] === true, "alice should store a wrap addressed to her");

  const stats = await call("stats");
  const aliceUsage = stats.topUsers.find((u) => u.pubkey === alice.pub);
  const bobUsage = stats.topUsers.find((u) => u.pubkey === bob.pub);

  expect(aliceUsage?.events === 4, `alice must own 4 events including her wrap, got ${aliceUsage?.events}`);
  expect(bobUsage?.events === 1, "bob must own 1 event");
  expect(stats.topUsers[0].pubkey === alice.pub, "the top user must be the one using the most storage");
  expect(stats.events >= 5 && stats.storage > 0 && stats.dbSize > 0, "stats must report totals");
  expect(stats.users >= 2 && stats.connections >= 2, "stats must count users and connections");
  expect(stats.allowList === false, "the relay must start open");

  pass("testStats");
}

async function testBans(conns) {
  expect((await call("banpubkey", [nip19.npubEncode(bob.pub), "spam"])) === true, "banpubkey must accept an npub");

  const banned = await call("listbannedpubkeys");
  expect(banned.some((b) => b.pubkey === bob.pub && b.reason === "spam"), "bob must be listed as banned");

  const ok = await publish(conns.bob, sign(bob, { content: "after ban" }));
  expect(ok[2] === false && ok[3].startsWith("blocked:"), `a banned pubkey can't write, even on an authed connection: ${ok[3]}`);

  const fresh = await connect();
  const auth = await authAs(fresh, bob);
  expect(auth[2] === false && auth[3].startsWith("restricted:"), `a banned pubkey can't AUTH: ${auth[3]}`);

  await call("unbanpubkey", [bob.pub]);
  expect((await authAs(fresh, bob))[2] === true, "an unbanned pubkey can AUTH again");
  await fresh.close();

  pass("testBans");
}

async function testAllowList() {
  await call("allowpubkey", [carol.pub, "paid"]);

  const stats = await call("stats");
  expect(stats.allowList === true, "an allowed pubkey turns the allow list on");
  expect((await relayInfo()).limitation.restricted_writes === true, "NIP-11 must say writes are restricted");

  const client = await connect();
  const refused = await authAs(client, bob);
  expect(refused[2] === false && refused[3].startsWith("restricted:"), `a pubkey off the allow list can't AUTH: ${refused[3]}`);
  expect((await authAs(client, carol))[2] === true, "an allowed pubkey can AUTH");
  expect((await authAs(client, admin))[2] === true, "admins can always AUTH");

  await call("banpubkey", [carol.pub]);
  const allowed = await call("listallowedpubkeys");
  expect(!allowed.some((a) => a.pubkey === carol.pub), "banning a pubkey removes it from the allow list");

  await call("unbanpubkey", [carol.pub]);
  expect((await call("stats")).allowList === false, "the relay is open again once the allow list is empty");
  await client.close();

  pass("testAllowList");
}

async function testRelayInfoOverrides() {
  await call("changerelayname", ["Renamed"]);
  await call("changerelaydescription", ["Set from the admin"]);
  await call("changerelayicon", ["https://relay.test/icon.png"]);

  let info = await relayInfo();
  expect(info.name === "Renamed", `NIP-11 name must follow changerelayname, got ${info.name}`);
  expect(info.description === "Set from the admin", "NIP-11 description must follow changerelaydescription");
  expect(info.icon === "https://relay.test/icon.png", "NIP-11 icon must follow changerelayicon");

  const landing = await (await fetch(httpUrl)).text();
  expect(landing.includes("Renamed"), "the landing page must show the new name");

  await call("changerelayname", [""]);
  info = await relayInfo();
  expect(info.name === "nostr-private-relay", "an empty name falls back to the config");

  pass("testRelayInfoOverrides");
}

async function testBlockedIps() {
  const before = await connect();

  await call("blockip", ["127.0.0.1", "abuse"]);
  expect(await closed(before), "blocking an IP drops its open connections");

  const blocked = await call("listblockedips");
  expect(blocked.some((b) => b.ip === "127.0.0.1" && b.reason === "abuse"), "the IP must be listed as blocked");

  const ws = await openWebSocket(wsUrl);
  const client = new WsClient(ws);
  expect(await closed(client), "a blocked IP is closed as soon as it connects");

  const invalid = await rpc("blockip", ["not an ip"]);
  expect(invalid.error?.includes("invalid IP"), "blockip must validate the address");

  await call("unblockip", ["127.0.0.1"]);
  const after = await connect();
  await after.close();

  pass("testBlockedIps");
}

async function testBackup() {
  const token = await call("backup");
  expect(/^[0-9a-f]{64}$/.test(token), `backup must return a token, got ${token}`);

  const res = await fetch(`${httpUrl}admin/backup?token=${token}`);
  expect(res.status === 200, `the backup must download, got ${res.status}`);
  expect(
    /^attachment; filename="relay\.test-\d{8}-\d{6}\.mdb"$/.test(res.headers.get("content-disposition")),
    `the backup must download as a file, got ${res.headers.get("content-disposition")}`,
  );
  const file = Buffer.from(await res.arrayBuffer());
  expect(file.length > 0 && file.length === Number(res.headers.get("content-length")), "the backup must arrive whole");

  const reused = await fetch(`${httpUrl}admin/backup?token=${token}`);
  expect(reused.status === 404, `a backup link works once, got ${reused.status}`);
  await reused.text();

  const forged = await fetch(`${httpUrl}admin/backup?token=${"00".repeat(32)}`);
  expect(forged.status === 404, `an unknown token must be refused, got ${forged.status}`);
  await forged.text();

  const restoreDir = path.join(workDir, "admin-restore-db");
  const restoreCfg = path.join(workDir, "admin-restore.conf");
  cleanDb(restoreDir);
  writeFileSync(path.join(restoreDir, "data.mdb"), file);
  writeConfig(config(restoreDir, port + 1), restoreCfg);

  const exported = runStrfry(["--config", restoreCfg, "export"]);
  expect(exported.status === 0, `the backup must open as a DB: ${exported.stderr}`);
  const events = exported.stdout.trim().split("\n").map((line) => JSON.parse(line));
  expect(events.filter((ev) => ev.pubkey === alice.pub).length === 3, "the backup must hold alice's events");
  expect(events.some((ev) => ev.kind === 1059 && ev.tags.some((t) => t[0] === "p" && t[1] === alice.pub)), "the backup must hold the wrap addressed to alice");

  pass("testBackup");
}

async function testErasePubkey() {
  const client = await connect();
  await authAs(client, alice);
  await authAs(client, bob);

  const deleted = await call("erasepubkey", [alice.pub]);
  expect(deleted === 4, `erasepubkey must delete alice's events and the wrap addressed to her, got ${deleted}`);

  const left = await query(client, "left", {});
  expect(left.every((ev) => ev.pubkey !== alice.pub && ev.kind !== 1059), "nothing of alice must remain");
  expect(left.some((ev) => ev.pubkey === bob.pub), "bob's events must remain");

  const stats = await call("stats");
  expect(!stats.topUsers.some((u) => u.pubkey === alice.pub), "alice must be gone from the stats");
  await client.close();

  pass("testErasePubkey");
}

async function postImport(token, body) {
  const res = await fetch(`${httpUrl}admin/import?token=${token}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-ndjson" },
    body,
  });
  return { status: res.status, ...(await res.json()) };
}

async function testImport() {
  const dave = newUser();
  const eve = newUser();
  await call("banpubkey", [eve.pub]);

  const notes = [0, 1, 2].map((i) => sign(dave, { content: `dave ${i}`, created_at: now() - 400 * 86400 + i }));
  const wrap = sign(newUser(), { kind: 1059, tags: [["p", dave.pub]], content: "wrapped" });
  const forged = { ...sign(dave, { content: "signed" }), content: "tampered" };
  const firstSlice = notes.map((ev) => JSON.stringify(ev) + "\n").join("") + "\n";
  const secondSlice = [wrap, sign(eve, { content: "banned" }), forged].map((ev) => JSON.stringify(ev)).join("\n") + "\nnot json";

  const token = await call("import");
  expect(/^[0-9a-f]{64}$/.test(token), `import must return a token, got ${token}`);

  const first = await postImport(token, firstSlice);
  expect(first.status === 200 && first.result.lines === 4 && first.result.added === 3, `old events must import: ${JSON.stringify(first)}`);

  const second = (await postImport(token, secondSlice)).result;
  expect(second.lines === 4 && second.added === 1, `the wrap must import: ${JSON.stringify(second)}`);
  expect(second.refused === 1 && second.errors.some((e) => e.line === 2 && e.error.includes("banned")), "a banned pubkey's event must be refused");
  expect(second.invalid === 2 && second.errors.some((e) => e.line === 3 && e.error.includes("bad event id")), "a tampered event must be invalid");

  const again = (await postImport(token, firstSlice)).result;
  expect(again.added === 0 && again.skipped === 3, `events already stored must be skipped: ${JSON.stringify(again)}`);

  const client = await connect();
  await authAs(client, dave);
  let stored = await query(client, "imported", {});
  expect(stored.length === 4 && stored.some((ev) => ev.id === wrap.id), `dave must read his imported events and wrap, got ${stored.length}`);

  const deletion = sign(dave, { kind: 5, tags: [["e", wrap.id]] });
  expect((await postImport(token, JSON.stringify(deletion))).result.added === 1, "a deletion request must import");
  stored = await query(client, "after-deletion", {});
  expect(!stored.some((ev) => ev.id === wrap.id), "an imported deletion from the recipient must delete the wrap");
  await client.close();

  const unknown = await postImport("00".repeat(32), firstSlice);
  expect(unknown.status === 404, `an unknown import token must be refused, got ${unknown.status}`);

  const tooLarge = await postImport(token, "x".repeat((1 << 20) + 1));
  expect(tooLarge.status === 413, `a slice over 1 MiB must be refused, got ${tooLarge.status}`);

  pass("testImport");
}

async function main() {
  console.log("* relay management (NIP-86) integration tests");

  writeConfig(
    config(dbDir, port, true, { privateStorage: true, adminPubkeys: nip19.npubEncode(admin.pub) }),
    cfgPath,
  );

  await runRelaySuite({
    relayConfigPath: cfgPath,
    relayPort: port,
    relayDbPath: dbDir,
    tests: async (ctx) => {
      wsUrl = ctx.wsUrl;

      await testHttpEndpoints();
      await testOnlyAdminsCanCall();

      const conns = { alice: await connect(), bob: await connect() };
      try {
        await testStats(conns);
        await testBans(conns);
      } finally {
        await conns.alice.close();
        await conns.bob.close();
      }

      await testAllowList();
      await testRelayInfoOverrides();
      await testBlockedIps();
      await testBackup();
      await testErasePubkey();
      await testImport();
    },
  });

  console.log("All relay management tests passed!");
}

main().catch((err) => {
  console.error(err && err.stack ? err.stack : String(err));
  process.exit(1);
});
