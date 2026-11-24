import os from "node:os";
import path from "node:path";
import http from "node:http";
import { setTimeout as delay } from "node:timers/promises";
import { finalizeEvent, generateSecretKey, getPublicKey } from "@nostr/tools";
import { openWebSocket, WsClient } from "../utils/websocketClient.js";
import { config, runRelaySuite, writeConfig } from "../utils/relay.js";

const workDir = path.join(os.tmpdir(), "strfry-tests");
const dbDir = path.join(workDir, "webhook-db");
const cfgPath = path.join(workDir, "webhook.conf");
const port = 40561;
const serviceUrl = "wss://relay.test";
const maxSubscriptionsPerPubkey = 10;

const now = () => Math.floor(Date.now() / 1000);
const pass = (msg) => console.log(`Pass: ${msg}`);

function expect(cond, msg) {
  if (!cond) throw new Error(msg);
}

function newUser() {
  const sk = generateSecretKey();
  return { sk, pub: getPublicKey(sk) };
}

const alice = newUser();
const bob = newUser();

function sign(user, { kind = 1, tags = [], content = "", created_at = now() } = {}) {
  return finalizeEvent({ kind, tags, content, created_at }, user.sk);
}

function writeRelayConfig(webhooks, options = {}) {
  writeConfig(
    config(dbDir, port, true, {
      privateStorage: true,
      ...options,
      webhooks: { maxSubscriptionsPerPubkey, allowHttp: true, ...webhooks },
    }),
    cfgPath,
  );
}

// Echoes each challenge, unless the path says otherwise. Records every request, and answers 404 to POSTs under /gone/
class CallbackServer {
  constructor() {
    this.posts = [];
    this.challenges = [];
    this.server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        if (req.method === "GET") {
          const url = new URL(req.url, "http://callback");
          const challenge = url.searchParams.get("challenge");
          this.challenges.push({ path: url.pathname, query: url.search, challenge });

          res.statusCode = url.pathname.startsWith("/echo-404/") ? 404 : 200;
          if (url.pathname.startsWith("/no-echo/")) res.end("ok");
          else if (url.pathname.startsWith("/echo-newline/")) res.end(`${challenge}\n`);
          else res.end(challenge);
          return;
        }

        this.posts.push({ path: req.url, contentType: req.headers["content-type"], body: JSON.parse(body) });
        res.statusCode = req.url.startsWith("/gone/") ? 404 : 200;
        res.end("ok");
      });
    });
  }

  async listen() {
    // Every interface, so the machine's host name reaches it too
    await new Promise((resolve) => this.server.listen(0, resolve));
    this.base = `http://127.0.0.1:${this.server.address().port}`;
  }

  url(p) {
    return this.base + p;
  }

  to(p) {
    return this.posts.filter((post) => post.path === p);
  }

  async waitFor(p, eventId, timeoutMs = 3_000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const post = this.to(p).find((post) => post.body.id === eventId);
      if (post) return post;
      await delay(20);
    }
    throw new Error(`no POST to ${p} for ${eventId}`);
  }

  close() {
    this.server.close();
  }
}

const callbacks = new CallbackServer();

let wsUrl;

async function connect(user) {
  const client = new WsClient(await openWebSocket(wsUrl));
  const challenge = (await client.waitFor((m) => m[0] === "AUTH"))[1];
  const auth = finalizeEvent(
    {
      kind: 22242,
      created_at: now(),
      tags: [
        ["relay", serviceUrl],
        ["challenge", challenge],
      ],
      content: "",
    },
    user.sk,
  );
  client.send(["AUTH", auth]);
  const ok = await client.waitFor((m) => m[0] === "OK" && m[1] === auth.id);
  expect(ok[2] === true, `AUTH should succeed, got: ${ok[3]}`);
  return client;
}

async function publish(client, ev) {
  client.send(["EVENT", ev]);
  return await client.waitFor((m) => m[0] === "OK" && m[1] === ev.id);
}

async function store(client, ev) {
  const ok = await publish(client, ev);
  expect(ok[2] === true, `event should be stored, got: ${ok[3]}`);
  return ev;
}

async function query(client, subId, ...filters) {
  client.send(["REQ", subId, ...filters]);
  const msgs = await client.collectUntil((m) => (m[0] === "EOSE" || m[0] === "CLOSED") && m[1] === subId);
  if (msgs[msgs.length - 1][0] === "EOSE") client.send(["CLOSE", subId]);
  return msgs.filter((m) => m[0] === "EVENT" && m[1] === subId).map((m) => m[2]);
}

function subscription(user, d, { filters = [], ignore = [], callback, includeEvent = false, relay = serviceUrl, extraTags = [], created_at } = {}) {
  const tags = [["d", d]];
  if (relay) tags.push(["relay", relay]);
  for (const f of filters) tags.push(["filter", typeof f === "string" ? f : JSON.stringify(f)]);
  for (const f of ignore) tags.push(["ignore", JSON.stringify(f)]);
  if (callback) tags.push(["callback", callback]);
  if (includeEvent) tags.push(["include_event"]);
  return sign(user, { kind: 30390, tags: [...tags, ...extraTags], created_at });
}

async function testNip11() {
  const res = await fetch(`http://127.0.0.1:${port}/`, { headers: { Accept: "application/nostr+json" } });
  const info = await res.json();
  expect(info.supported_nips.includes("9a"), `NIP-11 must list 9a, got ${JSON.stringify(info.supported_nips)}`);
  pass("testNip11");
}

async function testRefusedSubscriptions({ aliceConn }) {
  const cb = callbacks.url("/refused");
  const kinds1 = { kinds: [1] };

  const cases = [
    ["another relay", subscription(alice, "r1", { filters: [kinds1], callback: cb, relay: "wss://other.example" }), "relay tag"],
    ["no relay tag", subscription(alice, "r2", { filters: [kinds1], callback: cb, relay: null }), "relay tag"],
    ["no filter", subscription(alice, "r3", { callback: cb }), "filter"],
    ["a filter that isn't JSON", subscription(alice, "r4", { filters: ["{kinds"], callback: cb }), "JSON"],
    ["a filter strfry can't run", subscription(alice, "r5", { filters: [{ foo: 1 }], callback: cb }), "filter"],
    ["no callback", subscription(alice, "r6", { filters: [kinds1] }), "callback"],
    ["two callbacks", subscription(alice, "r7", { filters: [kinds1], callback: cb, extraTags: [["callback", cb]] }), "callback"],
    ["a callback that isn't http", subscription(alice, "r8", { filters: [kinds1], callback: "ftp://example.com/x" }), "https"],
    ["a callback that isn't a URL", subscription(alice, "r9", { filters: [kinds1], callback: "not a url" }), "URL"],
  ];

  for (const [what, ev, reason] of cases) {
    const ok = await publish(aliceConn, ev);
    expect(
      ok[2] === false && ok[3].startsWith("invalid:") && ok[3].includes(reason),
      `a subscription with ${what} must be refused with invalid: (${reason}), got: ${ok[3]}`,
    );
  }

  pass("testRefusedSubscriptions");
}

async function testCallbackVerification({ aliceConn }) {
  const kinds1 = { kinds: [1] };

  // Nothing listens on port 1
  const cases = [
    ["doesn't echo the challenge", callbacks.url("/no-echo/1"), "didn't echo"],
    ["adds a newline to the challenge", callbacks.url("/echo-newline/1"), "didn't echo"],
    ["answers 404", callbacks.url("/echo-404/1"), "404"],
    ["is unreachable", "http://127.0.0.1:1/x", "unreachable"],
  ];

  for (const [i, [what, callback, reason]] of cases.entries()) {
    const ok = await publish(aliceConn, subscription(alice, `unverified-${i}`, { filters: [kinds1], callback }));
    expect(
      ok[2] === false && ok[3].startsWith("invalid:") && ok[3].includes(reason),
      `a subscription whose callback ${what} must be refused with invalid: (${reason}), got: ${ok[3]}`,
    );
  }

  const stored = await query(aliceConn, "unverified", { kinds: [30390], "#d": cases.map((_, i) => `unverified-${i}`) });
  expect(stored.length === 0, "a subscription whose callback refused the challenge must not be stored");

  await store(aliceConn, subscription(alice, "verified", { filters: [kinds1], callback: callbacks.url("/verified?token=abc"), created_at: now() - 10 }));
  const current = await store(aliceConn, subscription(alice, "verified", { filters: [kinds1], callback: callbacks.url("/verified?token=abc") }));

  const gets = callbacks.challenges.filter((c) => c.path === "/verified");
  expect(gets.length === 2, `each subscription must be verified, got ${gets.length} GETs`);
  expect(
    gets.every((g) => g.query.startsWith("?token=abc&challenge=") && /^[0-9a-f]{64}$/.test(g.challenge)),
    `the challenge must be appended to the callback's query, got ${gets.map((g) => g.query)}`,
  );
  expect(gets[0].challenge !== gets[1].challenge, "each challenge must be new");

  await store(aliceConn, current);
  expect(callbacks.challenges.filter((c) => c.path === "/verified").length === 2, "a subscription the relay already has must not be verified again");

  pass("testCallbackVerification");
}

async function testPushesMatchingEvents({ aliceConn }) {
  await store(aliceConn, subscription(alice, "notes", { filters: [{ kinds: [1] }], callback: callbacks.url("/notes") }));
  await store(
    aliceConn,
    subscription(alice, "full", {
      filters: [{ kinds: [1] }],
      ignore: [{ "#t": ["skip"] }],
      includeEvent: true,
      callback: callbacks.url("/full"),
    }),
  );

  const note = await store(aliceConn, sign(alice, { content: "hello" }));
  const post = await callbacks.waitFor("/notes", note.id);
  expect(post.contentType === "application/json", `the POST must be JSON, got ${post.contentType}`);
  expect(post.body.relay === "wss://relay.test/", `relay must be the normalized relay URL, got ${post.body.relay}`);
  expect(!("event" in post.body), "without include_event, the event must not be sent");

  const full = await callbacks.waitFor("/full", note.id);
  const fields = ["id", "pubkey", "created_at", "kind", "tags", "content", "sig"];
  const sent = full.body.event ?? {};
  expect(
    fields.every((k) => JSON.stringify(sent[k]) === JSON.stringify(note[k])),
    "with include_event, the whole event must be sent",
  );

  const skipped = await store(aliceConn, sign(alice, { content: "skip me", tags: [["t", "skip"]] }));
  await callbacks.waitFor("/notes", skipped.id);
  await delay(300);
  expect(!callbacks.to("/full").some((p) => p.body.id === skipped.id), "an event matching an ignore filter must not be pushed");

  const reaction = await store(aliceConn, sign(alice, { kind: 7, content: "+" }));
  const later = await store(aliceConn, sign(alice, { content: "after the reaction" }));
  await callbacks.waitFor("/notes", later.id);
  await delay(300);
  expect(!callbacks.to("/notes").some((p) => p.body.id === reaction.id), "an event matching no filter must not be pushed");

  pass("testPushesMatchingEvents");
}

async function testOnlyOwnEvents({ aliceConn, bobConn }) {
  await store(aliceConn, subscription(alice, "wraps", { filters: [{ kinds: [1059] }], callback: callbacks.url("/wraps") }));

  const bobNote = await store(bobConn, sign(bob, { content: "bob's note" }));

  const wrap = (to) => sign(newUser(), { kind: 1059, tags: [["p", to.pub]], content: "sealed" });
  const forBob = await store(bobConn, wrap(bob));
  const forAlice = await store(aliceConn, wrap(alice));

  await callbacks.waitFor("/wraps", forAlice.id);
  await delay(300);
  expect(!callbacks.to("/notes").some((p) => p.body.id === bobNote.id), "another user's events must not be pushed");
  expect(!callbacks.to("/wraps").some((p) => p.body.id === forBob.id), "a gift wrap for someone else must not be pushed");

  pass("testOnlyOwnEvents");
}

async function testSubscriptionsAreNeverPushed({ aliceConn }) {
  await store(aliceConn, subscription(alice, "everything", { filters: [{}], callback: callbacks.url("/everything") }));

  const other = await store(aliceConn, subscription(alice, "other", { filters: [{ kinds: [30023] }], callback: callbacks.url("/other") }));
  const note = await store(aliceConn, sign(alice, { content: "seen by everything" }));
  await callbacks.waitFor("/everything", note.id);
  await delay(300);
  expect(!callbacks.to("/everything").some((p) => p.body.id === other.id), "kind 30390 events must never be pushed");

  await store(aliceConn, sign(alice, { kind: 5, tags: [["a", `30390:${alice.pub}:everything`]] }));
  await store(aliceConn, sign(alice, { kind: 5, tags: [["e", other.id]] }));
  const afterDeletion = await store(aliceConn, sign(alice, { content: "after the deletion" }));
  await callbacks.waitFor("/notes", afterDeletion.id);
  await delay(300);
  expect(
    !callbacks.to("/everything").some((p) => p.body.id === afterDeletion.id),
    "a deleted subscription must not receive anything",
  );

  pass("testSubscriptionsAreNeverPushed");
}

async function testReplacementKeepsPushing({ aliceConn }) {
  const first = subscription(alice, "resync", { filters: [{ kinds: [1] }], callback: callbacks.url("/resync"), created_at: now() - 10 });
  await store(aliceConn, first);
  await store(aliceConn, subscription(alice, "resync", { filters: [{ kinds: [1] }], callback: callbacks.url("/resync") }));

  const subs = await query(aliceConn, "resync", { kinds: [30390], "#d": ["resync"] });
  expect(subs.length === 1 && subs[0].id !== first.id, "the newer subscription must replace the older one");

  const note = await store(aliceConn, sign(alice, { content: "after the resync" }));
  await callbacks.waitFor("/resync", note.id);
  expect(callbacks.to("/resync").filter((p) => p.body.id === note.id).length === 1, "a replaced subscription must push once");

  pass("testReplacementKeepsPushing");
}

async function testRemovedOn404({ aliceConn }) {
  await store(aliceConn, subscription(alice, "gone", { filters: [{ kinds: [1] }], callback: callbacks.url("/gone/1") }));
  const note = await store(aliceConn, sign(alice, { content: "for a push server that forgot us" }));
  await callbacks.waitFor("/gone/1", note.id);

  const deadline = Date.now() + 3_000;
  let remaining;
  do {
    await delay(100);
    remaining = await query(aliceConn, "gone", { kinds: [30390], "#d": ["gone"] });
  } while (remaining.length && Date.now() < deadline);
  expect(remaining.length === 0, "a subscription whose callback answers 404 must be deleted");

  const again = await store(aliceConn, sign(alice, { content: "after the 404" }));
  await callbacks.waitFor("/notes", again.id);
  await delay(300);
  expect(callbacks.to("/gone/1").length === 1, "a deleted subscription must not be called again");

  pass("testRemovedOn404");
}

async function testSubscriptionLimit({ bobConn }) {
  for (let i = 0; i < maxSubscriptionsPerPubkey; i++) {
    await store(bobConn, subscription(bob, `bob-${i}`, { filters: [{ kinds: [1] }], callback: callbacks.url(`/bob/${i}`) }));
  }

  const ok = await publish(bobConn, subscription(bob, "one-too-many", { filters: [{ kinds: [1] }], callback: callbacks.url("/bob/x") }));
  expect(ok[2] === false && ok[3].startsWith("blocked:"), `a subscription over the limit must be blocked, got: ${ok[3]}`);

  await store(bobConn, subscription(bob, "bob-0", { filters: [{ kinds: [7] }], callback: callbacks.url("/bob/0"), created_at: now() + 1 }));

  pass("testSubscriptionLimit");
}

async function testIgnoreSelf({ aliceConn, bobConn }) {
  const dms = { kinds: [1059], "#p": [alice.pub] };
  await store(aliceConn, subscription(alice, "dm-all", { filters: [dms], callback: callbacks.url("/dm-all") }));
  await store(aliceConn, subscription(alice, "dm-inbox", { filters: [dms], callback: callbacks.url("/dm-inbox"), extraTags: [["ignore_self"]] }));

  // Bob can only send Alice a gift wrap while anyone can write
  const wrapForAlice = () => sign(newUser(), { kind: 1059, tags: [["p", alice.pub]], content: "sealed" });
  const bobCanWrite = async (expected) => {
    const deadline = Date.now() + 3_000;
    let ev, ok;
    do {
      await delay(100);
      ev = wrapForAlice();
      ok = await publish(bobConn, ev);
    } while (ok[2] !== expected && Date.now() < deadline);
    expect(ok[2] === expected, `bob's gift wrap for alice should be ${expected ? "stored" : "refused"}, got: ${ok[3]}`);
    return ev;
  };

  writeRelayConfig({ allowPrivateAddresses: true }, { authorOnlyWrites: false });
  const received = await bobCanWrite(true);
  const selfCopy = await store(aliceConn, wrapForAlice());

  await callbacks.waitFor("/dm-inbox", received.id);
  await callbacks.waitFor("/dm-all", received.id);
  await callbacks.waitFor("/dm-all", selfCopy.id);
  await delay(300);
  expect(
    !callbacks.to("/dm-inbox").some((p) => p.body.id === selfCopy.id),
    "with ignore_self, an event sent over a connection AUTHed as the subscription's author must not be pushed",
  );

  writeRelayConfig({ allowPrivateAddresses: true });
  await bobCanWrite(false);

  pass("testIgnoreSelf");
}

async function testPrivateAddresses({ aliceConn }) {
  // A host name passes the parser, so only the check before connecting can stop it
  const byName = `http://${os.hostname()}:${callbacks.server.address().port}/by-name`;
  const byNameOk = await publish(aliceConn, subscription(alice, "by-name", { filters: [{ kinds: [1] }], callback: byName }));
  const control = await store(aliceConn, sign(alice, { content: "reaches the host name" }));
  const hostNameReachable = byNameOk[2] === true && (await callbacks.waitFor("/by-name", control.id).then(() => true, () => false));
  if (!hostNameReachable) console.log(`Skipping the host name check: ${os.hostname()} doesn't reach this machine`);

  writeRelayConfig({ allowPrivateAddresses: false });

  const refused = (url) => subscription(alice, `private-${url}`, { filters: [{ kinds: [1] }], callback: url });
  const deadline = Date.now() + 3_000;
  let ok;
  do {
    await delay(100);
    ok = await publish(aliceConn, refused(callbacks.url("/private")));
  } while (ok[2] === true && Date.now() < deadline);
  expect(ok[2] === false && ok[3].includes("private address"), `a loopback callback must be refused, got: ${ok[3]}`);

  for (const url of ["http://localhost/x", "http://[::1]/x", "http://10.1.2.3/x", "http://192.168.1.1/x", "http://[::ffff:127.0.0.1]/x", "http://169.254.169.254/latest"]) {
    const res = await publish(aliceConn, refused(url));
    expect(res[2] === false && res[3].includes("private address"), `${url} must be refused, got: ${res[3]}`);
  }

  // The parser may let this one through as a host name: then the connection to 127.0.0.1 must be refused
  const callbackPort = callbacks.server.address().port;
  await publish(aliceConn, refused(`http://0x7f000001:${callbackPort}/hex`));

  // Subscriptions stored before are checked again, so /notes stops receiving
  const note = await store(aliceConn, sign(alice, { content: "nobody should get this" }));
  await delay(1_000);
  expect(!callbacks.to("/notes").some((p) => p.body.id === note.id), "a stored loopback subscription must stop being called");
  expect(
    callbacks.to("/hex").length === 0 && !callbacks.challenges.some((c) => c.path === "/hex"),
    "a numeric host for 127.0.0.1 must not be called",
  );
  expect(
    !callbacks.to("/by-name").some((p) => p.body.id === note.id),
    "a host name resolving to a private address must not be called",
  );

  pass("testPrivateAddresses");
}

async function testDisabled({ aliceConn }) {
  writeRelayConfig({ enabled: false });

  const deadline = Date.now() + 3_000;
  let ok;
  do {
    await delay(100);
    ok = await publish(aliceConn, subscription(alice, `disabled-${Date.now()}`, { filters: [{ kinds: [1] }], callback: "https://push.example.com/x" }));
  } while (!ok[3].startsWith("blocked:") && Date.now() < deadline);
  expect(ok[2] === false && ok[3].startsWith("blocked:"), `with webhooks disabled, subscriptions must be blocked, got: ${ok[3]}`);

  const res = await fetch(`http://127.0.0.1:${port}/`, { headers: { Accept: "application/nostr+json" } });
  const info = await res.json();
  expect(!info.supported_nips.includes("9a"), "with webhooks disabled, NIP-11 must not list 9a");

  pass("testDisabled");
}

async function main() {
  console.log("* webhook (NIP-9a) integration tests");

  await callbacks.listen();
  writeRelayConfig({ allowPrivateAddresses: true });

  try {
    await runRelaySuite({
      relayConfigPath: cfgPath,
      relayPort: port,
      relayDbPath: dbDir,
      tests: async (ctx) => {
        wsUrl = ctx.wsUrl;

        await testNip11();

        const conns = { aliceConn: await connect(alice), bobConn: await connect(bob) };
        try {
          await testRefusedSubscriptions(conns);
          await testCallbackVerification(conns);
          await testPushesMatchingEvents(conns);
          await testOnlyOwnEvents(conns);
          await testSubscriptionsAreNeverPushed(conns);
          await testReplacementKeepsPushing(conns);
          await testRemovedOn404(conns);
          await testSubscriptionLimit(conns);
          await testIgnoreSelf(conns);
          await testPrivateAddresses(conns);
          await testDisabled(conns);
        } finally {
          await conns.aliceConn.close();
          await conns.bobConn.close();
        }
      },
    });
  } finally {
    callbacks.close();
  }

  console.log("All webhook tests passed!");
}

main().catch((err) => {
  console.error(err && err.stack ? err.stack : String(err));
  process.exit(1);
});
