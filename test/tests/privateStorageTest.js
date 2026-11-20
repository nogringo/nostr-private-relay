import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { finalizeEvent, generateSecretKey, getPublicKey } from "@nostr/tools";
import { openWebSocket, WsClient } from "../utils/websocketClient.js";
import { config, runRelaySuite, writeConfig } from "../utils/relay.js";

const require = createRequire(import.meta.url);
const { Negentropy, NegentropyStorageVector } = require("../../external/negentropy/js/Negentropy.js");

const workDir = path.join(os.tmpdir(), "strfry-tests");
const dbDir = path.join(workDir, "private-db");
const cfgPath = path.join(workDir, "privateStorage.conf");
const port = 40557;
const serviceUrl = "wss://relay.test";

// Largest NIP-44 v2 payload: 1 + 32 + 2 + 65536 + 32 bytes, base64 encoded
const MAX_NIP44_PAYLOAD_LENGTH = 87472;

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
const carol = newUser();

const stored = { [alice.pub]: new Set(), [bob.pub]: new Set() };

function sign(user, { kind = 1, tags = [], content = "", created_at = now() } = {}) {
  return finalizeEvent({ kind, tags, content, created_at }, user.sk);
}

let wsUrl;

async function connect() {
  const client = new WsClient(await openWebSocket(wsUrl));
  const auth = await client.waitFor((m) => m[0] === "AUTH");
  client.challenge = auth[1];
  return client;
}

async function authAs(client, user) {
  const ev = finalizeEvent(
    {
      kind: 22242,
      created_at: now(),
      tags: [
        ["relay", serviceUrl],
        ["challenge", client.challenge],
      ],
      content: "",
    },
    user.sk,
  );
  client.send(["AUTH", ev]);
  return await client.waitFor((m) => m[0] === "OK" && m[1] === ev.id);
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
  const msgs = await client.collectUntil(
    (m) => (m[0] === "EOSE" || m[0] === "CLOSED") && m[1] === subId,
  );
  const last = msgs[msgs.length - 1];
  if (last[0] === "EOSE") client.send(["CLOSE", subId]);
  return {
    events: msgs.filter((m) => m[0] === "EVENT" && m[1] === subId).map((m) => m[2]),
    closed: last[0] === "CLOSED" ? last[2] : null,
  };
}

function sameIds(events, ids) {
  const got = new Set(events.map((ev) => ev.id));
  return got.size === ids.size && [...ids].every((id) => got.has(id));
}

async function testEverythingNeedsAuth() {
  const client = await connect();

  const req = await query(client, "req", {});
  expect(
    req.closed?.startsWith("auth-required:"),
    `unauthenticated REQ must be CLOSED with an auth-required: prefix, got: ${req.closed}`,
  );

  client.send(["COUNT", "count", {}]);
  const count = await client.waitFor((m) => m[1] === "count");
  expect(
    count[0] === "CLOSED" && count[2].startsWith("auth-required:"),
    "unauthenticated COUNT must be CLOSED with auth-required:",
  );

  client.send(["NEG-OPEN", "neg", {}, "61"]);
  const neg = await client.waitFor((m) => m[1] === "neg");
  expect(
    neg[0] === "NEG-ERR" && neg[2].startsWith("auth-required:"),
    "unauthenticated NEG-OPEN must fail with auth-required:",
  );

  const ok = await publish(client, sign(alice, { content: "no auth" }));
  expect(
    ok[2] === false && ok[3].startsWith("auth-required:"),
    "unauthenticated EVENT must be rejected with auth-required:",
  );

  await client.close();
  pass("testEverythingNeedsAuth");
}

async function testWritesNeedTheirAuthor({ aliceConn, bobConn }) {
  expect((await authAs(aliceConn, alice))[2] === true, "alice should AUTH");
  expect((await authAs(aliceConn, alice))[2] === true, "AUTH again as the same pubkey should succeed");
  expect((await authAs(bobConn, bob))[2] === true, "bob should AUTH");

  const draft = (d, content) =>
    sign(alice, {
      kind: 31234,
      tags: [
        ["d", d],
        ["k", "1"],
        ["expiration", String(now() + 90 * 86400)],
      ],
      content,
    });

  for (const ev of [
    sign(alice, { content: "alice note" }),
    draft("draft-1", "encrypted draft"),
    draft("draft-max", "A".repeat(MAX_NIP44_PAYLOAD_LENGTH)),
  ]) {
    await store(aliceConn, ev);
    stored[alice.pub].add(ev.id);
  }

  for (const ev of [
    sign(bob, { content: "bob note" }),
    sign(bob, { kind: 31234, tags: [["d", "bob-draft"], ["k", "1"]], content: "bob draft" }),
  ]) {
    await store(bobConn, ev);
    stored[bob.pub].add(ev.id);
  }

  const other = await publish(aliceConn, sign(bob, { content: "bob, sent by alice" }));
  expect(
    other[2] === false && other[3].startsWith("restricted:"),
    "an event from someone else than the authenticated pubkey must be restricted",
  );

  pass("testWritesNeedTheirAuthor");
}

async function testReadsOnlyReturnOwnEvents({ aliceConn }) {
  const all = await query(aliceConn, "all", {});
  expect(
    sameIds(all.events, stored[alice.pub]),
    `REQ {} must return exactly alice's events, got ${all.events.length}`,
  );

  const bobs = await query(aliceConn, "bobs", { authors: [bob.pub] });
  expect(
    bobs.closed?.startsWith("restricted:"),
    `asking for another author must be CLOSED with restricted:, got: ${bobs.closed}`,
  );

  const bobNoteId = [...stored[bob.pub]][0];
  const byId = await query(aliceConn, "by-id", { ids: [bobNoteId] });
  expect(byId.events.length === 0 && !byId.closed, "another user's event must not be served by id");

  const mixed = await query(aliceConn, "mixed", { authors: [alice.pub, bob.pub], kinds: [31234] });
  expect(
    mixed.events.length === 2 && mixed.events.every((ev) => ev.pubkey === alice.pub),
    "authors must be narrowed down to the authenticated pubkey",
  );

  aliceConn.send(["COUNT", "count", {}]);
  const count = await aliceConn.waitFor((m) => m[1] === "count");
  expect(
    count[0] === "COUNT" && count[2].count === stored[alice.pub].size,
    `COUNT {} must only count alice's events, got ${JSON.stringify(count)}`,
  );

  pass("testReadsOnlyReturnOwnEvents");
}

async function testSeveralPubkeysPerConnection() {
  const client = await connect();
  expect((await authAs(client, alice))[2] === true, "first AUTH should succeed");
  expect((await authAs(client, bob))[2] === true, "second AUTH as another pubkey should succeed");

  const both = await query(client, "both", {});
  expect(
    sameIds(both.events, new Set([...stored[alice.pub], ...stored[bob.pub]])),
    "a connection authenticated as two pubkeys must see the events of both",
  );

  const third = await authAs(client, carol);
  expect(
    third[2] === false && third[3].startsWith("restricted:"),
    "AUTH beyond maxPubkeysPerConnection must be restricted",
  );

  await client.close();
  pass("testSeveralPubkeysPerConnection");
}

async function testLiveEventsStayPrivate({ aliceConn, bobConn }) {
  aliceConn.send(["REQ", "live", { kinds: [1] }]);
  await aliceConn.waitFor((m) => m[0] === "EOSE" && m[1] === "live");

  const bobLive = await store(bobConn, sign(bob, { content: "bob live" }));
  stored[bob.pub].add(bobLive.id);
  const aliceLive = await store(aliceConn, sign(alice, { content: "alice live" }));
  stored[alice.pub].add(aliceLive.id);

  const msgs = await aliceConn.collectUntil(
    (m) => m[0] === "EVENT" && m[1] === "live" && m[2].id === aliceLive.id,
  );
  expect(
    !msgs.some((m) => m[0] === "EVENT" && m[2].pubkey === bob.pub),
    "a live subscription must not receive other users' events",
  );
  aliceConn.send(["CLOSE", "live"]);

  pass("testLiveEventsStayPrivate");
}

async function testGiftWrapsBelongToTheirRecipient({ aliceConn, bobConn }) {
  const wrap = sign(newUser(), {
    kind: 1059,
    tags: [["p", alice.pub]],
    content: "sealed",
    created_at: now() - 3600,
  });

  const fromBob = await publish(bobConn, wrap);
  expect(fromBob[2] === false, "only the recipient may store a gift wrap");
  await store(aliceConn, wrap);

  const signedByBob = sign(bob, { kind: 1059, tags: [["p", alice.pub]], content: "sealed" });
  const fromSigner = await publish(bobConn, signedByBob);
  expect(
    fromSigner[2] === false && fromSigner[3].startsWith("restricted:"),
    "the signer of a gift wrap must not store it for its recipient",
  );

  const toBoth = sign(newUser(), { kind: 1059, tags: [["p", bob.pub], ["p", alice.pub]], content: "sealed" });
  for (const conn of [bobConn, aliceConn]) {
    const ok = await publish(conn, toBoth);
    expect(
      ok[2] === false && ok[3].startsWith("restricted:"),
      "a gift wrap with several p tags has no owner and must be refused",
    );
  }

  const forAlice = await query(aliceConn, "wraps", { kinds: [1059], "#p": [alice.pub] });
  expect(sameIds(forAlice.events, new Set([wrap.id])), "the recipient must get their gift wrap");

  const all = await query(aliceConn, "all-with-wrap", {});
  expect(all.events.some((ev) => ev.id === wrap.id), "REQ {} must include gift wraps addressed to the user");

  const forBob = await query(bobConn, "wraps", { kinds: [1059] });
  expect(forBob.events.length === 0, "gift wraps must not be served to anyone else");

  // NIP-59: the recipient deletes the wrap by its id, even though they didn't sign it
  const deletion = await store(aliceConn, sign(alice, { kind: 5, tags: [["e", wrap.id]] }));
  stored[alice.pub].add(deletion.id);

  const afterDelete = await query(aliceConn, "wraps-deleted", { kinds: [1059] });
  expect(afterDelete.events.length === 0, "the recipient must be able to delete their gift wrap");

  const again = await publish(aliceConn, wrap);
  expect(again[2] === false && again[3].startsWith("deleted:"), "a deleted gift wrap can't be stored again");

  pass("testGiftWrapsBelongToTheirRecipient");
  return wrap;
}

async function testSignerCantTouchAGiftWrap({ aliceConn }) {
  // A sender who kept the throwaway key can AUTH as it
  const signer = newUser();
  const signerConn = await connect();
  expect((await authAs(signerConn, signer))[2] === true, "the signer of a gift wrap should AUTH");

  const wrap = sign(signer, { kind: 1059, tags: [["p", alice.pub]], content: "sealed", created_at: now() - 3600 });
  const storedAfterVanish = sign(signer, { kind: 1059, tags: [["p", alice.pub]], content: "sealed", created_at: now() - 7200 });

  await store(signerConn, sign(signer, { kind: 5, tags: [["e", wrap.id]], content: "before" }));
  await store(aliceConn, wrap);
  stored[alice.pub].add(wrap.id);

  await store(signerConn, sign(signer, { kind: 5, tags: [["e", wrap.id]], content: "after" }));

  signerConn.send(["COUNT", "signer-count", { authors: [signer.pub], kinds: [1059] }]);
  const count = await signerConn.waitFor((m) => m[1] === "signer-count");
  expect(
    count[0] === "COUNT" && count[2].count === 0,
    `the signer must not count a gift wrap, got ${JSON.stringify(count)}`,
  );

  await store(signerConn, sign(signer, { kind: 62, tags: [["relay", serviceUrl]] }));
  await store(aliceConn, storedAfterVanish);
  stored[alice.pub].add(storedAfterVanish.id);

  const kept = await query(aliceConn, "signer-wraps", { kinds: [1059] });
  expect(
    sameIds(kept.events, new Set([wrap.id, storedAfterVanish.id])),
    "the signer's deletions and request to vanish must not touch the recipient's gift wraps",
  );

  await signerConn.close();
  pass("testSignerCantTouchAGiftWrap");
}

async function syncWithNegentropy(client, subId, filter) {
  const storage = new NegentropyStorageVector();
  storage.seal();
  const ne = new Negentropy(storage, 0);

  let msg = await ne.initiate();
  client.send(["NEG-OPEN", subId, filter, msg]);

  const need = new Set();
  while (true) {
    const resp = await client.waitFor((m) => m[1] === subId && (m[0] === "NEG-MSG" || m[0] === "NEG-ERR"));
    if (resp[0] === "NEG-ERR") return { error: resp[2] };

    const [next, , needIds] = await ne.reconcile(resp[2]);
    needIds.forEach((id) => need.add(id));
    if (next === null) break;
    client.send(["NEG-MSG", subId, next]);
  }

  client.send(["NEG-CLOSE", subId]);
  return { need };
}

async function testNegentropyOnlySyncsOwnEvents({ aliceConn }) {
  const { need, error } = await syncWithNegentropy(aliceConn, "neg-all", {});
  expect(!error, `negentropy should work once authenticated, got: ${error}`);
  expect(
    need.size === stored[alice.pub].size && [...stored[alice.pub]].every((id) => need.has(id)),
    `negentropy must offer exactly alice's events, got ${need.size}`,
  );

  const bobs = await syncWithNegentropy(aliceConn, "neg-bob", { authors: [bob.pub] });
  expect(bobs.error?.startsWith("restricted:"), "negentropy on another author must be restricted");

  pass("testNegentropyOnlySyncsOwnEvents");
}

async function testRequestToVanish({ aliceConn, bobConn }, deletedWrap) {
  const anonymous = await connect();

  const elsewhere = await publish(
    anonymous,
    sign(alice, { kind: 62, tags: [["relay", "wss://elsewhere.example"]] }),
  );
  expect(
    elsewhere[2] === false && elsewhere[3].startsWith("auth-required:"),
    "a request to vanish from another relay is a normal event and needs AUTH",
  );

  const wrap = await store(
    aliceConn,
    sign(newUser(), { kind: 1059, tags: [["p", alice.pub]], content: "dm", created_at: now() - 60 }),
  );
  const old = await store(aliceConn, sign(alice, { content: "before vanishing", created_at: now() - 10 }));

  const vanish = sign(alice, { kind: 62, tags: [["relay", serviceUrl]], content: "bye" });
  await store(anonymous, vanish);
  await anonymous.close();

  const left = await query(aliceConn, "after-vanish", {});
  expect(
    sameIds(left.events, new Set([vanish.id])),
    `only the request to vanish itself must be left, got ${left.events.length} events`,
  );

  for (const ev of [old, wrap, deletedWrap]) {
    const again = await publish(aliceConn, ev);
    expect(again[2] === false && again[3].startsWith("deleted:"), "vanished events can't be published again");
  }

  await store(aliceConn, sign(alice, { kind: 5, tags: [["e", vanish.id]], created_at: vanish.created_at + 1 }));
  const kept = await query(aliceConn, "vanish-kept", { kinds: [62] });
  expect(sameIds(kept.events, new Set([vanish.id])), "a deletion request has no effect on a request to vanish");

  await store(aliceConn, sign(alice, { content: "back again", created_at: vanish.created_at + 1 }));

  const bobs = await query(bobConn, "bob-untouched", {});
  expect(sameIds(bobs.events, stored[bob.pub]), "other users' events must survive a request to vanish");

  pass("testRequestToVanish");
}

async function testRelayInformation() {
  const res = await fetch(wsUrl.replace("ws://", "http://"), {
    headers: { Accept: "application/nostr+json" },
  });
  const info = await res.json();

  for (const nip of [37, 42, 62, 77]) {
    expect(info.supported_nips.includes(nip), `NIP-11 must list NIP-${nip}`);
  }
  expect(info.limitation.auth_required === true, "NIP-11 must say auth is required");
  expect(info.limitation.restricted_writes === true, "NIP-11 must say writes are restricted");

  pass("testRelayInformation");
}

async function main() {
  console.log("* private storage (NIP-37) relay integration tests");

  writeConfig(
    config(dbDir, port, true, { privateStorage: true, maxPubkeysPerConnection: 2 }),
    cfgPath,
  );

  await runRelaySuite({
    relayConfigPath: cfgPath,
    relayPort: port,
    relayDbPath: dbDir,
    tests: async (ctx) => {
      wsUrl = ctx.wsUrl;

      await testRelayInformation();
      await testEverythingNeedsAuth();

      const conns = { aliceConn: await connect(), bobConn: await connect() };
      try {
        await testWritesNeedTheirAuthor(conns);
        await testReadsOnlyReturnOwnEvents(conns);
        await testSeveralPubkeysPerConnection();
        await testLiveEventsStayPrivate(conns);
        const deletedWrap = await testGiftWrapsBelongToTheirRecipient(conns);
        await testSignerCantTouchAGiftWrap(conns);
        await testNegentropyOnlySyncsOwnEvents(conns);
        await testRequestToVanish(conns, deletedWrap);
      } finally {
        await conns.aliceConn.close();
        await conns.bobConn.close();
      }
    },
  });

  console.log("All private storage tests passed!");
}

main().catch((err) => {
  console.error(err && err.stack ? err.stack : String(err));
  process.exit(1);
});
