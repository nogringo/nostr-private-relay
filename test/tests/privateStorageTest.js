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

// NIP-37: what each pubkey uploaded, which is all it can read back
const stored = new Map([alice, bob, carol].map((user) => [user.pub, new Map()]));
const keep = (user, ...evs) => evs.forEach((ev) => stored.get(user.pub).set(ev.id, ev));
const drop = (user, ...evs) => evs.forEach((ev) => stored.get(user.pub).delete(ev.id));
const idsOf = (user) => new Set(stored.get(user.pub).keys());
const signedBy = (user, author) => [...stored.get(user.pub).values()].filter((ev) => ev.pubkey === author.pub);

function sign(user, { kind = 1, tags = [], content = "", created_at = now() } = {}) {
  return finalizeEvent({ kind, tags, content, created_at }, user.sk);
}

function writeRelayConfig() {
  writeConfig(config(dbDir, port, { maxPubkeysPerConnection: 2 }), cfgPath);
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

async function testUploadsAreKeptForTheirUploader({ aliceConn, bobConn }) {
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
    keep(alice, await store(aliceConn, ev));
  }

  const bobNote = sign(bob, { content: "bob note" });
  for (const ev of [bobNote, sign(bob, { kind: 31234, tags: [["d", "bob-draft"], ["k", "1"]], content: "bob draft" })]) {
    keep(bob, await store(bobConn, ev));
  }

  const kept = sign(bob, { content: "bob, kept by alice" });
  const first = await publish(aliceConn, kept);
  expect(first[2] === true && first[3] === "", `alice must be able to store bob's event for herself, got: ${first[3]}`);
  keep(alice, kept);

  const again = await publish(aliceConn, kept);
  expect(again[2] === true && again[3].startsWith("duplicate:"), "storing the same event twice is a duplicate");

  const copy = await publish(aliceConn, bobNote);
  expect(
    copy[2] === true && copy[3] === "",
    `an event another user stored must be new to alice, without telling her it exists, got: ${copy[3]}`,
  );
  keep(alice, bobNote);

  const protectedEv = await publish(aliceConn, sign(bob, { content: "protected", tags: [["-"]] }));
  expect(
    protectedEv[2] === false && protectedEv[3].startsWith("restricted:"),
    "a NIP-70 protected event can only be stored by its author",
  );

  pass("testUploadsAreKeptForTheirUploader");
}

async function testReadsOnlyReturnOwnUploads({ aliceConn, bobConn }) {
  const all = await query(aliceConn, "all", {});
  expect(sameIds(all.events, idsOf(alice)), `REQ {} must return exactly what alice stored, got ${all.events.length}`);

  const bobs = await query(aliceConn, "bobs", { authors: [bob.pub] });
  expect(
    !bobs.closed && sameIds(bobs.events, new Set(signedBy(alice, bob).map((ev) => ev.id))),
    `asking for another author must return the copies alice stored, got: ${bobs.closed ?? bobs.events.length}`,
  );

  const bobDraft = signedBy(bob, bob).find((ev) => ev.kind === 31234);
  const byId = await query(aliceConn, "by-id", { ids: [bobDraft.id] });
  expect(byId.events.length === 0 && !byId.closed, "an event alice didn't store must not be served to her, even by id");

  const mixed = await query(aliceConn, "mixed", { authors: [alice.pub, bob.pub], kinds: [31234] });
  expect(
    mixed.events.length === 2 && mixed.events.every((ev) => ev.pubkey === alice.pub),
    "a filter on several authors must only match what alice stored",
  );

  const forBob = await query(bobConn, "bob-all", {});
  expect(sameIds(forBob.events, idsOf(bob)), "bob must not get what alice stored, even the events he signed");

  aliceConn.send(["COUNT", "count", {}]);
  const count = await aliceConn.waitFor((m) => m[1] === "count");
  expect(
    count[0] === "COUNT" && count[2].count === idsOf(alice).size,
    `COUNT {} must only count what alice stored, got ${JSON.stringify(count)}`,
  );

  pass("testReadsOnlyReturnOwnUploads");
}

async function testSeveralPubkeysPerConnection({ aliceConn, bobConn }) {
  const client = await connect();
  expect((await authAs(client, alice))[2] === true, "first AUTH should succeed");
  expect((await authAs(client, bob))[2] === true, "second AUTH as another pubkey should succeed");

  const both = await query(client, "both", {});
  expect(
    sameIds(both.events, new Set([...idsOf(alice), ...idsOf(bob)])),
    "a connection authenticated as two pubkeys must see what both stored",
  );

  // The event's owner stores it when the connection authenticated as them, else the first pubkey
  const bobsOwn = await store(client, sign(bob, { content: "bob, from a shared connection" }));
  keep(bob, bobsOwn);
  const carols = await store(client, sign(carol, { content: "carol, from a shared connection" }));
  keep(alice, carols);

  const forBob = await query(bobConn, "shared-bob", { ids: [bobsOwn.id, carols.id] });
  const forAlice = await query(aliceConn, "shared-alice", { ids: [bobsOwn.id, carols.id] });
  expect(sameIds(forBob.events, new Set([bobsOwn.id])), "bob's event must be stored for bob");
  expect(sameIds(forAlice.events, new Set([carols.id])), "someone else's event must be stored for the first pubkey");

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
  keep(bob, bobLive);
  const aliceLive = await store(aliceConn, sign(alice, { content: "alice live" }));
  keep(alice, aliceLive);

  const msgs = await aliceConn.collectUntil(
    (m) => m[0] === "EVENT" && m[1] === "live" && m[2].id === aliceLive.id,
  );
  expect(
    !msgs.some((m) => m[0] === "EVENT" && m[2].pubkey === bob.pub),
    "a live subscription must not receive what other users store",
  );

  keep(alice, await store(aliceConn, bobLive));
  await aliceConn.waitFor((m) => m[0] === "EVENT" && m[1] === "live" && m[2].id === bobLive.id);
  aliceConn.send(["CLOSE", "live"]);

  pass("testLiveEventsStayPrivate");
}

async function testGiftWraps({ aliceConn, bobConn }) {
  const wrap = sign(newUser(), {
    kind: 1059,
    tags: [["p", alice.pub]],
    content: "sealed",
    created_at: now() - 3600,
  });

  // A sender can keep a copy of the wrap they sent
  keep(bob, await store(bobConn, wrap));
  keep(alice, await store(aliceConn, wrap));

  const signedByBob = sign(bob, { kind: 1059, tags: [["p", alice.pub]], content: "sealed" });
  keep(bob, await store(bobConn, signedByBob));

  const toBoth = sign(newUser(), { kind: 1059, tags: [["p", bob.pub], ["p", alice.pub]], content: "sealed" });
  for (const conn of [bobConn, aliceConn]) {
    const ok = await publish(conn, toBoth);
    expect(ok[2] === false && ok[3].startsWith("invalid:"), `a gift wrap must have a single p tag, got: ${ok[3]}`);
  }

  const forAlice = await query(aliceConn, "wraps", { kinds: [1059], "#p": [alice.pub] });
  expect(sameIds(forAlice.events, new Set([wrap.id])), "the recipient must get the gift wrap she stored, and only it");

  const all = await query(aliceConn, "all-with-wrap", {});
  expect(all.events.some((ev) => ev.id === wrap.id), "REQ {} must include the gift wraps the user stored");

  const forBob = await query(bobConn, "wraps", { kinds: [1059] });
  expect(sameIds(forBob.events, new Set([wrap.id, signedByBob.id])), "the sender must get the copies he stored");

  // NIP-59: the recipient deletes the wrap by its id, even though they didn't sign it
  const deletion = await store(aliceConn, sign(alice, { kind: 5, tags: [["e", wrap.id]] }));
  keep(alice, deletion);
  drop(alice, wrap);

  const afterDelete = await query(aliceConn, "wraps-deleted", { kinds: [1059] });
  expect(afterDelete.events.length === 0, "the recipient must be able to delete her gift wrap");

  const again = await publish(aliceConn, wrap);
  expect(again[2] === false && again[3].startsWith("deleted:"), "a deleted gift wrap can't be stored again");

  const bobsCopy = await query(bobConn, "wraps-kept", { ids: [wrap.id] });
  expect(bobsCopy.events.length === 1, "a deletion only removes the copy of the pubkey that stored it");

  pass("testGiftWraps");
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
  keep(alice, await store(aliceConn, wrap));

  await store(signerConn, sign(signer, { kind: 5, tags: [["e", wrap.id]], content: "after" }));

  signerConn.send(["COUNT", "signer-count", { authors: [signer.pub], kinds: [1059] }]);
  const count = await signerConn.waitFor((m) => m[1] === "signer-count");
  expect(
    count[0] === "COUNT" && count[2].count === 0,
    `the signer must not count a gift wrap it didn't store, got ${JSON.stringify(count)}`,
  );

  await store(signerConn, sign(signer, { kind: 62, tags: [["relay", serviceUrl]] }));
  keep(alice, await store(aliceConn, storedAfterVanish));

  const kept = await query(aliceConn, "signer-wraps", { kinds: [1059] });
  expect(
    sameIds(kept.events, new Set([wrap.id, storedAfterVanish.id])),
    "the signer's deletions and request to vanish must not touch the recipient's gift wraps",
  );

  await signerConn.close();
  pass("testSignerCantTouchAGiftWrap");
}

async function testCopiesAreDeletedOnTheirOwn({ aliceConn, bobConn }) {
  const carolConn = await connect();
  expect((await authAs(carolConn, carol))[2] === true, "carol should AUTH");

  const note = sign(alice, { content: "copied note", created_at: now() - 30 });
  keep(alice, await store(aliceConn, note));
  keep(bob, await store(bobConn, note));

  const deletion = sign(alice, { kind: 5, tags: [["e", note.id]] });
  keep(alice, await store(aliceConn, deletion));
  drop(alice, note);

  expect((await query(aliceConn, "deleted-note", { ids: [note.id] })).events.length === 0, "alice's deletion must delete her copy");
  expect((await query(bobConn, "kept-note", { ids: [note.id] })).events.length === 1, "alice's deletion must not touch bob's copy");

  const again = await publish(aliceConn, note);
  expect(again[2] === false && again[3].startsWith("deleted:"), "alice can't store the note she deleted again");

  // A pubkey can delete its own copy of someone else's event
  keep(bob, await store(bobConn, sign(bob, { kind: 5, tags: [["e", note.id]] })));
  drop(bob, note);
  expect((await query(bobConn, "bob-deleted", { ids: [note.id] })).events.length === 0, "bob must be able to delete his copy");

  const bobAgain = await publish(bobConn, note);
  expect(bobAgain[2] === false && bobAgain[3].startsWith("deleted:"), "bob can't store the copy he deleted again");

  // Nobody stores the note anymore, yet carol never deleted it
  await store(carolConn, note);
  expect((await query(carolConn, "carol-note", { ids: [note.id] })).events.length === 1, "carol must still be able to store the note");

  // NIP-09: the author's deletion applies to the storage of whoever stores it
  await store(carolConn, deletion);
  expect((await query(carolConn, "carol-deleted", { ids: [note.id] })).events.length === 0, "a copy of the author's deletion must delete carol's copy");

  await carolConn.close();
  pass("testCopiesAreDeletedOnTheirOwn");
}

async function testReplaceableCopies({ aliceConn, bobConn }) {
  const carolConn = await connect();
  expect((await authAs(carolConn, carol))[2] === true, "carol should AUTH");

  const profile = (name, created_at) => sign(alice, { kind: 0, content: JSON.stringify({ name }), created_at });
  const v1 = profile("v1", now() - 20);
  const v2 = profile("v2", now() - 10);
  const profiles = (conn, subId) => query(conn, subId, { kinds: [0], authors: [alice.pub] });

  keep(alice, await store(aliceConn, v1));
  keep(bob, await store(bobConn, v1));
  keep(alice, await store(aliceConn, v2));
  drop(alice, v1);

  expect(sameIds((await profiles(aliceConn, "alice-profile")).events, new Set([v2.id])), "alice's newer profile must replace hers");
  expect(sameIds((await profiles(bobConn, "bob-profile")).events, new Set([v1.id])), "alice's newer profile must not replace bob's copy");

  keep(bob, await store(bobConn, v2));
  drop(bob, v1);
  expect(sameIds((await profiles(bobConn, "bob-newer")).events, new Set([v2.id])), "bob's newer copy must replace his older one");

  const older = await publish(carolConn, v1);
  expect(older[2] === true, `carol must be able to store an older version that only others replaced, got: ${older[3]}`);
  await store(carolConn, v2);
  const replaced = await publish(carolConn, v1);
  expect(replaced[2] === false && replaced[3].startsWith("replaced:"), "carol can't store an older version than hers");

  await carolConn.close();
  pass("testReplaceableCopies");
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

async function testNegentropyOnlySyncsOwnUploads({ aliceConn }) {
  const { need, error } = await syncWithNegentropy(aliceConn, "neg-all", {});
  expect(!error, `negentropy should work once authenticated, got: ${error}`);
  expect(sameIds([...need].map((id) => ({ id })), idsOf(alice)), `negentropy must offer exactly what alice stored, got ${need.size}`);

  const bobs = await syncWithNegentropy(aliceConn, "neg-bob", { authors: [bob.pub] });
  expect(!bobs.error, `negentropy on another author should work, got: ${bobs.error}`);
  expect(
    sameIds([...bobs.need].map((id) => ({ id })), new Set(signedBy(alice, bob).map((ev) => ev.id))),
    "negentropy on another author must only offer the copies alice stored",
  );

  pass("testNegentropyOnlySyncsOwnUploads");
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

  const bobs = await query(bobConn, "bob-untouched", {});
  expect(
    sameIds(bobs.events, idsOf(bob)),
    "a request to vanish must not touch what other users stored, even alice's events and her gift wraps",
  );

  for (const ev of [old, wrap, deletedWrap]) {
    const again = await publish(aliceConn, ev);
    expect(again[2] === false && again[3].startsWith("deleted:"), "vanished events can't be stored again in alice's storage");
  }

  const bobCopy = await publish(bobConn, old);
  expect(bobCopy[2] === true, `bob must still be able to store a copy of alice's old event, got: ${bobCopy[3]}`);
  keep(bob, old);

  await store(aliceConn, sign(alice, { kind: 5, tags: [["e", vanish.id]], created_at: vanish.created_at + 1 }));
  const kept = await query(aliceConn, "vanish-kept", { kinds: [62] });
  expect(sameIds(kept.events, new Set([vanish.id])), "a deletion request has no effect on a request to vanish");

  await store(aliceConn, sign(alice, { content: "back again", created_at: vanish.created_at + 1 }));

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

  writeRelayConfig();

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
        await testUploadsAreKeptForTheirUploader(conns);
        await testReadsOnlyReturnOwnUploads(conns);
        await testSeveralPubkeysPerConnection(conns);
        await testLiveEventsStayPrivate(conns);
        const deletedWrap = await testGiftWraps(conns);
        await testSignerCantTouchAGiftWrap(conns);
        await testCopiesAreDeletedOnTheirOwn(conns);
        await testReplaceableCopies(conns);
        await testNegentropyOnlySyncsOwnUploads(conns);
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
