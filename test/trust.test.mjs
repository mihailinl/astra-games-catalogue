// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The games keys come from the root-signed trust.json's `kind_keys` (minice
// docs/architecture/2026-11-01-content-catalogue.md §5): a games document
// verifies only under the two games kind keys — never another kind's key,
// never an index key — and rotating to `next` is setting one secret, with no
// other change anywhere.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { privateKeyFromSeed, signEnvelope } from "../lib/vendor/astra-registry/bot/lib/sign.mjs";
import { INDEX_SCHEMA, signatureCheck, verifyDocuments, WITHDRAWN_SCHEMA } from "../lib/documents.mjs";
import { selectSigner, selectSigners, signBoth, spentBySchema } from "../lib/signing.mjs";
import { emptyModeration, loadState, writeJson } from "../lib/state.mjs";
import { loadTrust } from "../lib/trust.mjs";
import { candidate, kindKeyRow, makeCatalogue, makeTrust, rootsOf, T0 } from "./catalogue.mjs";
import { throwawayKey } from "./helpers.mjs";

/** Re-sign a games document's body with an arbitrary key, as a forger holding that key would. */
function resignWith(envelope, domain, key, keyId) {
  return signEnvelope({ domain, signed: envelope.signed, signers: [{ key_id: keyId, privateKey: privateKeyFromSeed(Buffer.from(key.seedB64, "base64")) }] });
}

const bothUnder = (kindKeys, index, withdrawn) =>
  verifyDocuments([{ envelope: index, domain: INDEX_SCHEMA }, { envelope: withdrawn, domain: WITHDRAWN_SCHEMA, indexBody: index.signed }], { kindKeys, now: T0 });
const both = (c, index, withdrawn) => bothUnder(c.kindKeys, index, withdrawn);

test("a games document signed by ANOTHER KIND's key is refused, though trust.json authorises that key", () => {
  const c = makeCatalogue();
  c.sign({ candidates: [candidate()] });
  for (const [key, id] of [[c.commandsCurrent, "astra-commands-2026a"], [c.commandsNext, "astra-commands-2026b"]]) {
    const index = resignWith(c.dist("games-index.json"), INDEX_SCHEMA, key, id);
    const withdrawn = resignWith(c.dist("games-withdrawn.json"), WITHDRAWN_SCHEMA, key, id);
    const [pi, pw] = both(c, index, withdrawn);
    assert.ok(pi.some((p) => p.startsWith("signature")), `index under ${id}: ${pi}`);
    assert.ok(pw.some((p) => p.startsWith("signature")), `withdrawn under ${id}: ${pw}`);
  }
  // even when the forger claims a games key id
  const lying = resignWith(c.dist("games-index.json"), INDEX_SCHEMA, c.commandsCurrent, "astra-games-2026a");
  assert.ok(both(c, lying, c.dist("games-withdrawn.json"))[0].some((p) => p.startsWith("signature")));
});

test("a games document signed by the plugin INDEX key is refused", () => {
  const c = makeCatalogue();
  c.sign({ candidates: [candidate()] });
  const index = resignWith(c.dist("games-index.json"), INDEX_SCHEMA, c.indexKey, "astra-index-2026a");
  const withdrawn = resignWith(c.dist("games-withdrawn.json"), WITHDRAWN_SCHEMA, c.indexKey, "astra-index-2026a");
  const [pi, pw] = both(c, index, withdrawn);
  assert.ok(pi.some((p) => p.startsWith("signature")));
  assert.ok(pw.some((p) => p.startsWith("signature")));
});

test("the signer refuses another kind's key and the index key in the games secret", () => {
  const c = makeCatalogue();
  for (const k of [c.commandsCurrent, c.indexKey]) {
    assert.throws(() => c.sign({ env: { GAMES_SIGNING_KEY_CURRENT: k.seedB64 } }), /E_KEY_NOT_AUTHORISED/);
  }
  assert.throws(() => c.sign({ env: { GAMES_SIGNING_KEY_CURRENT: c.current.seedB64, GAMES_SIGNING_KEY_NEXT: c.current.seedB64 } }), /E_KEY_NOT_AUTHORISED/, "the current key is not the next key");
});

test("rotation: setting GAMES_SIGNING_KEY_NEXT is the whole change; next signs first, current co-signs, and the same trust.json verifies both sides", () => {
  const c = makeCatalogue();
  c.sign({ candidates: [candidate()] });
  const before = c.dist("games-index.json");
  const trustBefore = fs.readFileSync(c.trustFile, "utf8");

  c.sign({ env: { ...c.env, GAMES_SIGNING_KEY_NEXT: c.next.seedB64 } });
  const index = c.dist("games-index.json");
  const withdrawn = c.dist("games-withdrawn.json");
  assert.equal(fs.readFileSync(c.trustFile, "utf8"), trustBefore, "trust.json did not change");
  assert.deepEqual(index.signatures.map((s) => s.key_id), ["astra-games-2026b", "astra-games-2026a"], "next is the primary; current co-signs (the ceremony bridge, always on)");
  assert.equal(index.signed.key_id, "games-current", "a key holding trust's current role signed, so the body names current");
  assert.ok(index.signed.serial > before.signed.serial, "the per-kind floor carries across the rotation");
  assert.deepEqual(both(c, index, withdrawn), [[], []]);
  assert.deepEqual(index.signed.entries, before.signed.entries, "the content did not change");
  // the old document still verifies too: clients accept both keys
  assert.deepEqual(both(c, before, JSON.parse(JSON.stringify(withdrawn)))[0], []);
  // and the rotated-away key is spent, for each schema this run signed with
  // next: the signer never slides back to it
  assert.deepEqual(c.state("floors.json").spent, { [INDEX_SCHEMA]: [spentA(c)], [WITHDRAWN_SCHEMA]: [spentA(c)] }, "the ledger records the public key beside the id");
  assert.throws(() => c.sign({ env: { GAMES_SIGNING_KEY_CURRENT: c.current.seedB64 } }), /E_KEY_RETIRED/);
});

// ── spent is per DOCUMENT SCHEMA, not per kind (minice design §11a.9) ──────

const SPENT_A = "astra-games-2026a";
/** The ledger entry that records A as spent, as signing.mjs writes it since 2026-11-07. */
const spentA = (c) => ({ key_id: SPENT_A, public_key: c.current.publicB64 });

function perSchema(c) {
  const currentEnv = { GAMES_SIGNING_KEY_CURRENT: c.current.seedB64 };
  // next ALONE: with current's seed beside it, current co-signs and the body says games-current (the bridge)
  const nextEnv = { GAMES_SIGNING_KEY_NEXT: c.next.seedB64 };
  const pick = (env, schema, floors) => selectSigner({ env, floors, kindKeys: c.kindKeys, now: T0, schema });
  const signWith = (state, indexEnv, withdrawnEnv) =>
    signBoth({ state, seedLoaders: { loaders: [] }, previous: null, kindKeys: c.kindKeys, now: T0,
      signers: { [INDEX_SCHEMA]: pick(indexEnv, INDEX_SCHEMA, state.floors), [WITHDRAWN_SCHEMA]: pick(withdrawnEnv, WITHDRAWN_SCHEMA, state.floors) } });
  return { currentEnv, nextEnv, pick, signWith };
}

test("spent is per schema: an index signed by next, then a withdrawn list signed by current, is accepted", () => {
  const c = makeCatalogue();
  c.sign({ candidates: [candidate()] });
  const { currentEnv, nextEnv, pick, signWith } = perSchema(c);
  const state = loadState(c.data);

  const first = signWith(state, nextEnv, currentEnv);
  assert.equal(first.index.signed.key_id, "games-next");
  assert.equal(first.index.signatures[0].key_id, "astra-games-2026b");
  assert.equal(first.withdrawn.signed.key_id, "games-current");
  assert.equal(first.withdrawn.signatures[0].key_id, SPENT_A);
  assert.deepEqual(both(c, first.index, first.withdrawn), [[], []], "both verify: clients accept both keys");
  assert.deepEqual(first.floors.spent, { [INDEX_SCHEMA]: [spentA(c)], [WITHDRAWN_SCHEMA]: [] }, "next signed only the index, so current is spent only for the index");

  state.floors = first.floors;
  assert.equal(pick(currentEnv, WITHDRAWN_SCHEMA, state.floors).key_id, SPENT_A, "the withdrawn list may still be signed by current");
  assert.equal(signWith(state, nextEnv, currentEnv).withdrawn.signed.key_id, "games-current", "and is, again, while the index stays on next");
  assert.throws(() => pick(currentEnv, INDEX_SCHEMA, state.floors), /E_KEY_RETIRED: astra-games-2026a was rotated away from for astra\.games\.index\/1/, "the index never goes back to current");
  // signBoth checks the ledger itself, whatever floors a signer was picked under
  assert.throws(
    () => signBoth({ state, seedLoaders: { loaders: [] }, previous: null, kindKeys: c.kindKeys, now: T0,
      signers: { [INDEX_SCHEMA]: pick(currentEnv, INDEX_SCHEMA, {}), [WITHDRAWN_SCHEMA]: pick(currentEnv, WITHDRAWN_SCHEMA, {}) } }),
    /E_KEY_RETIRED: astra-games-2026a is spent for astra\.games\.index\/1/,
  );
  assert.throws(
    () => signBoth({ state, seedLoaders: { loaders: [] }, previous: null, kindKeys: c.kindKeys, now: T0,
      signers: { [INDEX_SCHEMA]: pick(nextEnv, WITHDRAWN_SCHEMA, state.floors), [WITHDRAWN_SCHEMA]: pick(currentEnv, WITHDRAWN_SCHEMA, state.floors) } }),
    /E_SCHEMA/, "a signer picked for one schema does not sign the other",
  );

  // the run itself picks one role for both documents: with only current, the index refuses it, and nothing is written
  // (the data as that first signing leaves it: the floors AND the documents they are the floors of)
  writeJson(path.join(c.data, "floors.json"), state.floors);
  writeJson(path.join(c.data, "dist", "games-index.json"), first.index);
  writeJson(path.join(c.data, "dist", "games-withdrawn.json"), first.withdrawn);
  const served = fs.readFileSync(path.join(c.data, "dist", "games-withdrawn.json"), "utf8");
  assert.throws(() => c.sign({ env: currentEnv }), /E_KEY_RETIRED: .* astra\.games\.index\/1/);
  assert.equal(fs.readFileSync(path.join(c.data, "dist", "games-withdrawn.json"), "utf8"), served, "a refused run writes nothing");
  const run = c.sign({ env: nextEnv });
  assert.equal(run.keyId, "astra-games-2026b");
  assert.deepEqual(c.state("floors.json").spent, { [INDEX_SCHEMA]: [spentA(c)], [WITHDRAWN_SCHEMA]: [spentA(c)] });
});

test("spent is per schema: a withdrawn list signed by current after a next-signed withdrawn list is refused", () => {
  const c = makeCatalogue();
  c.sign();
  const { currentEnv, nextEnv, pick, signWith } = perSchema(c);
  const state = loadState(c.data);

  // the withdrawn list moves first this time; the index stays on current
  state.floors = signWith(state, currentEnv, nextEnv).floors;
  assert.deepEqual(state.floors.spent, { [INDEX_SCHEMA]: [], [WITHDRAWN_SCHEMA]: [spentA(c)] });
  assert.throws(() => pick(currentEnv, WITHDRAWN_SCHEMA, state.floors), /E_KEY_RETIRED: astra-games-2026a was rotated away from for astra\.games\.withdrawn\/1/);
  assert.throws(() => signWith(state, currentEnv, currentEnv), /E_KEY_RETIRED/);
  assert.equal(pick(currentEnv, INDEX_SCHEMA, state.floors).key_id, SPENT_A, "the index has not moved, so it may");
  // and the ledger only moves forward: a later current-signed index spends nothing back
  state.floors = signWith(state, currentEnv, nextEnv).floors;
  assert.deepEqual(state.floors.spent, { [INDEX_SCHEMA]: [], [WITHDRAWN_SCHEMA]: [spentA(c)] });
});

test("the per-kind ledger written before 2026-11-02 counts for both schemas; any other shape refuses the run", () => {
  const legacy = spentBySchema({ spent: [SPENT_A] });
  assert.deepEqual(Object.fromEntries(Object.entries(legacy).map(([k, v]) => [k, [...v]])), { [INDEX_SCHEMA]: [SPENT_A], [WITHDRAWN_SCHEMA]: [SPENT_A] },
    "one key signed both documents in every run then, so a key spent then is spent for both");
  const c = makeCatalogue();
  const { currentEnv, pick } = perSchema(c);
  for (const schema of [INDEX_SCHEMA, WITHDRAWN_SCHEMA]) assert.throws(() => pick(currentEnv, schema, { spent: [SPENT_A] }), /E_KEY_RETIRED/);
  for (const spent of ["x", null, 7, [1], [""], {}, { [INDEX_SCHEMA]: [] }, { [INDEX_SCHEMA]: [], [WITHDRAWN_SCHEMA]: "x" },
    { [INDEX_SCHEMA]: [], [WITHDRAWN_SCHEMA]: [], "astra.commands.index/1": [] }]) {
    assert.throws(() => spentBySchema({ spent }), /E_STATE_SPENT/, JSON.stringify(spent));
  }
  assert.throws(() => pick(currentEnv, "astra.commands.index/1", {}), /E_SCHEMA/);
  writeJson(path.join(c.data, "floors.json"), { kind: "games", index: 0, withdrawn: 0, spent: { [INDEX_SCHEMA]: [] } });
  assert.throws(() => c.sign(), /E_STATE_SPENT/);
  assert.equal(fs.existsSync(path.join(c.data, "dist")), false, "a refused run writes nothing");
});

// ── the ceremony bridge (games-index-v1 §3): roles from trust.json ────────
//
// Trust N lists current A and next B; the signer has moved to B. Trust N+1
// lists current B and a fresh next C. With both seeds set, the signer signs
// B first and A beside it under games-current, before and after the ceremony.

const ids = (spent) => Object.fromEntries(Object.entries(spent).map(([k, v]) => [k, [...v]]));
const flip = (e) => ({ ...e, signatures: [...e.signatures].reverse() });
const emptyState = (floors = {}) => ({ entries: [], engineCodes: {}, moderation: emptyModeration(), withdrawn: { rows: [], held: [] }, health: {}, floors });
const seedKey = (k) => privateKeyFromSeed(Buffer.from(k.seedB64, "base64"));

test("a bridged document verifies under trust N and under N+1, in either signature order", () => {
  const c = makeCatalogue({ withNext: true });
  c.sign({ candidates: [candidate()] });
  const index = c.dist("games-index.json");
  const withdrawn = c.dist("games-withdrawn.json");
  for (const d of [index, withdrawn]) {
    assert.deepEqual(d.signatures.map((x) => x.key_id), ["astra-games-2026b", "astra-games-2026a"], "the primary (next) first, the spent current beside it");
    assert.equal(d.signed.key_id, "games-current");
  }
  const kN1 = loadTrust({ doc: c.promotedTrust(throwawayKey()), now: T0, roots: c.roots }).kindKeys;
  for (const [order, i, w] of [["primary first", index, withdrawn], ["co-signer first", flip(index), flip(withdrawn)]]) {
    assert.deepEqual(bothUnder(c.kindKeys, i, w), [[], []], `under N, ${order}`);
    assert.deepEqual(bothUnder(kN1, i, w), [[], []], `under N+1, ${order}`);
  }
  const by = (d, kk) => signatureCheck(d, INDEX_SCHEMA, kk, T0).verifiedBy.map((k) => `${k.key_id}:${k.role}`);
  assert.deepEqual(by(index, c.kindKeys), ["astra-games-2026a:current", "astra-games-2026b:next"], "under N both roles verify");
  assert.deepEqual(by(flip(index), c.kindKeys), ["astra-games-2026a:current", "astra-games-2026b:next"], "whatever the order");
  assert.deepEqual(by(index, kN1), ["astra-games-2026b:current"], "under N+1 A is unlisted and ignored; B verifies as current");

  // the two B-only documents the bridge exists to avoid
  const bOnlyNext = resignWith({ signed: { ...index.signed, key_id: "games-next" } }, INDEX_SCHEMA, c.next, "astra-games-2026b");
  assert.deepEqual(signatureCheck(bOnlyNext, INDEX_SCHEMA, c.kindKeys, T0).problems, [], "B-only games-next is today's routine under N");
  assert.ok(signatureCheck(bOnlyNext, INDEX_SCHEMA, kN1, T0).problems.some((p) => p.includes("names games-next")), "and is refused under N+1");
  const bOnlyCurrent = resignWith(index, INDEX_SCHEMA, c.next, "astra-games-2026b");
  assert.deepEqual(signatureCheck(bOnlyCurrent, INDEX_SCHEMA, kN1, T0).problems, []);
  assert.ok(signatureCheck(bOnlyCurrent, INDEX_SCHEMA, c.kindKeys, T0).problems.some((p) => p.includes("names games-current")), "re-signing with B alone first does not help: N refuses it");
});

test("under N+1 the signer keeps co-signing with the spent A and the body says games-current", () => {
  const c = makeCatalogue({ withNext: true });
  c.sign({ candidates: [candidate()] }); // under N: B signs, A co-signs, A is spent for both schemas
  const fresh = throwawayKey();
  const kN1 = c.useTrust(c.promotedTrust(fresh));
  const run = c.sign(); // the environment is untouched: CURRENT still holds A's seed, NEXT B's
  const index = c.dist("games-index.json");
  const withdrawn = c.dist("games-withdrawn.json");
  for (const d of [index, withdrawn]) {
    assert.deepEqual(d.signatures.map((x) => x.key_id), ["astra-games-2026b", "astra-games-2026a"]);
    assert.equal(d.signed.key_id, "games-current", "B holds current under N+1");
  }
  assert.equal(run.keyId, "astra-games-2026b", "the sign-result's key_id is the primary's (the service bounds it to 64 bytes)");
  assert.deepEqual(run.signedBy, { [INDEX_SCHEMA]: ["astra-games-2026b", "astra-games-2026a"], [WITHDRAWN_SCHEMA]: ["astra-games-2026b", "astra-games-2026a"] });
  assert.deepEqual(run.warnings, [], "A co-signs, so nothing to warn about");
  assert.deepEqual(bothUnder(kN1, index, withdrawn), [[], []], "under N+1");
  assert.deepEqual(bothUnder(c.kindKeys, index, withdrawn), [[], []], "and under N, for the clients that have not taken N+1: A's co-signature is A's");
  assert.deepEqual(c.state("floors.json").spent, { [INDEX_SCHEMA]: [spentA(c)], [WITHDRAWN_SCHEMA]: [spentA(c)] }, "no next signed, so nothing new is spent");
  const sel = selectSigner({ env: c.env, floors: c.state("floors.json"), kindKeys: kN1, now: T0, schema: WITHDRAWN_SCHEMA });
  assert.deepEqual(sel.keys.map((k) => [k.key_id, k.role, k.spent]), [["astra-games-2026b", "current", false], ["astra-games-2026a", null, true]]);

  // the slots are not roles: A in the NEXT slot and B in CURRENT sign the same document
  const swapped = c.sign({ env: { GAMES_SIGNING_KEY_CURRENT: c.next.seedB64, GAMES_SIGNING_KEY_NEXT: c.current.seedB64 } });
  assert.deepEqual(swapped.signedBy[INDEX_SCHEMA], ["astra-games-2026b", "astra-games-2026a"]);

  // the next routine rotation under N+1 has the same shape: C first, B beside it, and B is spent
  c.sign({ env: { GAMES_SIGNING_KEY_CURRENT: c.next.seedB64, GAMES_SIGNING_KEY_NEXT: fresh.seedB64 } });
  assert.deepEqual(c.dist("games-index.json").signatures.map((x) => x.key_id), ["astra-games-2026c", "astra-games-2026b"]);
  assert.equal(c.dist("games-index.json").signed.key_id, "games-current");
  assert.deepEqual(c.state("floors.json").spent[INDEX_SCHEMA], [spentA(c), { key_id: "astra-games-2026b", public_key: c.next.publicB64 }]);
});

test("an unlisted seed that is not recorded as spent is refused", () => {
  const c = makeCatalogue({ withNext: true });
  const kN1 = loadTrust({ doc: c.promotedTrust(throwawayKey()), now: T0, roots: c.roots }).kindKeys;
  const pick = (floors, schema = INDEX_SCHEMA, env = c.env) => selectSigner({ env, floors, kindKeys: kN1, now: T0, schema });
  // the ceremony came before the signer ever moved to B: nothing records A as spent
  assert.throws(() => pick({}), /E_KEY_NOT_AUTHORISED: GAMES_SIGNING_KEY_CURRENT holds a key that is neither a games kind key of trust.json nor recorded in floors.json as spent for astra\.games\.index\/1/);
  // spent for the index only: it may co-sign the index and not the withdrawn list
  const indexOnly = { spent: { [INDEX_SCHEMA]: [spentA(c)], [WITHDRAWN_SCHEMA]: [] } };
  assert.deepEqual(pick(indexOnly).keys.map((k) => k.key_id), ["astra-games-2026b", "astra-games-2026a"]);
  assert.throws(() => pick(indexOnly, WITHDRAWN_SCHEMA), /E_KEY_NOT_AUTHORISED/);
  // a bare key id (a ledger written before 2026-11-07) cannot vouch for a key trust.json no longer names
  assert.throws(() => pick({ spent: { [INDEX_SCHEMA]: [SPENT_A], [WITHDRAWN_SCHEMA]: [SPENT_A] } }), /E_KEY_NOT_AUTHORISED/);
  // a ledger entry names a key by its public key, not by the id a seed would like
  assert.throws(() => pick({ spent: { [INDEX_SCHEMA]: [{ key_id: SPENT_A, public_key: throwawayKey().publicB64 }], [WITHDRAWN_SCHEMA]: [] } }), /E_KEY_NOT_AUTHORISED/);

  // signBoth holds the rule for whatever signer it is handed
  const withA = (schema) => {
    const sel = selectSigner({ env: { GAMES_SIGNING_KEY_NEXT: c.next.seedB64 }, floors: {}, kindKeys: kN1, now: T0, schema });
    return { ...sel, keys: [...sel.keys, { key_id: SPENT_A, role: null, public_key: c.current.publicB64, privateKey: seedKey(c.current), spent: true }] };
  };
  assert.throws(() => signBoth({ state: emptyState(), seedLoaders: { loaders: [] }, previous: null, kindKeys: kN1, now: T0, signers: { [INDEX_SCHEMA]: withA(INDEX_SCHEMA), [WITHDRAWN_SCHEMA]: withA(WITHDRAWN_SCHEMA) } }),
    /E_KEY_NOT_AUTHORISED: astra-games-2026a is neither a games kind key of trust.json nor recorded in floors.json as spent for astra\.games\.index\/1/);
  // a recorded public key with some other private half is not that key
  const spentState = emptyState({ spent: { [INDEX_SCHEMA]: [spentA(c)], [WITHDRAWN_SCHEMA]: [spentA(c)] } });
  const impostor = (schema) => {
    const sel = withA(schema);
    return { ...sel, keys: sel.keys.map((k) => (k.role === null ? { ...k, privateKey: seedKey(throwawayKey()) } : k)) };
  };
  assert.throws(() => signBoth({ state: spentState, seedLoaders: { loaders: [] }, previous: null, kindKeys: kN1, now: T0, signers: { [INDEX_SCHEMA]: impostor(INDEX_SCHEMA), [WITHDRAWN_SCHEMA]: impostor(WITHDRAWN_SCHEMA) } }),
    /E_KEY_NOT_AUTHORISED: the private half handed in for astra-games-2026a is not that key's/);
  assert.equal(signBoth({ state: spentState, seedLoaders: { loaders: [] }, previous: null, kindKeys: kN1, now: T0, signers: { [INDEX_SCHEMA]: withA(INDEX_SCHEMA), [WITHDRAWN_SCHEMA]: withA(WITHDRAWN_SCHEMA) } }).index.signed.key_id,
    "games-current", "recorded as spent, A co-signs");
  // and the run refuses, writing nothing
  c.useTrust(c.promotedTrust(throwawayKey()));
  assert.throws(() => c.sign(), /E_KEY_NOT_AUTHORISED/);
  assert.equal(fs.existsSync(path.join(c.data, "dist")), false);
});

test("a spent key never signs alone", () => {
  const c = makeCatalogue({ withNext: true });
  c.sign(); // B and A: A is spent for both schemas
  const onlyA = { GAMES_SIGNING_KEY_CURRENT: c.current.seedB64 };
  assert.throws(() => c.sign({ env: onlyA }), /E_KEY_RETIRED: astra-games-2026a was rotated away from for astra\.games\.index\/1 .*a spent key never signs alone/);
  assert.throws(() => c.sign({ env: { GAMES_SIGNING_KEY_NEXT: c.current.seedB64 } }), /E_KEY_RETIRED/, "the slot is not a role");

  // signBoth refuses it too, for a signer selected before A was spent
  const state = loadState(c.data);
  const early = selectSigners({ env: onlyA, floors: {}, kindKeys: c.kindKeys, now: T0 });
  assert.throws(() => signBoth({ state, seedLoaders: { loaders: [] }, previous: null, signers: early, kindKeys: c.kindKeys, now: T0 }),
    /E_KEY_RETIRED: astra-games-2026a is spent for astra\.games\.index\/1, and a spent key never signs alone/);

  // after the ceremony A is unlisted, and alone it is still a spent key
  const kN1 = c.useTrust(c.promotedTrust(throwawayKey()));
  assert.throws(() => c.sign({ env: onlyA }), /E_KEY_RETIRED: astra-games-2026a was rotated away from/);
  const lone = (schema) => ({ schema, keys: [{ key_id: SPENT_A, role: null, public_key: c.current.publicB64, privateKey: seedKey(c.current), spent: true }] });
  assert.throws(() => signBoth({ state, seedLoaders: { loaders: [] }, previous: null, signers: { [INDEX_SCHEMA]: lone(INDEX_SCHEMA), [WITHDRAWN_SCHEMA]: lone(WITHDRAWN_SCHEMA) }, kindKeys: kN1, now: T0 }),
    /E_KEY_RETIRED: astra-games-2026a is spent for astra\.games\.index\/1, and a spent key never signs alone/);
});

test("the ledger written before this change still reads, and a malformed one refuses", () => {
  const c = makeCatalogue({ withNext: true });
  // per-schema lists of ids (2026-11-02 to 11-07), and the flat per-kind list before that
  for (const spent of [{ [INDEX_SCHEMA]: [SPENT_A], [WITHDRAWN_SCHEMA]: [SPENT_A] }, [SPENT_A]]) {
    assert.deepEqual(ids(spentBySchema({ spent })), { [INDEX_SCHEMA]: [SPENT_A], [WITHDRAWN_SCHEMA]: [SPENT_A] }, JSON.stringify(spent));
    assert.throws(() => selectSigner({ env: { GAMES_SIGNING_KEY_CURRENT: c.current.seedB64 }, floors: { spent }, kindKeys: c.kindKeys, now: T0, schema: WITHDRAWN_SCHEMA }), /E_KEY_RETIRED/,
      "a bare id still spends the listed key of that id");
  }
  // a run under N reads the old ledger and records A's public key beside its id ...
  writeJson(path.join(c.data, "floors.json"), { kind: "games", index: 0, withdrawn: 0, spent: { [INDEX_SCHEMA]: [SPENT_A], [WITHDRAWN_SCHEMA]: [] } });
  c.sign();
  assert.deepEqual(c.state("floors.json").spent, { [INDEX_SCHEMA]: [spentA(c)], [WITHDRAWN_SCHEMA]: [spentA(c)] });
  // ... so after the ceremony the bridge holds
  c.useTrust(c.promotedTrust(throwawayKey()));
  c.sign();
  assert.deepEqual(c.dist("games-withdrawn.json").signatures.map((x) => x.key_id), ["astra-games-2026b", "astra-games-2026a"]);

  const pub = c.current.publicB64;
  for (const spent of [
    { [INDEX_SCHEMA]: [{ key_id: SPENT_A }], [WITHDRAWN_SCHEMA]: [] },
    { [INDEX_SCHEMA]: [{ key_id: SPENT_A, public_key: "AAAA" }], [WITHDRAWN_SCHEMA]: [] },
    { [INDEX_SCHEMA]: [{ key_id: SPENT_A, public_key: pub.replace(/=+$/, "") }], [WITHDRAWN_SCHEMA]: [] },
    { [INDEX_SCHEMA]: [{ key_id: SPENT_A, public_key: pub, role: "current" }], [WITHDRAWN_SCHEMA]: [] },
    { [INDEX_SCHEMA]: [{ key_id: "Astra Games", public_key: pub }], [WITHDRAWN_SCHEMA]: [] },
    { [INDEX_SCHEMA]: [{ key_id: `${SPENT_A}\nkey_id=x`, public_key: pub }], [WITHDRAWN_SCHEMA]: [] },
    { [INDEX_SCHEMA]: [{ key_id: SPENT_A, public_key: pub }, null], [WITHDRAWN_SCHEMA]: [] },
    { [INDEX_SCHEMA]: [[SPENT_A]], [WITHDRAWN_SCHEMA]: [] },
    [{ key_id: SPENT_A, public_key: pub }],
  ]) {
    assert.throws(() => spentBySchema({ spent }), /E_STATE_SPENT/, JSON.stringify(spent));
  }
  const served = fs.readFileSync(path.join(c.data, "dist", "games-index.json"), "utf8");
  writeJson(path.join(c.data, "floors.json"), { kind: "games", index: 0, withdrawn: 0, spent: { [INDEX_SCHEMA]: [{ key_id: SPENT_A }], [WITHDRAWN_SCHEMA]: [] } });
  assert.throws(() => c.sign(), /E_STATE_SPENT/);
  assert.equal(fs.readFileSync(path.join(c.data, "dist", "games-index.json"), "utf8"), served, "a refused run writes nothing");
});

test("under N+1 with B alone the run signs as before and warns that A no longer co-signs", () => {
  const c = makeCatalogue({ withNext: true });
  const under = c.sign({ env: { GAMES_SIGNING_KEY_NEXT: c.next.seedB64 } });
  assert.deepEqual(under.warnings, [], "under N, A is still listed: B alone is the routine rotation");
  c.sign(); // and the bridge, so A's public key is recorded
  c.useTrust(c.promotedTrust(throwawayKey()));
  const run = c.sign({ env: { GAMES_SIGNING_KEY_NEXT: c.next.seedB64 } });
  assert.deepEqual(c.dist("games-index.json").signatures.map((x) => x.key_id), ["astra-games-2026b"]);
  assert.equal(c.dist("games-index.json").signed.key_id, "games-current");
  for (const schema of [INDEX_SCHEMA, WITHDRAWN_SCHEMA]) {
    assert.ok(run.warnings.includes(`astra-games-2026a no longer co-signs ${schema}: clients still on the trust.json that listed it recover after one forced trust refresh`), JSON.stringify(run.warnings));
  }
  assert.deepEqual(c.sign().warnings, [], "with A back beside B, no warning");
});

test("a floors.json that has lost its spent ledger refuses the run (fail closed)", () => {
  const c = makeCatalogue({ withNext: true });
  c.sign(); // B and A: A is spent for both schemas
  const served = fs.readFileSync(path.join(c.data, "dist", "games-index.json"), "utf8");
  const floorsFile = path.join(c.data, "floors.json");
  const kept = c.state("floors.json");
  for (const [why, floors] of [
    ["serials and no ledger", { kind: "games", index: T0, withdrawn: T0 }],
    ["null", null],
    ["a list", []],
    ["a serial that is not one", { kind: "games", index: "T0", withdrawn: T0, spent: kept.spent }],
  ]) {
    writeJson(floorsFile, floors);
    assert.throws(() => c.sign({ env: { GAMES_SIGNING_KEY_CURRENT: c.current.seedB64 } }), /E_STATE_SPENT/, why);
  }
  fs.rmSync(floorsFile);
  assert.throws(() => c.sign({ env: { GAMES_SIGNING_KEY_CURRENT: c.current.seedB64 } }), /E_STATE_SPENT: dist\/ holds signed documents and floors.json is missing/);
  assert.equal(fs.readFileSync(path.join(c.data, "dist", "games-index.json"), "utf8"), served, "a refused run writes nothing");
  // with the ledger back, A alone is refused for what it is: spent
  writeJson(floorsFile, kept);
  assert.throws(() => c.sign({ env: { GAMES_SIGNING_KEY_CURRENT: c.current.seedB64 } }), /E_KEY_RETIRED/);
  // a catalogue that never signed has no floors, and that is not a refusal
  assert.doesNotThrow(() => makeCatalogue().sign());
  assert.deepEqual(ids(spentBySchema({})), { [INDEX_SCHEMA]: [], [WITHDRAWN_SCHEMA]: [] });
  assert.deepEqual(ids(spentBySchema({ kind: "games", index: 0, withdrawn: 0 })), { [INDEX_SCHEMA]: [], [WITHDRAWN_SCHEMA]: [] });
});

test("a body naming one role signed by the other role's key is refused", () => {
  const c = makeCatalogue();
  c.sign();
  const env = c.dist("games-index.json");
  const forged = resignWith({ signed: { ...env.signed, key_id: "games-next" } }, INDEX_SCHEMA, c.current, "astra-games-2026a");
  assert.ok(both(c, forged, c.dist("games-withdrawn.json"))[0].some((p) => p.includes("names games-next")));
});

// ── trust.json itself ──────────────────────────────────────────────────────

function trustCase(mutate, { rootKey = throwawayKey(), signWith = null, kind = null, expiresAt } = {}) {
  const games = [kindKeyRow("games", "current", "astra-games-2026a", throwawayKey()), kindKeyRow("games", "next", "astra-games-2026b", throwawayKey())];
  const doc = makeTrust({ rootKey: signWith ?? rootKey, kindKeys: games, expiresAt, mutate });
  return () => loadTrust({ doc, now: T0, roots: rootsOf(rootKey), ...(kind ? { kind } : {}) });
}

test("trust.json must verify under the roots, carry kind_keys, and keep a kind key out of index_keys", () => {
  assert.doesNotThrow(trustCase(null));
  assert.throws(trustCase(null, { signWith: throwawayKey() }), /E_TRUST_UNVERIFIED/, "not signed by a root");
  assert.throws(trustCase((s) => delete s.kind_keys), /E_TRUST_NO_KIND_KEYS/);
  assert.throws(trustCase((s) => s.kind_keys.pop()), /E_TRUST_KIND_KEYS/, "only one games key");
  assert.throws(trustCase((s) => s.kind_keys.push(kindKeyRow("games", "next", "astra-games-2026c", throwawayKey()))), /E_TRUST_KIND_KEYS/, "three games keys");
  assert.throws(trustCase((s) => (s.kind_keys[1].role = "current")), /E_TRUST_KIND_KEYS/, "two currents");
  assert.throws(trustCase((s) => (s.kind_keys[0].alg = "rsa")), /E_TRUST_KIND_KEYS/);
  // §5: next must start strictly after current, or the kind has no keys
  assert.throws(trustCase((s) => { const c = s.kind_keys.find((k) => k.role === "current"); const n = s.kind_keys.find((k) => k.role === "next"); n.not_before = c.not_before; }), /E_TRUST_KIND_KEYS/, "next starting with current");
  assert.throws(trustCase((s) => { const c = s.kind_keys.find((k) => k.role === "current"); const n = s.kind_keys.find((k) => k.role === "next"); [c.not_before, n.not_before] = [n.not_before, c.not_before]; }), /E_TRUST_KIND_KEYS/, "next before current");
  assert.throws(trustCase((s) => s.index_keys.push({ key_id: "astra-index-2026b", public_key: s.kind_keys[0].public_key })), /E_TRUST_KIND_KEY_IN_INDEX_KEYS/);
  assert.throws(trustCase((s) => s.kind_keys.push({ ...s.kind_keys[0], kind: "commands", role: "current", key_id: "astra-commands-2026a" }, kindKeyRow("commands", "next", "astra-commands-2026b", throwawayKey()))), /E_TRUST_KIND_KEYS/, "one key for two kinds");
  assert.throws(trustCase(null, { expiresAt: "2026-10-30T00:00:00Z" }), /E_TRUST_EXPIRED/);
  assert.throws(trustCase(null, { kind: "packs" }), /E_TRUST_KIND_KEYS/, "a kind with no keys");
});

test("a kind key is used only from its not_before", () => {
  const c = makeCatalogue();
  const late = { ...c.kindKeys, current: { ...c.kindKeys.current, not_before: "2026-12-01T00:00:00Z", notBefore: T0 + 30 * 86400 } };
  const rootKey = c.rootKey;
  const doc = makeTrust({ rootKey, kindKeys: [kindKeyRow("games", "current", "astra-games-2026a", c.current, late.current.not_before), kindKeyRow("games", "next", "astra-games-2026b", c.next, "2026-12-01T00:01:00Z")] });
  fs.writeFileSync(c.trustFile, JSON.stringify(doc));
  assert.throws(() => c.sign(), /E_KEY_NOT_YET_VALID/);
});

test("production: the compiled roots verify the published trust.json, which has no kind_keys yet", { skip: !process.env.ASTRA_REGISTRY_CHECKOUT && "set ASTRA_REGISTRY_CHECKOUT to a clone of astra-registry" }, () => {
  const text = execFileSync("git", ["-C", process.env.ASTRA_REGISTRY_CHECKOUT, "show", "origin/main:registry/v1/trust.json"], { encoding: "utf8" });
  const doc = JSON.parse(text);
  // compiled roots, no injection: the root signature is real and must check out
  if (Array.isArray(doc.signed.kind_keys)) {
    assert.doesNotThrow(() => loadTrust({ doc, now: T0 }));
  } else {
    assert.throws(() => loadTrust({ doc, now: T0 }), /E_TRUST_NO_KIND_KEYS/, "the root signature verified; only kind_keys is missing");
  }
});
