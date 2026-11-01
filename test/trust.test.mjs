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
import { test } from "node:test";

import { privateKeyFromSeed, signEnvelope } from "../lib/vendor/astra-registry/bot/lib/sign.mjs";
import { INDEX_SCHEMA, verifyDocuments, WITHDRAWN_SCHEMA } from "../lib/documents.mjs";
import { loadTrust } from "../lib/trust.mjs";
import { candidate, kindKeyRow, makeCatalogue, makeTrust, rootsOf, T0 } from "./catalogue.mjs";
import { throwawayKey } from "./helpers.mjs";

/** Re-sign a games document's body with an arbitrary key, as a forger holding that key would. */
function resignWith(envelope, domain, key, keyId) {
  return signEnvelope({ domain, signed: envelope.signed, signers: [{ key_id: keyId, privateKey: privateKeyFromSeed(Buffer.from(key.seedB64, "base64")) }] });
}

const both = (c, index, withdrawn) =>
  verifyDocuments([{ envelope: index, domain: INDEX_SCHEMA }, { envelope: withdrawn, domain: WITHDRAWN_SCHEMA, indexBody: index.signed }], { kindKeys: c.kindKeys, now: T0 });

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

test("rotation: setting GAMES_SIGNING_KEY_NEXT is the whole change; the same trust.json verifies both sides", () => {
  const c = makeCatalogue();
  c.sign({ candidates: [candidate()] });
  const before = c.dist("games-index.json");
  const trustBefore = fs.readFileSync(c.trustFile, "utf8");

  c.sign({ env: { ...c.env, GAMES_SIGNING_KEY_NEXT: c.next.seedB64 } });
  const index = c.dist("games-index.json");
  const withdrawn = c.dist("games-withdrawn.json");
  assert.equal(fs.readFileSync(c.trustFile, "utf8"), trustBefore, "trust.json did not change");
  assert.equal(index.signatures[0].key_id, "astra-games-2026b");
  assert.equal(index.signed.key_id, "games-next");
  assert.ok(index.signed.serial > before.signed.serial, "the per-kind floor carries across the rotation");
  assert.deepEqual(both(c, index, withdrawn), [[], []]);
  assert.deepEqual(index.signed.entries, before.signed.entries, "the content did not change");
  // the old document still verifies too: clients accept both keys
  assert.deepEqual(both(c, before, JSON.parse(JSON.stringify(withdrawn)))[0], []);
  // and the rotated-away key is spent: the signer never slides back to it
  assert.deepEqual(c.state("floors.json").spent, ["astra-games-2026a"]);
  assert.throws(() => c.sign({ env: { GAMES_SIGNING_KEY_CURRENT: c.current.seedB64 } }), /E_KEY_RETIRED/);
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
  assert.throws(trustCase((s) => s.index_keys.push({ key_id: "astra-index-2026b", public_key: s.kind_keys[0].public_key })), /E_TRUST_KIND_KEY_IN_INDEX_KEYS/);
  assert.throws(trustCase((s) => s.kind_keys.push({ ...s.kind_keys[0], kind: "commands", role: "current", key_id: "astra-commands-2026a" }, kindKeyRow("commands", "next", "astra-commands-2026b", throwawayKey()))), /E_TRUST_KIND_KEYS/, "one key for two kinds");
  assert.throws(trustCase(null, { expiresAt: "2026-10-30T00:00:00Z" }), /E_TRUST_EXPIRED/);
  assert.throws(trustCase(null, { kind: "packs" }), /E_TRUST_KIND_KEYS/, "a kind with no keys");
});

test("a kind key is used only from its not_before", () => {
  const c = makeCatalogue();
  const late = { ...c.kindKeys, current: { ...c.kindKeys.current, not_before: "2026-12-01T00:00:00Z", notBefore: T0 + 30 * 86400 } };
  const rootKey = c.rootKey;
  const doc = makeTrust({ rootKey, kindKeys: [kindKeyRow("games", "current", "astra-games-2026a", c.current, late.current.not_before), kindKeyRow("games", "next", "astra-games-2026b", c.next)] });
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
