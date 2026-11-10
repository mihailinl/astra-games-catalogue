// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The manifest id at the signer's door (accept.mjs): ingest judged a release
// against the state it read, and the state can move before the sign — two
// repositories releasing one `[integration] id` can both pass ingest, and
// only the first to be signed may hold it. The engine keys an integration's
// packages, inbox and games/<id>.json by that id (AstraPlugins
// spec/games/manifest.md §3), so the second is refused whoever owns it.

import assert from "node:assert/strict";
import { test } from "node:test";

import { act, candidate, makeCatalogue } from "./catalogue.mjs";

const ALICE = { account: "alice", slug: "foo-game", repo_id: 930000001, owner_id: 800000011, manifest_id: "foo.game" };
const BOB = { account: "bob", slug: "foo-game", repo_id: 930000002, owner_id: 800000012, manifest_id: "foo.game" };
const results = (r) => r.accepted.map((a) => a.result);

test("two repositories, one manifest id: the first signed holds it, the second is refused naming the holder", () => {
  const c = makeCatalogue();
  const r = c.sign({ candidates: [candidate(ALICE), candidate(BOB)] });
  assert.deepEqual(results(r), ["listed", "refused"]);
  assert.match(r.accepted[1].reason, /\[integration\] id "foo\.game" is held by alice's repository 930000001 \(alice\/foo-game\)/);
  assert.deepEqual(c.state("entries.json").map((e) => e.entry.id), ["alice/foo-game"]);
  // and in a later run, too
  assert.deepEqual(results(c.sign({ candidates: [candidate({ ...BOB, version: "1.0.1" })] })), ["refused"]);
});

test("the holder's own next version is listed", () => {
  const c = makeCatalogue();
  c.sign({ candidates: [candidate(ALICE)] });
  assert.deepEqual(results(c.sign({ candidates: [candidate({ ...ALICE, version: "1.1.0" })] })), ["listed"]);
});

test("the same account's second repository is another holder: refused by the manifest-id rule", () => {
  const c = makeCatalogue();
  c.sign({ candidates: [candidate(ALICE)] });
  const r = c.sign({ candidates: [candidate({ ...ALICE, slug: "foo-game-2", repo_id: 930000003 })] });
  assert.deepEqual(results(r), ["refused"]);
  assert.match(r.accepted[0].reason, /^\[integration\] id "foo\.game" is held by alice's repository 930000001/);
});

test("a look-alike manifest id is refused as confusable", () => {
  const c = makeCatalogue();
  c.sign({ candidates: [candidate(ALICE)] });
  const r = c.sign({ candidates: [candidate({ ...BOB, slug: "fo0-game", manifest_id: "fo0.game" })] });
  assert.deepEqual(results(r), ["refused"]);
  assert.match(r.accepted[0].reason, /\[integration\] id "fo0\.game" reads the same as "foo\.game"/);
});

for (const [type, payload] of [
  ["M_REVOKE", { versions: "*", reason_code: "security", reason_text: "A credential stealer." }],
  ["M_DELIST", { versions: "*", reason_code: "author-request" }],
]) {
  test(`a ${type === "M_REVOKE" ? "revoked" : "delisted"} holder keeps the name: installs still hold its data under that id`, () => {
    const c = makeCatalogue();
    c.sign({ candidates: [candidate(ALICE)] });
    assert.deepEqual(c.sign({ acts: [act(type, { repo_id: ALICE.repo_id, ...payload })] }).refusedActs, []);
    const r = c.sign({ candidates: [candidate(BOB)] });
    assert.deepEqual(results(r), ["refused"]);
    assert.match(r.accepted[0].reason, /\[integration\] id "foo\.game" is held by alice's repository/);
  });
}

test("a candidate without a manifest id cannot be judged, so it is not listed", () => {
  const c = makeCatalogue();
  const bare = candidate(ALICE);
  delete bare.meta.manifest_id;
  const r = c.sign({ candidates: [bare] });
  assert.deepEqual(results(r), ["refused"]);
  assert.match(r.accepted[0].reason, /carries no manifest id/);
});

// The one move (spec/games/manifest.md §3): between two first-party
// repositories, both rows of first-party.json (makeCatalogue copies the real
// one), for a successor integration whose engine data must carry over.
const GTA3 = "astra.unreal.gta3-definitive-edition";
const RESHADE = { account: "mihailinl", slug: "astra-unreal-gta3-definitive-edition", repo_id: 1412685270, owner_id: 193032699, manifest_id: GTA3, first_party: true, version: "0.3.1" };
const TRILOGY = { ...RESHADE, repo_id: 1427110216, version: "0.4.0" };

test("first-party move: astra-gta-trilogy takes astra.unreal.gta3-definitive-edition from astra-reshade and continues its entry", () => {
  const c = makeCatalogue();
  assert.deepEqual(results(c.sign({ candidates: [candidate(RESHADE)] })), ["listed"]);
  const r = c.sign({ candidates: [candidate(TRILOGY)] });
  assert.deepEqual(results(r), ["listed"], r.accepted[0].reason);
  assert.deepEqual(c.state("entries.json").map((e) => [e.entry.id, e.entry.version, e.entry.source.repo_id]), [
    ["mihailinl/astra-unreal-gta3-definitive-edition", "0.3.1", 1412685270],
    ["mihailinl/astra-unreal-gta3-definitive-edition", "0.4.0", 1427110216],
  ]);
});

test("a third-party repository never takes a first-party id", () => {
  const c = makeCatalogue();
  c.sign({ candidates: [candidate(RESHADE)] });
  const r = c.sign({ candidates: [candidate({ ...BOB, slug: "gta3", manifest_id: GTA3 })] });
  assert.deepEqual(results(r), ["refused"]);
  assert.match(r.accepted[0].reason, /\[integration\] id "astra\.unreal\.gta3-definitive-edition" is held by mihailinl's repository 1412685270/);
});

test("a first-party repository never takes a third party's id", () => {
  const c = makeCatalogue();
  c.sign({ candidates: [candidate(ALICE)] });
  const r = c.sign({ candidates: [candidate({ ...TRILOGY, slug: "foo-game", manifest_id: "foo.game" })] });
  assert.deepEqual(results(r), ["refused"]);
  assert.match(r.accepted[0].reason, /\[integration\] id "foo\.game" is held by alice's repository 930000001/);
});
