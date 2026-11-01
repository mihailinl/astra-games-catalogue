// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Moderator acts as data: every act re-signs BOTH documents in its own run;
// a revoke is in the withdrawn document in that same run; the foundation
// cascade defaults to a banner plus a yank; the takedown bound holds the
// fourth takedown in 24 hours; M_ADOPT_ENGINE_CODE needs all of its
// evidence; promotion and held releases.

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { ACT_TYPES } from "../lib/acts.mjs";
import { INDEX_SCHEMA, verifyDocuments, WITHDRAWN_SCHEMA } from "../lib/documents.mjs";
import { applyPlan, planReleases } from "../lib/promote.mjs";
import { act, candidate, FOO_DESCRIPTOR, makeCatalogue, T0 } from "./catalogue.mjs";

const GI = { slug: "peak-gi", repo_id: 920000001, account: "author" };
const FOO = { slug: "foo", repo_id: 920000002, account: "first", owner_id: 800000002, kind: "foundation", engine: "foo-engine", descriptor: FOO_DESCRIPTOR, version: "0.1.0", manifest_id: "first.foo" };
const SUCC = { slug: "foo-next", repo_id: 920000003, account: "second", owner_id: 800000003, kind: "foundation", engine: "foo-engine", version: "1.0.0", manifest_id: "second.foo-next" };
const DEP = { slug: "built-on-foo", repo_id: 920000004, account: "third", owner_id: 800000004, foundation: { id: "first.foo", version: "0.1.0", engine: "foo-engine" } };
const FP = { account: "mihailinl", slug: "astra-peak", repo_id: 1409552680, owner_id: 193032699, status: "prerelease", first_party: true };
const HELD = { slug: "moved", repo_id: 920000005, account: "author", verdict: "hold", findings: [{ code: "R_IDENTITY_CHANGED", message: "transferred" }] };

function seeded() {
  const c = makeCatalogue();
  const held = candidate(HELD);
  held.entry.source.repo_owner_id = 800000099; // the repository's NEW owner; the entry keeps the bound one
  c.sign({ candidates: [candidate(GI), candidate(FOO), candidate(SUCC), candidate(DEP), candidate(FP), held] });
  return c;
}

const evidence = { unanswered_reports: ["r-101", "r-102"], descriptor_failure: { kind: "probe", refs: ["probe-run-7"] }, successor_probe: "pass", successor_installs_without_failure: 3 };

/** One valid act of every type, against the seeded catalogue. */
const ACTS = {
  M_YANK: () => act("M_YANK", { repo_id: GI.repo_id, versions: "*", reason_code: "broken", reason_text: "Crashes on start." }),
  M_DELIST: () => act("M_DELIST", { repo_id: GI.repo_id, versions: "*", reason_code: "author-request" }),
  M_DEPRECATE: () => act("M_DEPRECATE", { repo_id: GI.repo_id, versions: "<2.0.0", reason_code: "broken", reason_text: "Use 2.x." }),
  M_REVOKE: () => act("M_REVOKE", { repo_id: GI.repo_id, versions: "<=1.0.0", reason_code: "security", reason_text: "A credential stealer." }),
  M_GAMES_EDIT: () => act("M_GAMES_EDIT", { op: "upsert", row: { store: "steam", id: 4000001, engine: "foo-engine", prefer: ["first/foo"], deny: [], refuse: null, allow_foundations: false, note: "detected wrongly" } }),
  M_ANTICHEAT_EDIT: () => act("M_ANTICHEAT_EDIT", { op: "add", row: { name: "Some Anti-Cheat", kind: "folder-marker", value: "SomeAC" } }),
  M_LOADERS_EDIT: () => act("M_LOADERS_EDIT", { op: "add", row: { name: "another-off-by-default", sha256: "a".repeat(64) } }),
  M_MARK_SOURCE_REVIEWED: () => act("M_MARK_SOURCE_REVIEWED", { entry_id: "author/peak-gi", version: "1.0.0" }),
  M_REASSIGN_ENGINE_CODE: () => act("M_REASSIGN_ENGINE_CODE", { code: "foo-engine", to: { account: "second", repo_id: SUCC.repo_id, repo_owner_id: SUCC.owner_id }, reason_text: "squatted" }),
  M_ADOPT_ENGINE_CODE: () => act("M_ADOPT_ENGINE_CODE", { code: "foo-engine", successor_entry_id: "second/foo-next", evidence }),
  M_SET_UNMAINTAINED: () => act("M_SET_UNMAINTAINED", { entry_id: "first/foo", unmaintained: true, successor_entry_id: "second/foo-next" }),
  M_SET_RECOMMENDED_FOUNDATION: () => act("M_SET_RECOMMENDED_FOUNDATION", { code: "foo-engine", entry_id: "second/foo-next" }),
  M_PROMOTE: () => act("M_PROMOTE", { entry_id: "mihailinl/astra-peak", version: "1.0.0" }),
  M_RELEASE_HOLD: () => act("M_RELEASE_HOLD", { hold_id: `${HELD.repo_id}@v1.0.0`, decision: "accept" }),
};

test("the act table covers every act type", () => {
  assert.deepEqual(Object.keys(ACTS).sort(), [...ACT_TYPES].sort());
});

for (const type of Object.keys(ACTS)) {
  test(`${type} re-signs both documents in its own run`, () => {
    const c = seeded();
    const before = { index: c.dist("games-index.json"), withdrawn: c.dist("games-withdrawn.json") };
    const r = c.sign({ acts: [ACTS[type]()] });
    assert.deepEqual(r.refusedActs, [], JSON.stringify(r.refusedActs));
    assert.equal(r.acts.length, 1);
    const index = c.dist("games-index.json");
    const withdrawn = c.dist("games-withdrawn.json");
    assert.ok(index.signed.issued_at > before.index.signed.issued_at, "index re-signed");
    assert.ok(withdrawn.signed.issued_at > before.withdrawn.signed.issued_at, "withdrawn re-signed");
    assert.notEqual(index.signatures[0].sig, before.index.signatures[0].sig);
    assert.notEqual(withdrawn.signatures[0].sig, before.withdrawn.signatures[0].sig);
    const problems = verifyDocuments([{ envelope: index, domain: INDEX_SCHEMA }, { envelope: withdrawn, domain: WITHDRAWN_SCHEMA, indexBody: index.signed }], { keys: c.keys, now: T0 });
    assert.deepEqual(problems, [[], []]);
    const recorded = JSON.parse(fs.readFileSync(path.join(c.data, "acts", "000001.json"), "utf8"));
    assert.equal(recorded.type, type);
    assert.equal(recorded.seq, 1);
  });
}

test("a revoke is in the withdrawn document in the same run, as no-play", () => {
  const c = seeded();
  c.sign({ acts: [ACTS.M_REVOKE()] });
  const rows = c.dist("games-withdrawn.json").signed.rows;
  assert.deepEqual(rows, [{ repo_id: GI.repo_id, versions: "<=1.0.0", act: "revoke", floor_effect: "no-play", reason_code: "security", reason_text: "A credential stealer.", at: T0 }]);
});

test("the foundation cascade defaults to a banner plus a yank on each dependant, in its own repository", () => {
  const c = seeded();
  c.sign({ acts: [act("M_REVOKE", { repo_id: FOO.repo_id, versions: "0.1.0", reason_code: "broken", reason_text: "Corrupts saves." })] });
  const rows = c.dist("games-withdrawn.json").signed.rows;
  const dep = rows.filter((r) => r.repo_id === DEP.repo_id);
  assert.deepEqual(dep.map((r) => r.act).sort(), ["deprecate", "yank"]);
  for (const r of dep) {
    assert.equal(r.entry_id, "third/built-on-foo");
    assert.equal(r.versions, "1.0.0");
  }
  assert.ok(!dep.some((r) => r.act === "revoke"), "a dependant is never revoked by default");
  assert.ok(rows.some((r) => r.repo_id === FOO.repo_id && r.act === "revoke"));
});

test("revoking a dependant too is an explicit per-entry choice in the act", () => {
  const c = seeded();
  c.sign({ acts: [act("M_REVOKE", { repo_id: FOO.repo_id, versions: "*", reason_code: "security", reason_text: "Backdoored.", cascade: { revoke: ["third/built-on-foo"] } })] });
  const dep = c.dist("games-withdrawn.json").signed.rows.filter((r) => r.repo_id === DEP.repo_id);
  assert.deepEqual(dep.map((r) => [r.act, r.floor_effect]), [["revoke", "no-play"]]);
});

test("the takedown bound: a fourth takedown in 24 hours is held, released later, or applied at once with break_glass", () => {
  const c = seeded();
  const take = (repo_id, extra = {}) => act("M_YANK", { repo_id, versions: "*", reason_code: "broken", ...extra });
  const r = c.sign({ acts: [take(GI.repo_id), take(FOO.repo_id), take(SUCC.repo_id), take(DEP.repo_id)] });
  assert.equal(r.refusedActs.length, 0);
  assert.equal(c.dist("games-withdrawn.json").signed.rows.length, 3);
  assert.equal(c.state("withdrawn.json").held.length, 1);
  // a re-sign a day later admits it
  c.sign({ now: T0 + 86401 });
  assert.equal(c.dist("games-withdrawn.json").signed.rows.length, 4);
  assert.equal(c.state("withdrawn.json").held.length, 0);
  // and break_glass skips the bound
  const g = seeded();
  g.sign({ acts: [take(GI.repo_id), take(FOO.repo_id), take(SUCC.repo_id), take(DEP.repo_id, { break_glass: true })] });
  assert.equal(g.dist("games-withdrawn.json").signed.rows.length, 4);
});

test("a deprecation is a banner, not a takedown: never held", () => {
  const c = seeded();
  const take = (repo_id) => act("M_YANK", { repo_id, versions: "*", reason_code: "broken" });
  c.sign({ acts: [take(GI.repo_id), take(FOO.repo_id), take(SUCC.repo_id), act("M_DEPRECATE", { repo_id: DEP.repo_id, versions: "*", reason_code: "broken" })] });
  assert.equal(c.dist("games-withdrawn.json").signed.rows.length, 4);
});

test("M_ADOPT_ENGINE_CODE moves the code and its descriptor, and marks the old foundation unmaintained", () => {
  const c = seeded();
  c.sign({ acts: [ACTS.M_ADOPT_ENGINE_CODE()] });
  const idx = c.dist("games-index.json").signed;
  assert.equal(idx.engine_codes["foo-engine"].account, "second");
  const succ = idx.entries.find((e) => e.id === "second/foo-next");
  const old = idx.entries.find((e) => e.id === "first/foo");
  assert.deepEqual(succ.descriptor, FOO_DESCRIPTOR);
  assert.equal(old.descriptor, null, "only the code's owner ships the descriptor");
  assert.deepEqual(c.state("moderation.json").foundations["first/foo"], { unmaintained: true, successor_entry_id: "second/foo-next" });
});

for (const [missing, strip] of [
  ["(a) unanswered reports", (e) => ({ ...e, unanswered_reports: [] })],
  ["(b) the descriptor failing", (e) => ({ ...e, descriptor_failure: undefined })],
  ["(c) a successor that passes gi-probe", (e) => ({ ...e, successor_probe: "fail" })],
  ["(c) an install without failure reports", (e) => ({ ...e, successor_installs_without_failure: 0 })],
]) {
  test(`M_ADOPT_ENGINE_CODE without ${missing} is refused and changes nothing`, () => {
    const c = seeded();
    const r = c.sign({ acts: [act("M_ADOPT_ENGINE_CODE", { code: "foo-engine", successor_entry_id: "second/foo-next", evidence: strip(evidence) })] });
    assert.equal(r.refusedActs.length, 1);
    assert.equal(c.dist("games-index.json").signed.engine_codes["foo-engine"].account, "first");
  });
}

test("acts the catalogue refuses: no 2FA confirmation, a security yank, no entry_id in a shared repository", () => {
  const c = seeded();
  const noConfirm = { ...ACTS.M_YANK(), confirmation: undefined };
  const securityYank = act("M_YANK", { repo_id: GI.repo_id, versions: "*", reason_code: "security" });
  // a second entry in GI's repository (R43: astra-bepinex hosts two)
  c.sign({ candidates: [candidate({ ...GI, slug: "peak-gi-extra" })] });
  const noEntry = act("M_YANK", { repo_id: GI.repo_id, versions: "*", reason_code: "broken" });
  const badRange = act("M_YANK", { repo_id: GI.repo_id, entry_id: "author/peak-gi", versions: "^1.0", reason_code: "broken" });
  const r = c.sign({ acts: [noConfirm, securityYank, noEntry, badRange] });
  assert.equal(r.refusedActs.length, 4);
  assert.equal(c.dist("games-withdrawn.json").signed.rows.length, 0);
});

test("M_PROMOTE lists a first-party prerelease, and promote.yml's plan then makes it stable on GitHub", async () => {
  const c = seeded();
  assert.ok(!c.dist("games-index.json").signed.entries.some((e) => e.id === "mihailinl/astra-peak"));
  c.sign({ acts: [ACTS.M_PROMOTE()] });
  const index = c.dist("games-index.json").signed;
  assert.ok(index.entries.some((e) => e.id === "mihailinl/astra-peak"));
  const firstParty = JSON.parse(fs.readFileSync(path.join(c.root, "first-party.json"), "utf8"));
  const plan = planReleases({ index, withdrawn: c.dist("games-withdrawn.json").signed, firstParty });
  assert.deepEqual(plan.map((p) => [p.repo_id, p.want_prerelease]), [[1409552680, false]]);
  const calls = [];
  const api = { async getRelease() { return { id: 7, prerelease: true }; }, async setPrerelease(r, id, v) { calls.push([r, id, v]); } };
  const out = await applyPlan(plan, api);
  assert.deepEqual(calls, [[1409552680, 7, false]]);
  assert.equal(out[0].to, "stable");
  // a revoke demotes it again (M7)
  c.sign({ acts: [act("M_REVOKE", { repo_id: 1409552680, versions: "*", reason_code: "security" })] });
  const plan2 = planReleases({ index: c.dist("games-index.json").signed, withdrawn: c.dist("games-withdrawn.json").signed, firstParty });
  assert.deepEqual(plan2.map((p) => p.want_prerelease), [true]);
});

test("M_RELEASE_HOLD accepts a changed hand: the listing is rebound to the repository's new owner", () => {
  const c = seeded();
  c.sign({ acts: [ACTS.M_RELEASE_HOLD()] });
  const e = c.dist("games-index.json").signed.entries.find((x) => x.id === "author/moved");
  assert.equal(e.publisher.repo_owner_id, 800000099, "installed users see changed_hands and are asked again");
  assert.equal(c.state("holds.json").length, 0);
  assert.equal(c.state("bindings.json")[String(HELD.repo_id)].repo_owner_id, 800000099);
});

test("M_MARK_SOURCE_REVIEWED labels only the bytes that were read", () => {
  const c = seeded();
  c.sign({ acts: [ACTS.M_MARK_SOURCE_REVIEWED()] });
  const e = c.dist("games-index.json").signed.entries.find((x) => x.id === "author/peak-gi");
  assert.equal(e.review, "source_reviewed");
  const other = c.dist("games-index.json").signed.entries.find((x) => x.id === "first/foo");
  assert.equal(other.review, "unchecked");
});
