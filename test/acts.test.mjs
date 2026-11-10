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

import { ACT_TYPES, actProblems } from "../lib/acts.mjs";
import { buildWithdrawnBody, INDEX_SCHEMA, LIFTS_MAX, verifyDocuments, withdrawnProblems, WITHDRAWN_SCHEMA } from "../lib/documents.mjs";
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
  M_LIFT: () => act("M_LIFT", { repo_id: GI.repo_id, versions: "<=1.0.0", lifts_at: T0, reason_text: "The advisory named another package." }, T0 + 60),
};

/** What must already be in the catalogue for the act above to be valid: a lift needs its row. */
const BEFORE = { M_LIFT: () => [ACTS.M_REVOKE()] };

test("the act table covers every act type", () => {
  assert.deepEqual(Object.keys(ACTS).sort(), [...ACT_TYPES].sort());
});

for (const type of Object.keys(ACTS)) {
  test(`${type} re-signs both documents in its own run`, () => {
    const c = seeded();
    const setup = BEFORE[type]?.() ?? [];
    if (setup.length) assert.deepEqual(c.sign({ acts: setup }).refusedActs, []);
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
    const problems = verifyDocuments([{ envelope: index, domain: INDEX_SCHEMA }, { envelope: withdrawn, domain: WITHDRAWN_SCHEMA, indexBody: index.signed }], { kindKeys: c.kindKeys, now: T0 });
    assert.deepEqual(problems, [[], []]);
    const recorded = JSON.parse(fs.readFileSync(path.join(c.data, "acts", `${String(setup.length + 1).padStart(6, "0")}.json`), "utf8"));
    assert.equal(recorded.type, type);
    assert.equal(recorded.seq, setup.length + 1);
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

test("M_RELEASE_HOLD accepts a changed binding: the listing moves to the account the repository now names", () => {
  const c = makeCatalogue();
  const first = candidate({ slug: "rebound", repo_id: 920000006, account: "author" });
  c.sign({ candidates: [first] });
  const moved = candidate({ slug: "rebound", repo_id: 920000006, account: "author", version: "1.1.0", verdict: "hold", findings: [{ code: "R_BINDING_CHANGED", message: "rebound" }] });
  moved.meta.claimant = { account: "new-owner", binding_token: "newOwnersToken_0123456789" };
  c.sign({ candidates: [moved] });
  c.sign({ acts: [act("M_RELEASE_HOLD", { hold_id: "920000006@v1.1.0", decision: "accept" })] });
  const e = c.dist("games-index.json").signed.entries.find((x) => x.id === "author/rebound" && x.version === "1.1.0");
  assert.equal(e.publisher.account, "new-owner");
  assert.equal(c.state("bindings.json")["920000006"].binding_token, "newOwnersToken_0123456789");
});

test("M_MARK_SOURCE_REVIEWED labels only the bytes that were read", () => {
  const c = seeded();
  c.sign({ acts: [ACTS.M_MARK_SOURCE_REVIEWED()] });
  const e = c.dist("games-index.json").signed.entries.find((x) => x.id === "author/peak-gi");
  assert.equal(e.review, "source_reviewed");
  const other = c.dist("games-index.json").signed.entries.find((x) => x.id === "first/foo");
  assert.equal(other.review, "unchecked");
});

// ── one act, once (lane C design §1.9 item 4) ───────────────────────────

test("a re-served act (same confirmation ref) is answered applied with its first seq, and is not applied twice", () => {
  const c = seeded();
  const yank = ACTS.M_YANK();
  const first = c.sign({ acts: [yank] });
  assert.equal(first.acts.length, 1);
  const seq = first.acts[0].seq;
  const rows = c.state("withdrawn.json").rows.length;
  const again = c.sign({ acts: [structuredClone(yank)] });
  assert.deepEqual(again.acts, [], "nothing applied the second time");
  assert.deepEqual(again.duplicateActs, [{ ref: yank.confirmation.ref, type: "M_YANK", seq }]);
  assert.deepEqual(again.refusedActs, [], "a duplicate is not a refusal and does not fail the run");
  assert.equal(c.state("withdrawn.json").rows.length, rows, "no second withdrawn row");
  assert.equal(fs.readdirSync(path.join(c.data, "acts")).length, 1, "one record per act");
});

test("the same confirmation ref twice in one run is applied once; the second answers with the first's seq", () => {
  const c = seeded();
  const hold = ACTS.M_RELEASE_HOLD();
  const r = c.sign({ acts: [hold, structuredClone(hold)] });
  assert.equal(r.acts.length, 1);
  assert.deepEqual(r.duplicateActs, [{ ref: hold.confirmation.ref, type: "M_RELEASE_HOLD", seq: r.acts[0].seq }]);
  assert.deepEqual(r.refusedActs, [], "the second M_RELEASE_HOLD is not refused for a hold the first already released");
});

test("a refused act carries its confirmation ref, so the service can say which act failed", () => {
  const c = seeded();
  const bad = act("M_PROMOTE", { entry_id: "nobody/nothing", version: "9.9.9" });
  const r = c.sign({ acts: [bad] });
  assert.equal(r.refusedActs.length, 1);
  assert.equal(r.refusedActs[0].ref, bad.confirmation.ref);
  assert.equal(r.refusedActs[0].type, "M_PROMOTE");
});

// ── M_LIFT (games-withdrawn-v1.md §2.2) ─────────────────────────────────────
//
// A client keeps a security revoke in force after the list stops carrying
// it, and releases it only on a signed lift. Until this act the catalogue
// could not write one, so such a revoke could never be undone for anybody
// who had already seen it.

const REVOKE_ROW = { repo_id: GI.repo_id, versions: "<=1.0.0", act: "revoke", floor_effect: "no-play", reason_code: "security", reason_text: "A credential stealer.", at: T0 };
const lift = (payload = {}, at = T0 + 60) => act("M_LIFT", { repo_id: GI.repo_id, versions: "<=1.0.0", lifts_at: T0, reason_text: "The advisory named another package.", ...payload }, at);
const withdrawnOf = (c) => c.dist("games-withdrawn.json").signed;
const verified = (c) => verifyDocuments(
  [{ envelope: c.dist("games-index.json"), domain: INDEX_SCHEMA }, { envelope: c.dist("games-withdrawn.json"), domain: WITHDRAWN_SCHEMA, indexBody: c.dist("games-index.json").signed }],
  { kindKeys: c.kindKeys, now: T0 },
);

function revoked() {
  const c = seeded();
  assert.deepEqual(c.sign({ acts: [ACTS.M_REVOKE()] }).refusedActs, []);
  assert.deepEqual(withdrawnOf(c).rows, [REVOKE_ROW]);
  return c;
}

test("the signed list always carries lifts, [] when there is none, and a state written before lifts existed still signs", () => {
  const c = seeded();
  assert.deepEqual(withdrawnOf(c).lifts, []);
  // a withdrawn.json from before the member existed
  fs.writeFileSync(path.join(c.data, "withdrawn.json"), JSON.stringify({ rows: [], held: [] }));
  c.sign({ acts: [ACTS.M_REVOKE()] });
  assert.deepEqual(withdrawnOf(c).lifts, []);
  assert.deepEqual(c.sign({ acts: [lift()] }).refusedActs, []);
  assert.equal(withdrawnOf(c).lifts.length, 1);
});

test("M_LIFT: the row leaves the list and its lift is in it, in the same run", () => {
  const c = revoked();
  const r = c.sign({ acts: [lift()] });
  assert.deepEqual(r.refusedActs, []);
  const w = withdrawnOf(c);
  assert.deepEqual(w.rows, [], "the lifted row left rows in the issue that carries its lift");
  assert.deepEqual(w.lifts, [{ repo_id: GI.repo_id, versions: "<=1.0.0", lifts_at: T0, at: T0 + 60 }], "what a client reads, and no more: no entry_id the row did not have, no by, no reason");
  assert.deepEqual(verified(c), [[], []]);
  // the state and the act log keep who and why
  assert.deepEqual(c.state("withdrawn.json").lifts, [{ repo_id: GI.repo_id, versions: "<=1.0.0", lifts_at: T0, at: T0 + 60, by: "mod-1", reason_text: "The advisory named another package.", lifted: ["revoke"] }]);
  const recorded = JSON.parse(fs.readFileSync(path.join(c.data, "acts", "000002.json"), "utf8"));
  assert.equal(recorded.type, "M_LIFT");
  assert.deepEqual(recorded.summary, { lifted: ["revoke"], repo_id: GI.repo_id, versions: "<=1.0.0", lifts_at: T0 });
});

test("M_LIFT: the lift stays in every later list, across runs and other acts", () => {
  const c = revoked();
  c.sign({ acts: [lift()] });
  const want = withdrawnOf(c).lifts;
  assert.equal(want.length, 1);
  c.sign({ now: T0 + 86400 });
  assert.deepEqual(withdrawnOf(c).lifts, want, "a daily re-sign");
  c.sign({ now: T0 + 2 * 86400, acts: [act("M_YANK", { repo_id: FOO.repo_id, versions: "*", reason_code: "broken" }, T0 + 2 * 86400)] });
  assert.deepEqual(withdrawnOf(c).lifts, want, "a later act of another subject");
  assert.equal(withdrawnOf(c).rows.length, 1);
  c.sign({ now: T0 + 30 * 86400 });
  assert.deepEqual(withdrawnOf(c).lifts, want, "a month on");
});

for (const [name, payload, problem] of [
  ["versions spelled with a space", { versions: "<= 1.0.0" }, /^versions "<= 1\.0\.0" matches no row of that subject as written; its rows carry "<=1\.0\.0"$/],
  ["versions one byte off", { versions: "<=1.0.1" }, /^versions "<=1\.0\.1" matches no row of that subject as written/],
  ["lifts_at one second late", { lifts_at: T0 + 1 }, new RegExp(`^lifts_at ${T0 + 1} matches no row of that subject; its rows were taken at ${T0}$`)],
  ["lifts_at one second early", { lifts_at: T0 - 1 }, /^lifts_at \d+ matches no row of that subject/],
  ["an entry_id the row does not have", { entry_id: "author/peak-gi" }, /^entry_id "author\/peak-gi" matches no row of repository 920000001; its rows name none$/],
  ["another repository", { repo_id: SUCC.repo_id }, /^repo_id 920000003 has no row in the list to lift$/],
]) {
  test(`M_LIFT is refused when it names no row (${name}), says which part, and lifts nothing`, () => {
    const c = revoked();
    const r = c.sign({ acts: [lift(payload)] });
    assert.equal(r.refusedActs.length, 1);
    assert.equal(r.refusedActs[0].problems.length, 1, JSON.stringify(r.refusedActs[0].problems));
    assert.match(r.refusedActs[0].problems[0], problem);
    assert.deepEqual(withdrawnOf(c).rows, [REVOKE_ROW]);
    assert.deepEqual(withdrawnOf(c).lifts, []);
  });
}

test("M_LIFT: a row that names an entry is lifted only by a lift that names it, byte for byte", () => {
  const c = seeded();
  c.sign({ candidates: [candidate({ ...GI, slug: "peak-gi-extra" })] });
  c.sign({ acts: [act("M_REVOKE", { repo_id: GI.repo_id, entry_id: "author/peak-gi", versions: "*", reason_code: "security" })] });
  for (const [payload, problem] of [
    [{}, /^entry_id none matches no row of repository 920000001; its rows name "author\/peak-gi"$/],
    [{ entry_id: "Author/peak-gi" }, /^entry_id "Author\/peak-gi" matches no row/],
    [{ entry_id: "author/peak-gi-extra" }, /^entry_id "author\/peak-gi-extra" matches no row/],
  ]) {
    const r = c.sign({ acts: [lift({ versions: "*", ...payload })] });
    assert.match(r.refusedActs[0]?.problems[0] ?? "", problem);
    assert.equal(withdrawnOf(c).rows.length, 1);
  }
  assert.deepEqual(c.sign({ acts: [lift({ versions: "*", entry_id: "author/peak-gi" })] }).refusedActs, []);
  assert.deepEqual(withdrawnOf(c).rows, []);
  assert.deepEqual(withdrawnOf(c).lifts, [{ repo_id: GI.repo_id, versions: "*", entry_id: "author/peak-gi", lifts_at: T0, at: T0 + 60 }]);
  assert.deepEqual(verified(c), [[], []]);
});

test("M_LIFT leaves a row that shares the repository and the second but not the versions, or not the entry", () => {
  // two rows of one subject's repository, taken in the same second, with different versions
  const v = seeded();
  v.sign({ acts: [act("M_YANK", { repo_id: GI.repo_id, versions: "<=1.0.0", reason_code: "broken" }), act("M_DEPRECATE", { repo_id: GI.repo_id, versions: "*", reason_code: "broken" })] });
  assert.deepEqual(v.sign({ acts: [lift({ versions: "*" })] }).refusedActs, []);
  assert.deepEqual(withdrawnOf(v).rows.map((r) => [r.act, r.versions]), [["yank", "<=1.0.0"]]);
  assert.deepEqual(v.state("withdrawn.json").lifts[0].lifted, ["deprecate"]);
  // two entries of one repository, both revoked in the same second
  const e = seeded();
  e.sign({ candidates: [candidate({ ...GI, slug: "peak-gi-extra" })] });
  const revoke = (entry_id) => act("M_REVOKE", { repo_id: GI.repo_id, entry_id, versions: "*", reason_code: "security" });
  e.sign({ acts: [revoke("author/peak-gi"), revoke("author/peak-gi-extra")] });
  assert.deepEqual(e.sign({ acts: [lift({ versions: "*", entry_id: "author/peak-gi-extra" })] }).refusedActs, []);
  assert.deepEqual(withdrawnOf(e).rows.map((r) => r.entry_id), ["author/peak-gi"]);
  assert.deepEqual(verified(e), [[], []]);
});

for (const [name, payload, problems] of [
  ["no reason_text", { reason_text: undefined }, ["reason_text says why (the transparency log shows it)"]],
  ["an empty reason_text", { reason_text: "" }, ["reason_text says why (the transparency log shows it)"]],
  ["lifts_at a string", { lifts_at: String(T0) }, ["lifts_at is the lifted row's at, in Unix seconds"]],
  ["lifts_at with a fraction", { lifts_at: T0 + 0.5 }, ["lifts_at is the lifted row's at, in Unix seconds"]],
  ["lifts_at zero", { lifts_at: 0 }, ["lifts_at is the lifted row's at, in Unix seconds"]],
  ["no lifts_at", { lifts_at: undefined }, ["lifts_at is the lifted row's at, in Unix seconds"]],
  ["no versions", { versions: undefined }, ["versions is the lifted row's versions, exactly as that row carries it"]],
  ["empty versions", { versions: "" }, ["versions is the lifted row's versions, exactly as that row carries it"]],
  ["a numeric entry_id", { entry_id: 7 }, ["entry_id is not a string"]],
  ["a null entry_id", { entry_id: null }, ["entry_id is not a string"]],
  ["repo_id zero", { repo_id: 0 }, ["repo_id is not a repository id"]],
  ["a repo_id string", { repo_id: String(GI.repo_id) }, ["repo_id is not a repository id"]],
  ["everything wrong at once", { repo_id: -1, versions: 5, entry_id: [], lifts_at: null, reason_text: 5 }, [
    "repo_id is not a repository id",
    "versions is the lifted row's versions, exactly as that row carries it",
    "entry_id is not a string",
    "lifts_at is the lifted row's at, in Unix seconds",
    "reason_text says why (the transparency log shows it)",
  ]],
]) {
  test(`M_LIFT shape: ${name} is refused by its shape alone`, () => {
    const c = revoked();
    const r = c.sign({ acts: [lift(payload)] });
    assert.deepEqual(r.refusedActs.map((x) => x.problems), [problems]);
    assert.deepEqual(withdrawnOf(c).rows, [REVOKE_ROW]);
  });
}

test("M_LIFT shape needs no state: the same problems against a catalogue with no row at all (the service's half)", () => {
  const empty = { entries: [], withdrawn: { rows: [], held: [] }, holds: [], engineCodes: {} };
  assert.deepEqual(actProblems(lift({ lifts_at: "x", reason_text: undefined }), empty), ["lifts_at is the lifted row's at, in Unix seconds", "reason_text says why (the transparency log shows it)"]);
  assert.deepEqual(actProblems(lift(), empty), [`repo_id ${GI.repo_id} has no row in the list to lift`], "a well-shaped lift is then judged against the state");
});

test("M_LIFT: delivered twice it is applied once; a second lift of the same row finds none", () => {
  const c = revoked();
  const one = lift();
  c.sign({ acts: [one] });
  const again = c.sign({ acts: [one] });
  assert.deepEqual(again.duplicateActs.map((d) => d.seq), [2]);
  assert.deepEqual(again.refusedActs, []);
  const second = c.sign({ acts: [lift()] });
  assert.match(second.refusedActs[0].problems[0], /has no row in the list to lift$/);
  assert.equal(withdrawnOf(c).lifts.length, 1);
});

test("M_LIFT lifts what it names and nothing else: a cascade's rows stay, and its banner and yank leave by one lift of their own", () => {
  const c = seeded();
  c.sign({ acts: [act("M_REVOKE", { repo_id: FOO.repo_id, versions: "0.1.0", reason_code: "broken", reason_text: "Corrupts saves." })] });
  const rowsOf = (repo) => withdrawnOf(c).rows.filter((r) => r.repo_id === repo).map((r) => r.act).sort();
  assert.deepEqual(rowsOf(DEP.repo_id), ["deprecate", "yank"]);
  // the foundation's revoke is lifted: the dependant's rows are rows of another subject, and stay
  assert.deepEqual(c.sign({ acts: [lift({ repo_id: FOO.repo_id, versions: "0.1.0" })] }).refusedActs, []);
  assert.deepEqual(rowsOf(FOO.repo_id), []);
  assert.deepEqual(rowsOf(DEP.repo_id), ["deprecate", "yank"], "cascaded rows are lifted by their own acts");
  assert.deepEqual(verified(c), [[], []]);
  // the banner and the yank share their subject and their at, so a client's one lift names both: both leave
  assert.deepEqual(c.sign({ acts: [lift({ repo_id: DEP.repo_id, entry_id: "third/built-on-foo", versions: "1.0.0" }, T0 + 120)] }).refusedActs, []);
  assert.deepEqual(withdrawnOf(c).rows, []);
  assert.deepEqual(c.state("withdrawn.json").lifts.map((l) => l.lifted), [["revoke"], ["deprecate", "yank"]]);
  assert.deepEqual(verified(c), [[], []]);
});

test("M_LIFT: two separate acts on one subject within one second are one lift's rows, and both leave", () => {
  // found by the ops local stand: a revoke and a delist of one entry, both `*`, landed in the same second
  const c = seeded();
  c.sign({ acts: [act("M_REVOKE", { repo_id: GI.repo_id, versions: "*", reason_code: "security" }), act("M_DELIST", { repo_id: GI.repo_id, versions: "*", reason_code: "policy" })] });
  assert.deepEqual(withdrawnOf(c).rows.map((r) => r.act).sort(), ["delist", "revoke"]);
  const r = c.sign({ acts: [lift({ versions: "*" })] });
  assert.deepEqual(r.refusedActs, []);
  assert.deepEqual(r.acts[0].summary.lifted, ["delist", "revoke"], "the run's record says what left");
  assert.deepEqual(withdrawnOf(c).rows, [], "a client would match the lift to either, so neither may stay beside it");
  assert.deepEqual(verified(c), [[], []]);
  // a second later they are two subjects-in-time, and one lift names one
  const d = seeded();
  d.sign({ acts: [act("M_REVOKE", { repo_id: GI.repo_id, versions: "*", reason_code: "security" }), act("M_DELIST", { repo_id: GI.repo_id, versions: "*", reason_code: "policy" }, T0 + 1)] });
  d.sign({ acts: [lift({ versions: "*" })] });
  assert.deepEqual(withdrawnOf(d).rows.map((x) => [x.act, x.at]), [["delist", T0 + 1]]);
});

test("M_LIFT: a dependant revoked with its foundation stays revoked when the foundation's revoke is lifted", () => {
  const c = seeded();
  c.sign({ acts: [act("M_REVOKE", { repo_id: FOO.repo_id, versions: "*", reason_code: "security", reason_text: "Backdoored.", cascade: { revoke: ["third/built-on-foo"] } })] });
  c.sign({ acts: [lift({ repo_id: FOO.repo_id, versions: "*" })] });
  assert.deepEqual(withdrawnOf(c).rows.map((r) => [r.repo_id, r.act, r.reason_code]), [[DEP.repo_id, "revoke", "security"]]);
});

test("the takedown bound counts a lifted takedown: revoking and lifting is no way around 3 in 24 hours", () => {
  const c = seeded();
  const take = (repo_id) => act("M_YANK", { repo_id, versions: "*", reason_code: "broken" });
  c.sign({ acts: [take(GI.repo_id), take(FOO.repo_id), take(SUCC.repo_id)] });
  assert.equal(withdrawnOf(c).rows.length, 3);
  // one of the three is lifted, and a fourth unit is taken down within the window
  const r = c.sign({ now: T0 + 3600, acts: [lift({ versions: "*" }, T0 + 3600), act("M_YANK", { repo_id: DEP.repo_id, versions: "*", reason_code: "broken" }, T0 + 3600)] });
  assert.deepEqual(r.refusedActs, []);
  assert.equal(withdrawnOf(c).rows.length, 2, "the lifted row left, and the fourth takedown did not get its unit");
  assert.equal(c.state("withdrawn.json").held.length, 1);
  // the same unit again costs nothing, as before the lift
  c.sign({ now: T0 + 7200, acts: [act("M_YANK", { repo_id: GI.repo_id, versions: "*", reason_code: "broken" }, T0 + 7200)] });
  assert.equal(withdrawnOf(c).rows.length, 3);
  // a day after the first three, the held one is admitted
  c.sign({ now: T0 + 86401 });
  assert.equal(c.state("withdrawn.json").held.length, 0);
  assert.equal(withdrawnOf(c).rows.length, 4);
});

test("M_LIFT: a takedown held over the bound is not in the list, and the refusal says so", () => {
  const c = seeded();
  const take = (repo_id) => act("M_YANK", { repo_id, versions: "*", reason_code: "broken" });
  c.sign({ acts: [take(GI.repo_id), take(FOO.repo_id), take(SUCC.repo_id), take(DEP.repo_id)] });
  const r = c.sign({ acts: [lift({ repo_id: DEP.repo_id, versions: "*" })] });
  assert.deepEqual(r.refusedActs[0].problems, [`repo_id ${DEP.repo_id} has no row in the list to lift (a takedown of it is held over the bound and is not in the list yet)`]);
});

test("a row taken again after its lift: with a new at the old lift stays beside it, with the same at the lift leaves and the row wins", () => {
  const later = revoked();
  later.sign({ acts: [lift()] });
  later.sign({ now: T0 + 600, acts: [act("M_REVOKE", { repo_id: GI.repo_id, versions: "<=1.0.0", reason_code: "security", reason_text: "It was this package after all." }, T0 + 600)] });
  assert.deepEqual(withdrawnOf(later).rows.map((r) => r.at), [T0 + 600]);
  assert.deepEqual(withdrawnOf(later).lifts.map((l) => l.lifts_at), [T0], "the old lift does not name the new row");
  assert.deepEqual(verified(later), [[], []]);
  // the new row is lifted by its own at
  assert.deepEqual(later.sign({ now: T0 + 900, acts: [lift({ lifts_at: T0 + 600 }, T0 + 900)] }).refusedActs, []);
  assert.deepEqual(withdrawnOf(later).lifts.map((l) => l.lifts_at), [T0, T0 + 600]);

  const same = revoked();
  same.sign({ acts: [lift()] });
  same.sign({ acts: [act("M_REVOKE", { repo_id: GI.repo_id, versions: "<=1.0.0", reason_code: "security", reason_text: "A credential stealer." }, T0)] });
  assert.deepEqual(withdrawnOf(same).rows, [REVOKE_ROW]);
  assert.deepEqual(withdrawnOf(same).lifts, [], "a list that carried both would be refused by its own signer");
  assert.deepEqual(verified(same), [[], []]);
});

test(`the list carries at most ${LIFTS_MAX} lifts: past that the oldest is dropped, and never before`, () => {
  const state = (n) => ({ withdrawn: { rows: [], held: [], lifts: Array.from({ length: n }, (_, i) => ({ repo_id: 5, versions: "*", lifts_at: 1000 + i, at: 5000 + (n - i), by: "mod-1", reason_text: "x", lifted: ["yank"] })) } });
  const body = (n) => buildWithdrawnBody({ state: state(n), issuedAt: T0, keyId: "games-current" });
  assert.equal(body(LIFTS_MAX).lifts.length, LIFTS_MAX);
  assert.equal(body(LIFTS_MAX - 1).lifts.length, LIFTS_MAX - 1);
  const over = body(LIFTS_MAX + 3).lifts;
  assert.equal(over.length, LIFTS_MAX);
  // the three with the smallest `at` are the three last in the state: age is the lift's at, not its place
  assert.deepEqual(over.map((l) => l.at), Array.from({ length: LIFTS_MAX }, (_, i) => 5000 + 4 + i));
  assert.deepEqual(Object.keys(over[0]).sort(), ["at", "lifts_at", "repo_id", "versions"]);
  // and the whole thing through a real signing run: the state keeps all, the list serves the newest
  const c = revoked();
  const w = c.state("withdrawn.json");
  w.lifts = state(LIFTS_MAX + 3).withdrawn.lifts;
  fs.writeFileSync(path.join(c.data, "withdrawn.json"), JSON.stringify(w));
  c.sign({ acts: [lift()] });
  assert.equal(withdrawnOf(c).lifts.length, LIFTS_MAX);
  assert.ok(withdrawnOf(c).lifts.some((l) => l.repo_id === GI.repo_id), "the newest lift is in it");
  assert.equal(c.state("withdrawn.json").lifts.length, LIFTS_MAX + 4);
  assert.deepEqual(verified(c), [[], []]);
});

test("lift-not-contradicted: a list that carries a row and a lift a client would match to it is not signed", () => {
  const row = { ...REVOKE_ROW, entry_id: "author/peak-gi" };
  const l = { repo_id: row.repo_id, versions: row.versions, entry_id: row.entry_id, lifts_at: row.at, at: row.at + 60 };
  const problems = (lifts, rows = [row]) => withdrawnProblems({ rows, lifts });
  assert.deepEqual(problems([]), []);
  assert.deepEqual(withdrawnProblems({ rows: [row] }), [], "a list without the member carries no lift");
  assert.match(problems([l])[0], /^lift-not-contradicted: /);
  assert.match(problems([{ ...l, entry_id: " Author/Peak-GI " }])[0], /^lift-not-contradicted: /, "a client trims and lowercases entry_id");
  for (const near of [{ ...l, versions: "<= 1.0.0" }, { ...l, lifts_at: row.at + 1 }, { ...l, repo_id: row.repo_id + 1 }, { ...l, entry_id: "author/peak" }, { repo_id: l.repo_id, versions: l.versions, lifts_at: l.lifts_at, at: l.at }]) {
    assert.deepEqual(problems([near]), [], JSON.stringify(near));
  }
  assert.deepEqual(problems([{ repo_id: l.repo_id, versions: l.versions, lifts_at: l.lifts_at, at: l.at }], [REVOKE_ROW]).length, 1, "neither names an entry");
});

test("M_LIFT of a first-party revoke: promote.yml's plan makes the release stable again", () => {
  const c = seeded();
  c.sign({ acts: [ACTS.M_PROMOTE()] });
  const firstParty = JSON.parse(fs.readFileSync(path.join(c.root, "first-party.json"), "utf8"));
  const plan = () => planReleases({ index: c.dist("games-index.json").signed, withdrawn: withdrawnOf(c), firstParty }).map((p) => p.want_prerelease);
  c.sign({ acts: [act("M_REVOKE", { repo_id: 1409552680, versions: "*", reason_code: "security" })] });
  assert.deepEqual(plan(), [true]);
  c.sign({ acts: [lift({ repo_id: 1409552680, versions: "*" })] });
  assert.deepEqual(plan(), [false]);
});
