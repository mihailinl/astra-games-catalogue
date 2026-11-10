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

import { ACT_CLOCK_SKEW, ACT_TYPES, ActRefused, actProblems, applyAct, LIFT_KEEP_SECONDS, LIFT_LIMIT, retainLifts, ROW_KINDS } from "../lib/acts.mjs";
import { buildWithdrawnBody, INDEX_SCHEMA, LIFTS_MAX, verifyDocuments, withdrawnProblems, WITHDRAWN_SCHEMA } from "../lib/documents.mjs";
import { clientEntryId, entryKey, subjectKey } from "../lib/model.mjs";
import { listProblemsIntroduced, tryAct, unsignable } from "../lib/pipeline.mjs";
import { loadState } from "../lib/state.mjs";
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
  M_LIFT: () => act("M_LIFT", { repo_id: GI.repo_id, versions: "<=1.0.0", lifts_at: T0, kinds: ["revoke"], reason_text: "The advisory named another package." }, T0 + 60),
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

const DAY = 86400;
const KINDS_SHAPE = "kinds is the acts of the rows this lift removes: a non-empty array of distinct values out of yank, delist, deprecate, revoke";
const REVOKE_ROW = { repo_id: GI.repo_id, versions: "<=1.0.0", act: "revoke", floor_effect: "no-play", reason_code: "security", reason_text: "A credential stealer.", at: T0 };
const lift = (payload = {}, at = T0 + 60) => act("M_LIFT", { repo_id: GI.repo_id, versions: "<=1.0.0", lifts_at: T0, kinds: ["revoke"], reason_text: "The advisory named another package.", ...payload }, at);
const withdrawnOf = (c) => c.dist("games-withdrawn.json").signed;
const stateOf = (c) => c.state("withdrawn.json");
const verified = (c, now = T0) => verifyDocuments(
  [{ envelope: c.dist("games-index.json"), domain: INDEX_SCHEMA }, { envelope: c.dist("games-withdrawn.json"), domain: WITHDRAWN_SCHEMA, indexBody: c.dist("games-index.json").signed }],
  { kindKeys: c.kindKeys, now },
);
const problemsOf = (r) => r.refusedActs.map((x) => x.problems);

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
  // the state and the act log keep who, why, when it was applied and that it lifted a security revoke
  assert.deepEqual(stateOf(c).lifts, [{ repo_id: GI.repo_id, versions: "<=1.0.0", lifts_at: T0, at: T0 + 60, applied_at: T0, by: "mod-1", reason_text: "The advisory named another package.", lifted: ["revoke"], sticky: true }]);
  const recorded = JSON.parse(fs.readFileSync(path.join(c.data, "acts", "000002.json"), "utf8"));
  assert.equal(recorded.type, "M_LIFT");
  assert.deepEqual(recorded.summary, { lifted: ["revoke"], repo_id: GI.repo_id, versions: "<=1.0.0", lifts_at: T0 });
});

test("M_LIFT: the lift stays in every later list, across runs and other acts", () => {
  const c = revoked();
  c.sign({ acts: [lift()] });
  const want = withdrawnOf(c).lifts;
  assert.equal(want.length, 1);
  c.sign({ now: T0 + DAY });
  assert.deepEqual(withdrawnOf(c).lifts, want, "a daily re-sign");
  c.sign({ now: T0 + 2 * DAY, acts: [act("M_YANK", { repo_id: FOO.repo_id, versions: "*", reason_code: "broken" }, T0 + 2 * DAY)] });
  assert.deepEqual(withdrawnOf(c).lifts, want, "a later act of another subject");
  assert.equal(withdrawnOf(c).rows.length, 1);
  c.sign({ now: T0 + 30 * DAY });
  assert.deepEqual(withdrawnOf(c).lifts, want, "a month on");
});

for (const [name, payload, problem] of [
  ["versions spelled with a space", { versions: "<= 1.0.0" }, /^versions "<= 1\.0\.0" matches no row of that subject as written; its rows carry "<=1\.0\.0"$/],
  ["versions with a leading space", { versions: " <=1.0.0" }, /^versions " <=1\.0\.0" matches no row of that subject as written/],
  ["versions one byte off", { versions: "<=1.0.1" }, /^versions "<=1\.0\.1" matches no row of that subject as written/],
  ["lifts_at one second late", { lifts_at: T0 + 1 }, new RegExp(`^lifts_at ${T0 + 1} matches no row of that subject; its rows were taken at ${T0}$`)],
  ["lifts_at one second early", { lifts_at: T0 - 1 }, /^lifts_at \d+ matches no row of that subject/],
  ["an entry_id the row does not have", { entry_id: "author/peak-gi" }, /^entry_id "author\/peak-gi" matches no row of repository 920000001; its rows name none$/],
  ["another repository", { repo_id: SUCC.repo_id }, /^repo_id 920000003 has no row to lift, in the list or held$/],
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

test("M_LIFT leaves a row that shares the repository and the second but not the versions, or not the entry", () => {
  // two rows of one repository, taken in the same second, with different versions: two subjects
  const v = seeded();
  v.sign({ acts: [act("M_YANK", { repo_id: GI.repo_id, versions: "<=1.0.0", reason_code: "broken" }), act("M_DEPRECATE", { repo_id: GI.repo_id, versions: "*", reason_code: "broken" })] });
  assert.deepEqual(withdrawnOf(v).rows.map((r) => r.at), [T0, T0], "different subjects may share a second");
  assert.deepEqual(v.sign({ acts: [lift({ versions: "*", kinds: ["deprecate"] })] }).refusedActs, []);
  assert.deepEqual(withdrawnOf(v).rows.map((r) => [r.act, r.versions]), [["yank", "<=1.0.0"]]);
  assert.deepEqual(stateOf(v).lifts[0].lifted, ["deprecate"]);
  assert.equal(stateOf(v).lifts[0].sticky, false);
  // two entries of one repository, both revoked in the same second
  const e = seeded();
  e.sign({ candidates: [candidate({ ...GI, slug: "peak-gi-extra" })] });
  const revoke = (entry_id) => act("M_REVOKE", { repo_id: GI.repo_id, entry_id, versions: "*", reason_code: "security" });
  e.sign({ acts: [revoke("author/peak-gi"), revoke("author/peak-gi-extra")] });
  assert.deepEqual(e.sign({ acts: [lift({ versions: "*", entry_id: "author/peak-gi-extra" })] }).refusedActs, []);
  assert.deepEqual(withdrawnOf(e).rows.map((r) => r.entry_id), ["author/peak-gi"]);
  assert.deepEqual(verified(e), [[], []]);
});

// ── one reading of the subject: the client's (review round 1, finding 3) ──

test("the subject is read as a client reads it: entry_id trimmed and lowercased by Rust's rules, none equal to none only", () => {
  const key = (entry_id) => entryKey({ entry_id });
  assert.equal(key(undefined), "-");
  assert.equal(key(null), "-", "null and an absent member are the same: none");
  assert.equal(key("  Foo/Bar\t"), "=foo/bar");
  assert.equal(key("ÜNÏ/Peak"), "=ünï/peak", "Unicode lowercase, not ASCII only");
  assert.equal(key("İd/x"), "=i̇d/x", "U+0130 lowercases to i + U+0307 in Rust and in JavaScript alike");
  assert.equal(key("\u0085foo\u0085"), "=foo", "U+0085 is White_Space to Rust's trim(); JavaScript's trim() keeps it");
  assert.equal(key("﻿foo"), "=﻿foo", "U+FEFF is not White_Space to Rust; JavaScript's trim() strips it");
  assert.equal(key("　foo "), "=foo");
  for (const unreadable of ["", "   ", "\t\n", "\u0085", "a\u0007b", "a\u007fb", "a\u009fb", "foo\u0000", 7, {}, []]) assert.equal(key(unreadable), null, JSON.stringify(unreadable));
  assert.deepEqual(clientEntryId("x\u0001"), { unreadable: "it carries a control character" });
  // versions byte for byte; an absent one reads as ""; repo_id as a number
  assert.notEqual(subjectKey({ repo_id: 1, versions: "<=1.0.0" }), subjectKey({ repo_id: 1, versions: "<= 1.0.0" }));
  assert.notEqual(subjectKey({ repo_id: 1, versions: "*" }), subjectKey({ repo_id: 1, versions: " *" }));
  assert.equal(subjectKey({ repo_id: 1 }), subjectKey({ repo_id: 1, versions: "" }));
  assert.equal(subjectKey({ repo_id: 1, versions: "*", entry_id: null }), subjectKey({ repo_id: 1, versions: "*" }));
  assert.notEqual(subjectKey({ repo_id: 1, versions: "*", entry_id: "a" }), subjectKey({ repo_id: 1, versions: "*" }), "none is no id");
  assert.equal(subjectKey({ repo_id: 1, versions: "*", entry_id: " " }), null);
});

test("M_LIFT names a row whose entry_id it spells as a client would read it, and the lift is written as the ROW spelled it", () => {
  const c = seeded();
  c.sign({ candidates: [candidate({ ...GI, slug: "peak-gi-extra" })] });
  c.sign({ acts: [act("M_REVOKE", { repo_id: GI.repo_id, entry_id: "author/peak-gi", versions: "*", reason_code: "security" })] });
  for (const [payload, problem] of [
    [{}, /^entry_id none matches no row of repository 920000001; its rows name "author\/peak-gi"$/],
    [{ entry_id: "author/peak-gi-extra" }, /^entry_id "author\/peak-gi-extra" matches no row/],
    [{ entry_id: "author/peak-g" }, /^entry_id "author\/peak-g" matches no row/],
  ]) {
    const r = c.sign({ acts: [lift({ versions: "*", ...payload })] });
    assert.match(r.refusedActs[0]?.problems[0] ?? "", problem);
    assert.equal(withdrawnOf(c).rows.length, 1);
  }
  assert.deepEqual(c.sign({ acts: [lift({ versions: "*", entry_id: "  Author/Peak-GI " })] }).refusedActs, []);
  assert.deepEqual(withdrawnOf(c).rows, []);
  assert.deepEqual(withdrawnOf(c).lifts, [{ repo_id: GI.repo_id, versions: "*", entry_id: "author/peak-gi", lifts_at: T0, at: T0 + 60 }]);
  assert.deepEqual(verified(c), [[], []]);
});

test("a non-ASCII entry_id is written in lowercase, and then read alike everywhere", () => {
  const NOWHERE = 930000001; // a repository the catalogue lists no entry of, so an act may name any entry
  const c = seeded();
  assert.deepEqual(c.sign({ acts: [act("M_REVOKE", { repo_id: NOWHERE, entry_id: "ünï/peak-ς", versions: "*", reason_code: "security" })] }).refusedActs, []);
  assert.deepEqual(c.sign({ acts: [lift({ repo_id: NOWHERE, versions: "*", entry_id: " ünï/Peak-ς " })] }).refusedActs, [], "ASCII letters in any case, white space at the ends");
  assert.deepEqual(withdrawnOf(c).rows, []);
  assert.equal(withdrawnOf(c).lifts[0].entry_id, "ünï/peak-ς");
  assert.deepEqual(verified(c), [[], []]);
  // the list itself is READ with Unicode lowercase, as a client reads it: a row and a lift spelled in two cases are one subject
  const row = { ...REVOKE_ROW, entry_id: "ünï/peak" };
  assert.match(withdrawnProblems({ rows: [row], lifts: [{ repo_id: row.repo_id, versions: row.versions, entry_id: "ÜNÏ/Peak", lifts_at: row.at, at: row.at + 1 }] })[0], /^lift-not-contradicted: /);
  assert.match(withdrawnProblems({ rows: [row, { ...row, entry_id: "ÜNÏ/PEAK", act: "delist", reason_code: "policy" }], lifts: [] })[0], /^one-act-per-second: /);
});

const NOT_LOWERCASE = (cp, extra = "") => `entry_id holds a non-ASCII character that is not already lowercase (U+${cp}${extra}): a client lowercases an id by its own Unicode tables, which may not be the signer's; write the id in lowercase`;
for (const [name, entry_id, problem] of [
  ["only spaces", "   ", "entry_id is not an id a client can read: it is empty once trimmed"],
  ["only U+0085", "\u0085", "entry_id is not an id a client can read: it is empty once trimmed"],
  ["a control character", "author/peak\u0007gi", "entry_id is not an id a client can read: it carries a control character"],
  ["a NUL", "author/peak-gi\u0000", "entry_id is not an id a client can read: it carries a control character"],
  ["an uppercase non-ASCII letter", "Ünï/peak", NOT_LOWERCASE("00DC")],
  ["U+0130, whose lowercase is two code points", "İd/peak", NOT_LOWERCASE("0130")],
  ["a capital sigma, whose lowercase depends on its neighbours", "ας/Σ", NOT_LOWERCASE("03A3")],
  ["a letter of a recent Unicode version", "peak/꟎", NOT_LOWERCASE("A7CE")],
  ["an unassigned code point", "peak/͸", NOT_LOWERCASE("0378", ", unassigned")],
]) {
  test(`an entry_id that not every client reads alike (${name}) is refused in a withdrawal act and in a lift, and written nowhere`, () => {
    const NOWHERE = 930000001;
    const c = seeded();
    const r = c.sign({ acts: [act("M_REVOKE", { repo_id: NOWHERE, entry_id, versions: "*", reason_code: "security" }), lift({ repo_id: NOWHERE, versions: "*", entry_id })] });
    assert.deepEqual(problemsOf(r), [[problem], [problem]]);
    assert.deepEqual(withdrawnOf(c).rows, []);
    assert.deepEqual(stateOf(c).held, []);
  });
}

test("an act whose rows the signer would refuse to sign is REFUSED with the reason, and the run goes on (the poison act)", () => {
  // A cascade writes its rows with the dependant's id from the STATE, which no act shape reaches. Give the
  // dependant an id no client can read: applied, the list would fail entry-id-readable and the run would end
  // with no report, the service would serve the act again, and nothing would be signed after it.
  const c = seeded();
  const entries = c.state("entries.json");
  entries.find((e) => e.entry.id === "third/built-on-foo").entry.id = "third/built\u0007on-foo";
  fs.writeFileSync(path.join(c.data, "entries.json"), JSON.stringify(entries));
  const before = withdrawnOf(c).issued_at;
  const r = c.sign({ acts: [act("M_REVOKE", { repo_id: FOO.repo_id, versions: "0.1.0", reason_code: "broken" }), ACTS.M_YANK()] });
  assert.equal(r.refusedActs.length, 1);
  assert.equal(r.refusedActs[0].type, "M_REVOKE");
  assert.match(r.refusedActs[0].problems[0], /^applied, this act would leave a withdrawn list the signer refuses to sign: entry-id-readable: repo 920000004 carries entry_id "third\/built\\u0007on-foo"/);
  assert.deepEqual(r.acts.map((a) => a.type), ["M_YANK"], "the act after it is applied");
  assert.deepEqual(withdrawnOf(c).rows.map((x) => [x.repo_id, x.act]), [[GI.repo_id, "yank"]], "nothing of the refused act was kept");
  assert.ok(withdrawnOf(c).issued_at > before, "and both documents are signed");
  assert.deepEqual(stateOf(c).spent.map((s) => s.unit), [`${GI.repo_id}#*`], "it spent no unit");
});

test("listProblemsIntroduced: only what the act added, never what the state already had", () => {
  const row = { repo_id: 5, versions: "*", act: "revoke", floor_effect: "no-play", reason_code: "security", at: 100 };
  const state = (rows, lifts = []) => ({ withdrawn: { rows, held: [], lifts } });
  const l = { repo_id: 5, versions: "*", lifts_at: 100, at: 200 };
  assert.deepEqual(listProblemsIntroduced(state([row]), state([row]), T0, null), []);
  assert.match(listProblemsIntroduced(state([row]), state([row], [l]), T0, null)[0], /^lift-not-contradicted: /);
  assert.match(listProblemsIntroduced(state([row]), state([row, { ...row, act: "delist", floor_effect: "no-offer", reason_code: "policy" }]), T0, null)[0], /^one-act-per-second: /);
  assert.deepEqual(listProblemsIntroduced(state([row], [l]), state([row], [l]), T0, null), [], "already broken is not this act's doing");
});

// ── invariant I: one act per subject and second; a row never erases a lift ──

test("two acts on one subject in one second: the later row takes the next free second, so each has a lift of its own", () => {
  // found by the ops local stand: a revoke and a delist of one entry, both `*`, landed in the same second
  const c = seeded();
  const r = c.sign({ acts: [act("M_REVOKE", { repo_id: GI.repo_id, versions: "*", reason_code: "security" }), act("M_DELIST", { repo_id: GI.repo_id, versions: "*", reason_code: "policy" }), act("M_YANK", { repo_id: GI.repo_id, versions: "*", reason_code: "broken" })] });
  assert.deepEqual(r.refusedActs, []);
  assert.deepEqual(withdrawnOf(c).rows.map((x) => [x.act, x.at]), [["revoke", T0], ["delist", T0 + 1], ["yank", T0 + 2]]);
  assert.deepEqual(r.acts.map((a) => [a.at, a.summary.at]), [[T0, T0], [T0, T0 + 1], [T0, T0 + 2]], "the act keeps its own at; its summary says the row's");
  assert.deepEqual(verified(c), [[], []]);
  // one lift, one act's row
  c.sign({ acts: [lift({ versions: "*" })] });
  assert.deepEqual(withdrawnOf(c).rows.map((x) => [x.act, x.at]), [["delist", T0 + 1], ["yank", T0 + 2]]);
  c.sign({ acts: [lift({ versions: "*", lifts_at: T0 + 2, kinds: ["yank"] }, T0 + 90)] });
  assert.deepEqual(withdrawnOf(c).rows.map((x) => x.act), ["delist"]);
  assert.deepEqual(verified(c), [[], []]);
});

test("the rows one act writes for one subject keep one second, even a moved one: a cascade's banner and its yank", () => {
  const c = seeded();
  // the dependant already carries a row of the cascade's subject, taken in the same second
  c.sign({ acts: [act("M_DEPRECATE", { repo_id: DEP.repo_id, entry_id: "third/built-on-foo", versions: "1.0.0", reason_code: "author-request" })] });
  c.sign({ acts: [act("M_REVOKE", { repo_id: FOO.repo_id, versions: "0.1.0", reason_code: "broken", reason_text: "Corrupts saves." })] });
  const dep = withdrawnOf(c).rows.filter((x) => x.repo_id === DEP.repo_id).map((x) => [x.act, x.reason_code, x.at]);
  assert.deepEqual(dep, [["deprecate", "author-request", T0], ["deprecate", "broken", T0 + 1], ["yank", "broken", T0 + 1]]);
  assert.deepEqual(verified(c), [[], []]);
  // the cascade's pair leaves by one lift; the moderator's own banner stays
  c.sign({ acts: [lift({ repo_id: DEP.repo_id, entry_id: "third/built-on-foo", versions: "1.0.0", lifts_at: T0 + 1, kinds: ["deprecate", "yank"] })] });
  assert.deepEqual(withdrawnOf(c).rows.filter((x) => x.repo_id === DEP.repo_id).map((x) => [x.act, x.reason_code]), [["deprecate", "author-request"]]);
});

test("a row never erases a lift: a deprecate dated at the lifted revoke's second moves on, the lift stays, and the unit stays spent (finding 2)", () => {
  const c = revoked();
  c.sign({ acts: [lift()] });
  assert.equal(withdrawnOf(c).lifts.length, 1);
  // the reviewer's case: M_DEPRECATE of the same subject, dated at the revoke's own second
  const r = c.sign({ acts: [act("M_DEPRECATE", { repo_id: GI.repo_id, versions: "<=1.0.0", reason_code: "broken" }, T0)] });
  assert.deepEqual(r.refusedActs, []);
  assert.deepEqual(withdrawnOf(c).rows.map((x) => [x.act, x.at]), [["deprecate", T0 + 1]], "the row took the second after the lift's");
  assert.deepEqual(withdrawnOf(c).lifts, [{ repo_id: GI.repo_id, versions: "<=1.0.0", lifts_at: T0, at: T0 + 60 }], "the lift is still served");
  assert.deepEqual(verified(c), [[], []]);
  // and the lifted revoke's unit is still spent: two more takedowns fill the bound, the next is held
  const take = (repo_id) => act("M_YANK", { repo_id, versions: "*", reason_code: "broken" });
  c.sign({ acts: [take(FOO.repo_id), take(SUCC.repo_id), take(DEP.repo_id)] });
  assert.equal(stateOf(c).held.length, 1);
  // a revoke taken again at that very second moves on too, and is a new row with a lift of its own
  const again = revoked();
  again.sign({ acts: [lift()] });
  again.sign({ acts: [act("M_REVOKE", { repo_id: GI.repo_id, versions: "<=1.0.0", reason_code: "security", reason_text: "It was this package after all." }, T0)] });
  assert.deepEqual(withdrawnOf(again).rows.map((x) => x.at), [T0 + 1]);
  assert.deepEqual(withdrawnOf(again).lifts.map((l) => l.lifts_at), [T0]);
  assert.deepEqual(verified(again), [[], []]);
  assert.deepEqual(again.sign({ now: T0 + 900, acts: [lift({ lifts_at: T0 + 1 }, T0 + 900)] }).refusedActs, []);
  assert.deepEqual(withdrawnOf(again).lifts.map((l) => l.lifts_at), [T0, T0 + 1]);
});

test("the list's own rules: one act per subject and second (a cascade's banner and yank excepted), and no entry_id a client cannot read", () => {
  const row = (o = {}) => ({ ...REVOKE_ROW, entry_id: "author/peak-gi", ...o });
  const problems = (rows, lifts = []) => withdrawnProblems({ rows, lifts });
  assert.deepEqual(problems([row()]), []);
  assert.deepEqual(problems([row({ act: "deprecate", reason_code: "broken" }), row({ act: "yank", reason_code: "broken" })]), [], "the banner and the yank one cascade writes");
  assert.match(problems([row(), row({ act: "delist", reason_code: "policy" })])[0], /^one-act-per-second: repo 920000001 author\/peak-gi <=1\.0\.0 carries delist and revoke at /);
  assert.match(problems([row(), row({ entry_id: " Author/Peak-GI", act: "delist", reason_code: "policy" })])[0], /^one-act-per-second: /, "as a client reads the subject");
  assert.equal(problems([row(), row()]).length, 1, "the same act twice");
  assert.equal(problems([row({ act: "deprecate", reason_code: "broken" }), row({ act: "yank", reason_code: "broken" }), row({ act: "delist", reason_code: "broken" })]).length, 1, "three");
  assert.deepEqual(problems([row(), row({ at: T0 + 1, act: "delist", reason_code: "policy" })]), [], "a second apart");
  assert.deepEqual(problems([row(), row({ versions: "*", act: "delist", reason_code: "policy" })]), [], "another subject");
  assert.match(problems([row({ entry_id: "  " })])[0], /^entry-id-readable: repo 920000001 carries entry_id "  "/);
  assert.match(problems([], [{ repo_id: 5, versions: "*", entry_id: "a\u0001", lifts_at: 1, at: 2 }])[0], /^entry-id-readable: /);
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

// ── shape, and the lift's own `at` (finding 6) ───────────────────────────────

for (const [name, payload, problems] of [
  ["no reason_text", { reason_text: undefined }, ["reason_text says why (the transparency log shows it)"]],
  ["an empty reason_text", { reason_text: "" }, ["reason_text says why (the transparency log shows it)"]],
  ["lifts_at a string", { lifts_at: String(T0) }, ["lifts_at is the lifted row's at, in Unix seconds"]],
  ["lifts_at with a fraction", { lifts_at: T0 + 0.5 }, ["lifts_at is the lifted row's at, in Unix seconds"]],
  ["lifts_at zero", { lifts_at: 0 }, ["lifts_at is the lifted row's at, in Unix seconds"]],
  ["no lifts_at", { lifts_at: undefined }, ["lifts_at is the lifted row's at, in Unix seconds"]],
  ["lifts_at after the lift's own at", { lifts_at: T0 + 61 }, ["lifts_at is after the lift's own at: a lift is never older than the row it lifts"]],
  ["no versions", { versions: undefined }, ["versions is the lifted row's versions, exactly as that row carries it"]],
  ["empty versions", { versions: "" }, ["versions is the lifted row's versions, exactly as that row carries it"]],
  ["a numeric entry_id", { entry_id: 7 }, ["entry_id is not a string"]],
  ["a null entry_id", { entry_id: null }, ["entry_id is not a string"]],
  ["repo_id zero", { repo_id: 0 }, ["repo_id is not a repository id"]],
  ["a repo_id string", { repo_id: String(GI.repo_id) }, ["repo_id is not a repository id"]],
  ["a repo_id with a fraction", { repo_id: GI.repo_id + 0.5 }, ["repo_id is not a repository id"]],
  ["no kinds", { kinds: undefined }, [KINDS_SHAPE]],
  ["kinds that is not an array", { kinds: "revoke" }, [KINDS_SHAPE]],
  ["empty kinds", { kinds: [] }, [KINDS_SHAPE]],
  ["a kind the list does not know", { kinds: ["revoke", "lift"] }, [KINDS_SHAPE]],
  ["a kind that is not a string", { kinds: [["revoke"]] }, [KINDS_SHAPE]],
  ["a kind named twice", { kinds: ["revoke", "revoke"] }, [KINDS_SHAPE]],
  ["everything wrong at once", { repo_id: -1, versions: 5, entry_id: [], lifts_at: null, kinds: 7, reason_text: 5 }, [
    "repo_id is not a repository id",
    "versions is the lifted row's versions, exactly as that row carries it",
    "entry_id is not a string",
    "lifts_at is the lifted row's at, in Unix seconds",
    KINDS_SHAPE,
    "reason_text says why (the transparency log shows it)",
  ]],
]) {
  test(`M_LIFT shape: ${name} is refused by its shape alone`, () => {
    const c = revoked();
    const r = c.sign({ acts: [lift(payload)] });
    assert.deepEqual(problemsOf(r), [problems]);
    assert.deepEqual(withdrawnOf(c).rows, [REVOKE_ROW]);
  });
}

test("M_LIFT shape needs no state and no clock: the same problems against a catalogue with no row at all (the service's half)", () => {
  const empty = { entries: [], withdrawn: { rows: [], held: [] }, holds: [], engineCodes: {} };
  assert.deepEqual(actProblems(lift({ lifts_at: "x", reason_text: undefined }), empty), ["lifts_at is the lifted row's at, in Unix seconds", "reason_text says why (the transparency log shows it)"]);
  assert.deepEqual(actProblems(lift({ lifts_at: T0 + 61 }), empty), ["lifts_at is after the lift's own at: a lift is never older than the row it lifts"]);
  assert.deepEqual(actProblems(lift({ kinds: ["revoke", "banner"] }), empty), [KINDS_SHAPE]);
  assert.deepEqual(ROW_KINDS, ["yank", "delist", "deprecate", "revoke"], "the vocabulary the contract is told");
  assert.deepEqual(actProblems(lift({ kinds: [...ROW_KINDS] }), empty), [`repo_id ${GI.repo_id} has no row to lift, in the list or held`], "every kind at once is a shape");
  assert.deepEqual(actProblems(lift(), empty), [`repo_id ${GI.repo_id} has no row to lift, in the list or held`], "a well-shaped lift is then judged against the state");
});

test("M_LIFT is dated when it was taken: lifts_at <= at <= the signer's clock plus the skew", () => {
  const c = revoked();
  const ahead = c.sign({ now: T0 + 100, acts: [lift({}, T0 + 100 + ACT_CLOCK_SKEW + 1)] });
  assert.deepEqual(problemsOf(ahead), [[`at is ${ACT_CLOCK_SKEW + 1} seconds ahead of the signer's clock; an act is dated when it was taken (at most ${ACT_CLOCK_SKEW} seconds of skew)`]]);
  assert.equal(withdrawnOf(c).rows.length, 1);
  // exactly the skew is still this clock's
  assert.deepEqual(c.sign({ now: T0 + 100, acts: [lift({}, T0 + 100 + ACT_CLOCK_SKEW)] }).refusedActs, []);
  assert.deepEqual(withdrawnOf(c).lifts.map((l) => l.at), [T0 + 100 + ACT_CLOCK_SKEW]);
  // at equal to lifts_at is a lift taken in the row's own second
  const same = revoked();
  assert.deepEqual(same.sign({ acts: [lift({}, T0)] }).refusedActs, []);
});

test("M_LIFT: delivered twice it is applied once; a second lift of the same row finds none", () => {
  const c = revoked();
  const one = lift();
  c.sign({ acts: [one] });
  const again = c.sign({ acts: [one] });
  assert.deepEqual(again.duplicateActs.map((d) => d.seq), [2]);
  assert.deepEqual(again.refusedActs, []);
  const second = c.sign({ acts: [lift()] });
  assert.match(second.refusedActs[0].problems[0], /has no row to lift, in the list or held$/);
  assert.equal(withdrawnOf(c).lifts.length, 1);
});

// ── cascades and held takedowns (finding 1) ──────────────────────────────────

test("M_LIFT lifts what it names and nothing else: a cascade's published rows stay, and its banner and yank leave by one lift of their own", () => {
  const c = seeded();
  c.sign({ acts: [act("M_REVOKE", { repo_id: FOO.repo_id, versions: "0.1.0", reason_code: "broken", reason_text: "Corrupts saves." })] });
  const rowsOf = (repo) => withdrawnOf(c).rows.filter((r) => r.repo_id === repo).map((r) => r.act).sort();
  assert.deepEqual(rowsOf(DEP.repo_id), ["deprecate", "yank"]);
  // the foundation's revoke is lifted: the dependant's rows are rows of another subject, and stay
  assert.deepEqual(c.sign({ acts: [lift({ repo_id: FOO.repo_id, versions: "0.1.0" })] }).refusedActs, []);
  assert.deepEqual(rowsOf(FOO.repo_id), []);
  assert.deepEqual(rowsOf(DEP.repo_id), ["deprecate", "yank"], "published cascade rows are lifted by their own acts");
  assert.deepEqual(verified(c), [[], []]);
  // the banner and the yank are what ONE act wrote for the subject: one lift, both leave
  assert.deepEqual(c.sign({ acts: [lift({ repo_id: DEP.repo_id, entry_id: "third/built-on-foo", versions: "1.0.0", kinds: ["yank", "deprecate"] }, T0 + 120)] }).refusedActs, []);
  assert.deepEqual(withdrawnOf(c).rows, []);
  assert.deepEqual(stateOf(c).lifts.map((l) => [l.lifted, l.sticky]), [[["revoke"], false], [["deprecate", "yank"], false]]);
  assert.deepEqual(verified(c), [[], []]);
});

test("M_LIFT: a dependant revoked with its foundation stays revoked when the foundation's revoke is lifted", () => {
  const c = seeded();
  c.sign({ acts: [act("M_REVOKE", { repo_id: FOO.repo_id, versions: "*", reason_code: "security", reason_text: "Backdoored.", cascade: { revoke: ["third/built-on-foo"] } })] });
  c.sign({ acts: [lift({ repo_id: FOO.repo_id, versions: "*" })] });
  assert.deepEqual(withdrawnOf(c).rows.map((r) => [r.repo_id, r.act, r.reason_code]), [[DEP.repo_id, "revoke", "security"]]);
});

test("a held takedown does not outlive the lift of its cause: a foundation revoked for security, four dependants, two held (finding 1)", () => {
  const c = seeded();
  const more = [5, 6, 7].map((n) => ({ ...DEP, slug: `built-on-foo-${n}`, repo_id: 920000010 + n, account: `dep${n}`, owner_id: 800000010 + n }));
  c.sign({ candidates: more.map(candidate) });
  const r = c.sign({ acts: [act("M_REVOKE", { repo_id: FOO.repo_id, versions: "0.1.0", reason_code: "security", reason_text: "Backdoored." })] });
  assert.deepEqual(r.acts[0].summary, { applied: 7, held: 2, at: T0 }, "the revoke, four banners and two yanks; two yanks over the bound");
  assert.equal(stateOf(c).held.length, 2);
  assert.ok(stateOf(c).held.every((h) => h.row.cascade && h.row.act === "yank"));
  // the foundation's revoke is lifted
  const l = c.sign({ now: T0 + 3600, acts: [lift({ repo_id: FOO.repo_id, versions: "0.1.0" }, T0 + 3600)] });
  assert.deepEqual(l.refusedActs, []);
  assert.equal(l.acts[0].summary.dropped_held_cascade, 2);
  assert.deepEqual(stateOf(c).held, [], "the two held yanks went with their cause");
  const published = withdrawnOf(c).rows.map((x) => x.act).sort();
  assert.deepEqual(published, ["deprecate", "deprecate", "deprecate", "deprecate", "yank", "yank"], "what was published still needs lifts of its own");
  // a day later the window has room, and nothing is admitted
  const next = c.sign({ now: T0 + DAY + 7200 });
  assert.deepEqual(next.admitted, []);
  assert.deepEqual(withdrawnOf(c).rows.map((x) => x.act).sort(), published);
  assert.deepEqual(verified(c, T0 + DAY + 7200), [[], []]);
});

test("admitHeld drops a held cascade takedown whose cause is gone from the state by any road", () => {
  const c = seeded();
  const more = [5, 6, 7].map((n) => ({ ...DEP, slug: `built-on-foo-${n}`, repo_id: 920000010 + n, account: `dep${n}`, owner_id: 800000010 + n }));
  c.sign({ candidates: more.map(candidate) });
  // A revoke that is not for security: its row may leave the list without a
  // lift (clients release it by absence). A security revoke's may not, and
  // the same edit then refuses the run (sticky-row-vanished, sign.test.mjs).
  c.sign({ acts: [act("M_REVOKE", { repo_id: FOO.repo_id, versions: "0.1.0", reason_code: "policy" })] });
  assert.equal(stateOf(c).held.length, 2);
  // the cause leaves without a lift (a state edit, as the ops stand's --state-only makes)
  const w = stateOf(c);
  w.rows = w.rows.filter((x) => !(x.repo_id === FOO.repo_id && x.act === "revoke"));
  fs.writeFileSync(path.join(c.data, "withdrawn.json"), JSON.stringify(w));
  const next = c.sign({ now: T0 + DAY + 1 });
  assert.deepEqual(next.admitted, []);
  assert.deepEqual(stateOf(c).held, []);
  // while the cause stands, a held cascade takedown IS admitted when the window has room
  const d = seeded();
  d.sign({ candidates: more.map(candidate) });
  d.sign({ acts: [act("M_REVOKE", { repo_id: FOO.repo_id, versions: "0.1.0", reason_code: "security" })] });
  assert.equal(d.sign({ now: T0 + DAY + 1 }).admitted.length, 2);
});

test("M_LIFT names a takedown still HELD over the bound and drops it; nothing was published, so no lift is written", () => {
  const c = seeded();
  const take = (repo_id) => act("M_YANK", { repo_id, versions: "*", reason_code: "broken" });
  c.sign({ acts: [take(GI.repo_id), take(FOO.repo_id), take(SUCC.repo_id), take(DEP.repo_id)] });
  assert.equal(stateOf(c).held.length, 1);
  const r = c.sign({ acts: [lift({ repo_id: DEP.repo_id, versions: "*", kinds: ["yank"] })] });
  assert.deepEqual(r.refusedActs, []);
  assert.deepEqual(r.acts[0].summary, { lifted: [], repo_id: DEP.repo_id, versions: "*", lifts_at: T0, dropped_held: ["yank"] });
  assert.deepEqual(stateOf(c).held, []);
  assert.deepEqual(withdrawnOf(c).lifts, [], "no client ever saw the row");
  assert.equal(withdrawnOf(c).rows.length, 3);
  assert.equal(c.sign({ now: T0 + DAY + 1 }).admitted.length, 0);
  // a cascade's banner is published and its yank held: one lift takes the row and the hold, and IS written
  const p = seeded();
  p.sign({ acts: [take(GI.repo_id), take(SUCC.repo_id), act("M_REVOKE", { repo_id: FOO.repo_id, versions: "0.1.0", reason_code: "broken" })] });
  assert.deepEqual(stateOf(p).held.map((h) => [h.row.repo_id, h.row.act]), [[DEP.repo_id, "yank"]]);
  const q = p.sign({ acts: [lift({ repo_id: DEP.repo_id, entry_id: "third/built-on-foo", versions: "1.0.0", kinds: ["deprecate", "yank"] })] });
  assert.deepEqual(q.acts[0].summary.lifted, ["deprecate"]);
  assert.deepEqual(q.acts[0].summary.dropped_held, ["yank"]);
  assert.deepEqual(stateOf(p).held, []);
  assert.deepEqual(withdrawnOf(p).lifts.map((x) => x.entry_id), ["third/built-on-foo"]);
  assert.deepEqual(verified(p), [[], []]);
});

// ── the bounds: takedowns by apply time (finding 6), security lifts (finding 7) ──

test("the takedown bound counts a lifted takedown: revoking and lifting is no way around 3 in 24 hours", () => {
  const c = seeded();
  const take = (repo_id) => act("M_YANK", { repo_id, versions: "*", reason_code: "broken" });
  c.sign({ acts: [take(GI.repo_id), take(FOO.repo_id), take(SUCC.repo_id)] });
  assert.equal(withdrawnOf(c).rows.length, 3);
  // one of the three is lifted, and a fourth unit is taken down within the window
  const r = c.sign({ now: T0 + 3600, acts: [lift({ versions: "*", kinds: ["yank"] }, T0 + 3600), act("M_YANK", { repo_id: DEP.repo_id, versions: "*", reason_code: "broken" }, T0 + 3600)] });
  assert.deepEqual(r.refusedActs, []);
  assert.equal(withdrawnOf(c).rows.length, 2, "the lifted row left, and the fourth takedown did not get its unit");
  assert.equal(stateOf(c).held.length, 1);
  // the same unit again costs nothing, as before the lift
  c.sign({ now: T0 + 7200, acts: [act("M_YANK", { repo_id: GI.repo_id, versions: "*", reason_code: "broken" }, T0 + 7200)] });
  assert.equal(withdrawnOf(c).rows.length, 3);
  // a day after the first three, the held one is admitted
  c.sign({ now: T0 + DAY + 1 });
  assert.equal(stateOf(c).held.length, 0);
  assert.equal(withdrawnOf(c).rows.length, 4);
});

test("the takedown bound counts by when the signer applies an act, not by the act's own at: five revokes dated two days back", () => {
  const c = seeded();
  const more = [5, 6].map((n) => ({ ...GI, slug: `other-${n}`, repo_id: 920000020 + n, account: `other${n}`, owner_id: 800000020 + n }));
  c.sign({ candidates: more.map(candidate) });
  const old = (repo_id) => act("M_REVOKE", { repo_id, versions: "*", reason_code: "security" }, T0 - 2 * DAY);
  const r = c.sign({ acts: [GI.repo_id, SUCC.repo_id, DEP.repo_id, 920000025, 920000026].map(old) });
  assert.deepEqual(r.refusedActs, []);
  assert.deepEqual(r.acts.map((a) => [a.summary.applied, a.summary.held]), [[1, 0], [1, 0], [1, 0], [0, 1], [0, 1]]);
  assert.equal(withdrawnOf(c).rows.length, 3);
  assert.deepEqual(withdrawnOf(c).rows.map((x) => x.at), [T0 - 2 * DAY, T0 - 2 * DAY, T0 - 2 * DAY], "the rows keep the acts' second");
  assert.deepEqual(stateOf(c).spent.map((s) => s.at), [T0, T0, T0], "and the units are spent now");
  // a row written before the ledger (no act_ref) still counts by its at, as it always did
  const legacy = seeded();
  const w = stateOf(legacy);
  w.rows = [{ repo_id: GI.repo_id, versions: "*", act: "yank", floor_effect: "no-offer", reason_code: "broken", at: T0 - 3600 }];
  delete w.spent;
  fs.writeFileSync(path.join(legacy.data, "withdrawn.json"), JSON.stringify(w));
  const take = (repo_id) => act("M_YANK", { repo_id, versions: "*", reason_code: "broken" });
  legacy.sign({ acts: [take(FOO.repo_id), take(SUCC.repo_id), take(DEP.repo_id)] });
  assert.equal(stateOf(legacy).held.length, 1);
});

test(`lifts of security revokes are bounded: ${LIFT_LIMIT} in 24 hours by apply time, the next is refused (not held) and says when`, () => {
  const c = seeded();
  const more = [5].map((n) => ({ ...GI, slug: `other-${n}`, repo_id: 920000020 + n, account: `other${n}`, owner_id: 800000020 + n }));
  c.sign({ candidates: more.map(candidate) });
  const repos = [GI.repo_id, SUCC.repo_id, DEP.repo_id, 920000025];
  c.sign({ acts: repos.map((repo_id) => act("M_REVOKE", { repo_id, versions: "*", reason_code: "security", break_glass: true })) });
  assert.equal(withdrawnOf(c).rows.length, 4);
  const r = c.sign({ now: T0 + 100, acts: repos.map((repo_id) => lift({ repo_id, versions: "*" }, T0 + 100)) });
  assert.equal(r.acts.length, 3);
  assert.deepEqual(problemsOf(r), [[`the lift bound: 3 security revokes were lifted in the last 24 hours and at most 3 may be; this lift is refused, not held, and can be taken again from ${new Date((T0 + 100 + DAY) * 1000).toISOString().slice(0, 19)}Z`]]);
  assert.deepEqual(withdrawnOf(c).rows.map((x) => x.repo_id), [920000025], "the fourth security revoke is still in force");
  assert.deepEqual(stateOf(c).held, [], "refused, not held");
  // a lift of a row that is not sticky is not counted and not bounded
  c.sign({ now: T0 + 200, acts: [act("M_DEPRECATE", { repo_id: FOO.repo_id, versions: "*", reason_code: "broken" }, T0 + 200)] });
  assert.deepEqual(c.sign({ now: T0 + 300, acts: [lift({ repo_id: FOO.repo_id, versions: "*", lifts_at: T0 + 200, kinds: ["deprecate"] }, T0 + 300)] }).refusedActs, []);
  // one second before the window ends it is still refused; at the second the refusal named, applied
  assert.equal(c.sign({ now: T0 + 99 + DAY, acts: [lift({ repo_id: 920000025, versions: "*" }, T0 + 99 + DAY)] }).refusedActs.length, 1);
  assert.deepEqual(c.sign({ now: T0 + 100 + DAY, acts: [lift({ repo_id: 920000025, versions: "*" }, T0 + 100 + DAY)] }).refusedActs, []);
  assert.deepEqual(withdrawnOf(c).rows.filter((x) => x.act === "revoke"), []);
  // lifts of rows that are not sticky never count toward it, however many
  const n = seeded();
  const banners = [];
  for (let i = 0; i < 4; i++) {
    banners.push(act("M_DEPRECATE", { repo_id: FOO.repo_id, versions: `<0.0.${i + 1}`, reason_code: "broken" }));
    banners.push(lift({ repo_id: FOO.repo_id, versions: `<0.0.${i + 1}`, kinds: ["deprecate"] }));
  }
  assert.deepEqual(n.sign({ acts: [ACTS.M_REVOKE(), ...banners, lift()] }).refusedActs, []);
  assert.deepEqual(withdrawnOf(n).rows, []);
  // a back-dated lift does not escape: the bound counts when the signer applied the others
  const d = seeded();
  d.sign({ candidates: more.map(candidate) });
  d.sign({ acts: repos.map((repo_id) => act("M_REVOKE", { repo_id, versions: "*", reason_code: "security", break_glass: true }, T0 - 3 * DAY)) });
  const back = d.sign({ acts: repos.map((repo_id) => lift({ repo_id, versions: "*", lifts_at: T0 - 3 * DAY }, T0 - 2 * DAY)) });
  assert.equal(back.acts.length, 3);
  assert.equal(back.refusedActs.length, 1);
});

// ── retention (finding 4) ────────────────────────────────────────────────────

test("retention: 256 banner-and-lift pairs do not push a security revoke's lift out of the list", () => {
  const c = revoked();
  c.sign({ acts: [lift()] });
  const security = withdrawnOf(c).lifts[0];
  // 256 deprecations of 256 subjects, each lifted: the churn of ordinary moderation
  const acts = [];
  for (let i = 0; i < LIFTS_MAX; i++) {
    acts.push(act("M_DEPRECATE", { repo_id: FOO.repo_id, versions: `<0.0.${i + 1}`, reason_code: "broken" }, T0 + 100));
    acts.push(lift({ repo_id: FOO.repo_id, versions: `<0.0.${i + 1}`, lifts_at: T0 + 100, kinds: ["deprecate"] }, T0 + 200 + i));
  }
  const r = c.sign({ now: T0 + 1000, acts });
  assert.deepEqual(r.refusedActs, []);
  assert.equal(r.acts.length, 2 * LIFTS_MAX);
  const lifts = withdrawnOf(c).lifts;
  assert.equal(lifts.length, LIFTS_MAX);
  assert.deepEqual(lifts[0], security, "the security lift, the oldest of them all, is still served");
  assert.equal(stateOf(c).lifts.filter((l) => !l.sticky).length, LIFTS_MAX - 1, "the oldest banner's lift made room: no client needs it");
  assert.equal(stateOf(c).lifts.length, LIFTS_MAX, "the state holds what the list serves");
  assert.deepEqual(verified(c), [[], []]);
});

test("retention order: a lift of a non-sticky row first, then a security lift older than 365 days, never a younger one", () => {
  const mk = (i, sticky, at) => ({ repo_id: 5, versions: `<0.0.${i}`, lifts_at: at - 10, at, sticky, lifted: [sticky ? "revoke" : "yank"] });
  const now = T0;
  const young = Array.from({ length: LIFTS_MAX }, (_, i) => mk(i, true, now - 1000 + i));
  assert.equal(retainLifts(young, now).length, LIFTS_MAX);
  // one over, with one non-sticky lift anywhere: that one goes, even though it is the newest
  const withBanner = [...young, mk(999, false, now)];
  assert.ok(retainLifts(withBanner, now).every((l) => l.sticky));
  // one over, all sticky, one of them a year old: the old one goes
  const withOld = [mk(998, true, now - LIFT_KEEP_SECONDS), ...young];
  assert.deepEqual(retainLifts(withOld, now).map((l) => l.versions), young.map((l) => l.versions));
  // one second short of a year, it stays: the list is over, and that is the act's refusal, below
  const almost = [mk(998, true, now - LIFT_KEEP_SECONDS + 1), ...young];
  assert.equal(retainLifts(almost, now).length, LIFTS_MAX + 1);
  // two non-sticky: the older leaves first
  const two = [...young.slice(2), mk(1, false, now - 50), mk(2, false, now - 60), mk(3, false, now - 40)];
  assert.deepEqual(retainLifts(two, now).filter((l) => !l.sticky).map((l) => l.at), [now - 50, now - 40]);
  // a record that does not say (an older state) is kept as if it were sticky
  const unknown = [...young, { repo_id: 5, versions: "*", lifts_at: 1, at: now - 5 }];
  assert.equal(retainLifts(unknown, now).length, LIFTS_MAX + 1);
});

test("a full list of young security lifts: the next security lift is refused, a banner's lift is applied and simply not kept", () => {
  const c = seeded();
  c.sign({ acts: [ACTS.M_REVOKE(), act("M_DEPRECATE", { repo_id: FOO.repo_id, versions: "*", reason_code: "broken" })] });
  const w = stateOf(c);
  w.lifts = Array.from({ length: LIFTS_MAX }, (_, i) => ({ repo_id: 5, versions: `<0.0.${i}`, lifts_at: T0 - 9 * DAY, at: T0 - 8 * DAY + i, applied_at: T0 - 8 * DAY, by: "mod-1", reason_text: "x", lifted: ["revoke"], sticky: true }));
  fs.writeFileSync(path.join(c.data, "withdrawn.json"), JSON.stringify(w));
  const r = c.sign({ acts: [lift(), lift({ repo_id: FOO.repo_id, versions: "*", kinds: ["deprecate"] })] });
  assert.deepEqual(problemsOf(r), [[`the lift list is full: it holds ${LIFTS_MAX} lifts of security revokes, none older than 365 days, and one of those is never dropped for another`]]);
  assert.deepEqual(r.acts.map((a) => a.summary.lifted), [["deprecate"]]);
  assert.deepEqual(withdrawnOf(c).rows.map((x) => x.act), ["revoke"], "the security revoke stays in force; the banner left");
  assert.equal(withdrawnOf(c).lifts.length, LIFTS_MAX);
  assert.ok(stateOf(c).lifts.every((l) => l.sticky), "the banner's lift was not kept: its row's absence is its release");
  assert.deepEqual(verified(c), [[], []]);
  // once one of them is a year old, the security lift is applied and takes its place
  const y = stateOf(c);
  const aged = y.lifts[0];
  aged.applied_at = T0 - LIFT_KEEP_SECONDS; // a year since the signer applied it; its own at says eight days
  fs.writeFileSync(path.join(c.data, "withdrawn.json"), JSON.stringify(y));
  assert.deepEqual(c.sign({ acts: [lift()] }).refusedActs, []);
  assert.equal(withdrawnOf(c).lifts.length, LIFTS_MAX);
  assert.ok(withdrawnOf(c).lifts.some((l) => l.repo_id === GI.repo_id));
  assert.ok(!withdrawnOf(c).lifts.some((l) => l.repo_id === aged.repo_id && l.versions === aged.versions), "the one applied a year ago made room");
});

test("the list never carries more than 256 lifts, whatever the state holds", () => {
  const state = (n) => ({ withdrawn: { rows: [], held: [], lifts: Array.from({ length: n }, (_, i) => ({ repo_id: 5, versions: "*", lifts_at: 1000 + i, at: 5000 + (n - i), sticky: true })) } });
  const body = (n) => buildWithdrawnBody({ state: state(n), issuedAt: T0, keyId: "games-current" });
  assert.equal(body(LIFTS_MAX).lifts.length, LIFTS_MAX);
  assert.equal(body(LIFTS_MAX + 3).lifts.length, LIFTS_MAX);
  assert.deepEqual(Object.keys(body(1).lifts[0]).sort(), ["at", "lifts_at", "repo_id", "versions"]);
});

// ── review round 2: the clock for every act (N1), an honest trial (N2), a lift's age (N3), a legacy unit (N4), kinds (finding 5) ──

const AHEAD = (seconds) => `at is ${seconds} seconds ahead of the signer's clock; an act is dated when it was taken (at most ${ACT_CLOCK_SKEW} seconds of skew)`;
const MILLIS = "at is Unix seconds, not milliseconds";
const FULL = `the lift list is full: it holds ${LIFTS_MAX} lifts of security revokes, none older than 365 days, and one of those is never dropped for another`;
const youngSecurityLifts = (n) => Array.from({ length: n }, (_, i) => ({ repo_id: 5, versions: `<0.0.${i}`, lifts_at: T0 - 9 * DAY, at: T0 - 8 * DAY + i, applied_at: T0 - 8 * DAY, by: "mod-1", reason_text: "x", lifted: ["revoke"], sticky: true }));
const writeWithdrawn = (c, w) => fs.writeFileSync(path.join(c.data, "withdrawn.json"), JSON.stringify(w));

for (const type of Object.keys(ACTS)) {
  test(`${type} dated ahead of the signer's clock, or in milliseconds, is refused; dated at the skew it is applied (N1)`, () => {
    const c = seeded();
    const setup = BEFORE[type]?.() ?? [];
    if (setup.length) assert.deepEqual(c.sign({ acts: setup }).refusedActs, []);
    const now = T0 + 100;
    const ahead = c.sign({ now, acts: [{ ...ACTS[type](), at: now + ACT_CLOCK_SKEW + 1 }] });
    assert.deepEqual(problemsOf(ahead), [[AHEAD(ACT_CLOCK_SKEW + 1)]]);
    assert.deepEqual(ahead.acts, []);
    const millis = c.sign({ now, acts: [{ ...ACTS[type](), at: now * 1000 }] });
    assert.deepEqual(problemsOf(millis), [[MILLIS]]);
    assert.deepEqual(millis.acts, []);
    assert.deepEqual(c.sign({ now, acts: [{ ...ACTS[type](), at: now + ACT_CLOCK_SKEW }] }).refusedActs, []);
  });
}

test("at is Unix seconds: where milliseconds begin, and what is no integer at all (N1)", () => {
  const empty = { entries: [], withdrawn: { rows: [], held: [] }, holds: [], engineCodes: {} };
  const yank = (at) => actProblems({ ...ACTS.M_YANK(), at }, empty);
  assert.deepEqual(yank(1e11 - 1), [], "without a clock (the service's half) only the shape of at is judged");
  assert.deepEqual(yank(1e11), [MILLIS]);
  assert.deepEqual(yank(Number.MAX_SAFE_INTEGER), [MILLIS], "the reviewer's 2^53 - 1");
  assert.deepEqual(yank(2 ** 53), ["at is not Unix seconds"]);
  assert.deepEqual(yank(0), ["at is not Unix seconds"]);
  assert.deepEqual(yank(T0 + 0.5), ["at is not Unix seconds"]);
});

test("a withdrawal dated in the future is refused; dated at the skew it is published and can still be lifted (N1)", () => {
  const c = seeded();
  const revoke = (at) => act("M_REVOKE", { repo_id: GI.repo_id, versions: "<=1.0.0", reason_code: "security" }, at);
  // the reviewer's case: a security revoke dated ten days ahead would be published and never liftable
  const far = c.sign({ acts: [revoke(T0 + 10 * DAY)] });
  assert.deepEqual(problemsOf(far), [[AHEAD(10 * DAY)]]);
  assert.deepEqual(withdrawnOf(c).rows, []);
  assert.deepEqual(stateOf(c).held, []);
  // five minutes ahead is another machine's clock: published, with the act's second
  assert.deepEqual(c.sign({ acts: [revoke(T0 + ACT_CLOCK_SKEW)] }).refusedActs, []);
  assert.deepEqual(withdrawnOf(c).rows.map((r) => [r.act, r.at]), [["revoke", T0 + ACT_CLOCK_SKEW]]);
  // and it is liftable at once, on the same clock
  assert.deepEqual(c.sign({ acts: [lift({ lifts_at: T0 + ACT_CLOCK_SKEW }, T0 + ACT_CLOCK_SKEW)] }).refusedActs, []);
  assert.deepEqual(withdrawnOf(c).rows, []);
  assert.deepEqual(withdrawnOf(c).lifts, [{ repo_id: GI.repo_id, versions: "<=1.0.0", lifts_at: T0 + ACT_CLOCK_SKEW, at: T0 + ACT_CLOCK_SKEW }]);
  assert.deepEqual(verified(c), [[], []]);
});

test("an act whose text the documents cannot carry (half a surrogate pair) is refused at the trial, and the run goes on and signs (N2)", () => {
  const c = seeded();
  const NOWHERE = 930000001;
  const half = "\ud83d";
  const r = c.sign({ acts: [
    act("M_YANK", { repo_id: GI.repo_id, versions: "*", reason_code: "broken", reason_text: `Crashes on start ${half}` }),
    act("M_REVOKE", { repo_id: NOWHERE, entry_id: `someone/peak-${half}`, versions: "*", reason_code: "security" }),
    act("M_ANTICHEAT_EDIT", { op: "add", row: { name: `Some Anti-Cheat ${half}`, kind: "folder-marker", value: "SomeAC" } }), // the index, not the list
    ACTS.M_DEPRECATE(),
  ] });
  assert.equal(r.refusedActs.length, 3);
  assert.match(problemsOf(r)[0][0], /\$\.rows\[0\]\.reason_text: carries an unpaired surrogate/);
  assert.match(problemsOf(r)[1][0], /\$\.rows\[0\]\.entry_id: carries an unpaired surrogate/);
  assert.match(problemsOf(r)[2][0], /\$\.anticheat\[0\]\.name: carries an unpaired surrogate/);
  for (const [p] of problemsOf(r)) assert.match(p, /^applied, this act would leave documents that cannot be signed: /);
  assert.deepEqual(r.acts.map((a) => a.type), ["M_DEPRECATE"], "the act after them is applied");
  assert.deepEqual(withdrawnOf(c).rows.map((x) => x.act), ["deprecate"]);
  assert.deepEqual(stateOf(c).spent ?? [], [], "a refused takedown spends nothing");
  assert.deepEqual(verified(c), [[], []]);
});

test("the trial blames an act only for what it brought: a throw while applying is a refusal, a state that already could not be signed is not (N2)", () => {
  const c = seeded();
  const state = loadState(c.data);
  const o = { now: T0, reserved: undefined, seedLoaders: { add: [], remove: [] }, previous: null };
  assert.equal(unsignable(state, o), null);
  // anything thrown while applying
  const unknown = tryAct({ ...ACTS.M_DEPRECATE(), type: "M_NOPE" }, state, o);
  assert.deepEqual(unknown.problems, ["applied to a copy of the state, this act stopped the signer: no applier for M_NOPE"]);
  // a good act on a good state
  const good = tryAct(ACTS.M_DEPRECATE(), state, o);
  assert.equal(good.problems, undefined);
  assert.equal(good.state.withdrawn.rows.length, 1);
  assert.equal(state.withdrawn.rows.length, 0, "the state itself is not touched");
  // a state that cannot be signed before the act: the act is applied, the run stops at signing as it would have
  const broken = structuredClone(state);
  broken.withdrawn.rows.push({ repo_id: 5, versions: "*", act: "deprecate", floor_effect: "no-offer", reason_code: "broken", reason_text: "\ud83d", at: T0 - 5 });
  assert.match(unsignable(broken, o), /surrogate/i);
  assert.equal(tryAct(ACTS.M_DEPRECATE(), broken, o).problems, undefined);
});

test("the move to a free second stops at the signer's clock plus the skew: past it the act is refused, not dated where it could never be lifted (N2)", () => {
  const c = seeded();
  const w = stateOf(c);
  // one subject carrying a row in every second an act taken now may use
  w.rows = Array.from({ length: ACT_CLOCK_SKEW + 1 }, (_, i) => ({ repo_id: GI.repo_id, versions: "*", act: i % 2 ? "delist" : "deprecate", floor_effect: "no-offer", reason_code: "broken", at: T0 + i }));
  writeWithdrawn(c, w);
  const yank = () => act("M_YANK", { repo_id: GI.repo_id, versions: "*", reason_code: "broken" });
  const r = c.sign({ acts: [yank(), ACTS.M_REVOKE()] });
  assert.deepEqual(problemsOf(r), [[`no second is free for a row of repository ${GI.repo_id} *: every second from ${T0} to the signer's clock plus ${ACT_CLOCK_SKEW} seconds carries a row or a lift of that subject already, and a row dated later could never be lifted; take the act again later`]]);
  assert.deepEqual(r.acts.map((a) => a.type), ["M_REVOKE"], "the run goes on");
  assert.equal(withdrawnOf(c).rows.length, ACT_CLOCK_SKEW + 2);
  assert.deepEqual(verified(c, T0 + ACT_CLOCK_SKEW), [[], []]);
  // one second later there is one: the last the clock allows
  const later = c.sign({ now: T0 + 1, acts: [yank()] });
  assert.deepEqual(later.refusedActs, []);
  assert.equal(later.acts[0].summary.at, T0 + 1 + ACT_CLOCK_SKEW);
});

test("the move never leaves the integers JSON carries: at 2^53 - 1 it refuses, and it ends (N2)", () => {
  const top = Number.MAX_SAFE_INTEGER;
  const state = { entries: [], withdrawn: { rows: [{ repo_id: 5, versions: "*", act: "deprecate", floor_effect: "no-offer", reason_code: "broken", at: top }], held: [], lifts: [], spent: [] } };
  assert.throws(() => applyAct(act("M_DEPRECATE", { repo_id: 5, versions: "*", reason_code: "policy" }, top), state, { now: top }), ActRefused);
  assert.deepEqual(state.withdrawn.rows.map((r) => r.at), [top]);
  // and one below the top it takes the top, the last integer there is
  state.withdrawn.rows[0].at = top - 1;
  assert.equal(applyAct(act("M_DEPRECATE", { repo_id: 5, versions: "*", reason_code: "policy" }, top - 1), state, { now: top }).at, top);
});

test("a lift is aged from when the signer applied it, never from its own at: dated 400 days back into a full list it is refused, not accepted and dropped unpublished (N3)", () => {
  const c = seeded();
  const old = T0 - 400 * DAY;
  const w = stateOf(c);
  w.rows = [{ ...REVOKE_ROW, at: old }];
  w.lifts = youngSecurityLifts(LIFTS_MAX);
  writeWithdrawn(c, w);
  // the reviewer's case: at = lifts_at, 400 days ago; by its own date it is "older than 365 days" the moment it lands
  const r = c.sign({ acts: [lift({ lifts_at: old }, old)] });
  assert.deepEqual(problemsOf(r), [[FULL]]);
  assert.deepEqual(withdrawnOf(c).rows.map((x) => [x.act, x.at]), [["revoke", old]], "the revoke is still in force, and says so");
  assert.equal(withdrawnOf(c).lifts.length, LIFTS_MAX);
  assert.ok(!withdrawnOf(c).lifts.some((l) => l.repo_id === GI.repo_id));
  // With room for one it is applied, published, and from then on as young as the day it was applied.
  // Room is made by a lift a year old: one the last list carried cannot simply be taken out of the
  // state (sticky-lift-vanished, sign.test.mjs).
  const y = stateOf(c);
  y.lifts[0].applied_at = T0 - LIFT_KEEP_SECONDS;
  writeWithdrawn(c, y);
  assert.deepEqual(c.sign({ acts: [lift({ lifts_at: old }, old)] }).refusedActs, []);
  assert.deepEqual(withdrawnOf(c).lifts[0], { repo_id: GI.repo_id, versions: "<=1.0.0", lifts_at: old, at: old }, "published, the oldest by its date");
  assert.equal(stateOf(c).lifts.find((l) => l.repo_id === GI.repo_id).applied_at, T0);
  // the next security lift finds the list full: the old-dated one is not the one that makes room
  c.sign({ acts: [act("M_REVOKE", { repo_id: GI.repo_id, versions: "*", reason_code: "security" })] });
  assert.deepEqual(problemsOf(c.sign({ acts: [lift({ versions: "*" })] })), [[FULL]]);
  assert.ok(withdrawnOf(c).lifts.some((l) => l.repo_id === GI.repo_id && l.lifts_at === old), "the lift dated 400 days back is still served");
  assert.deepEqual(verified(c), [[], []]);
});

test("a lifted takedown written before the ledger (no act_ref) stays spent: lifting it gives no unit back (N4)", () => {
  const c = seeded();
  const w = stateOf(c);
  w.rows = [GI, FOO, SUCC].map((x) => ({ repo_id: x.repo_id, versions: "*", act: "yank", floor_effect: "no-offer", reason_code: "broken", at: T0 - 3600 }));
  delete w.spent;
  writeWithdrawn(c, w);
  const r = c.sign({ acts: [lift({ versions: "*", lifts_at: T0 - 3600, kinds: ["yank"] }), act("M_YANK", { repo_id: DEP.repo_id, versions: "*", reason_code: "broken" })] });
  assert.deepEqual(r.refusedActs, []);
  assert.deepEqual(r.acts[0].summary.lifted, ["yank"]);
  assert.deepEqual([r.acts[1].summary.applied, r.acts[1].summary.held], [0, 1], "the fourth unit of the window is held: the lifted one still counts");
  assert.deepEqual(stateOf(c).spent, [{ unit: `${GI.repo_id}#*`, at: T0 - 3600 }], "counted from the row's own second, as the row was");
  // a banner written before the ledger was never a unit, and lifting it spends none
  const b = seeded();
  const wb = stateOf(b);
  wb.rows = [{ repo_id: GI.repo_id, versions: "*", act: "deprecate", floor_effect: "no-offer", reason_code: "broken", at: T0 - 3600 }];
  delete wb.spent;
  writeWithdrawn(b, wb);
  b.sign({ acts: [lift({ versions: "*", lifts_at: T0 - 3600, kinds: ["deprecate"] })] });
  assert.deepEqual(stateOf(b).spent ?? [], []);
});

test("M_LIFT says what it lifts: copying an act's own at, where that act's row had moved to the next second, does not lift another act's row (finding 5)", () => {
  const c = seeded();
  c.sign({ acts: [act("M_REVOKE", { repo_id: GI.repo_id, versions: "*", reason_code: "security" }), act("M_DELIST", { repo_id: GI.repo_id, versions: "*", reason_code: "policy" })] });
  assert.deepEqual(withdrawnOf(c).rows.map((x) => [x.act, x.at]), [["revoke", T0], ["delist", T0 + 1]]);
  // the reviewer's case: the moderator means the delist and names the second of the delist ACT, where the security revoke sits
  const r = c.sign({ acts: [lift({ versions: "*", lifts_at: T0, kinds: ["delist"] })] });
  assert.deepEqual(problemsOf(r), [[`kinds [delist] is not what this lift would remove: the rows of that subject taken at ${T0} are [revoke]; a lift removes all of them and nothing else, so name exactly those, or the second of the row that was meant`]]);
  assert.deepEqual(withdrawnOf(c).rows.map((x) => [x.act, x.at]), [["revoke", T0], ["delist", T0 + 1]], "the security revoke is still in force");
  assert.deepEqual(withdrawnOf(c).lifts, []);
  // by the row's own second it is the delist that leaves
  const ok = c.sign({ acts: [lift({ versions: "*", lifts_at: T0 + 1, kinds: ["delist"] })] });
  assert.deepEqual(ok.refusedActs, []);
  assert.deepEqual(withdrawnOf(c).rows.map((x) => x.act), ["revoke"]);
  // the act log says what was expected; the signed list does not gain the member (a client matches by subject and second)
  assert.deepEqual(ok.acts[0].kinds, ["delist"]);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(c.data, "acts", "000003.json"), "utf8")).kinds, ["delist"]);
  assert.deepEqual(withdrawnOf(c).lifts, [{ repo_id: GI.repo_id, versions: "*", lifts_at: T0 + 1, at: T0 + 60 }]);
  assert.deepEqual(verified(c), [[], []]);
});

test("kinds is exactly the rows of that subject and second, published or held: a part of them, or more, is refused and names both sets", () => {
  const dep = { repo_id: DEP.repo_id, entry_id: "third/built-on-foo", versions: "1.0.0" };
  const told = (kinds, there) => `kinds [${[...kinds].sort().join(", ")}] is not what this lift would remove: the rows of that subject taken at ${T0} are [${there}]; a lift removes all of them and nothing else, so name exactly those, or the second of the row that was meant`;
  // a cascade's banner and yank, both published
  const c = seeded();
  c.sign({ acts: [act("M_REVOKE", { repo_id: FOO.repo_id, versions: "0.1.0", reason_code: "broken" })] });
  for (const kinds of [["yank"], ["deprecate"], ["revoke"], ["yank", "deprecate", "revoke"]]) {
    assert.deepEqual(problemsOf(c.sign({ acts: [lift({ ...dep, kinds })] })), [[told(kinds, "deprecate, yank")]], kinds.join());
  }
  assert.equal(withdrawnOf(c).rows.length, 3);
  assert.deepEqual(c.sign({ acts: [lift({ ...dep, kinds: ["yank", "deprecate"] })] }).refusedActs, [], "in any order");
  assert.equal(withdrawnOf(c).rows.length, 1);
  // the banner published and the yank held over the bound: the held one is part of what the lift removes
  const take = (repo_id) => act("M_YANK", { repo_id, versions: "*", reason_code: "broken" });
  const p = seeded();
  p.sign({ acts: [take(GI.repo_id), take(SUCC.repo_id), act("M_REVOKE", { repo_id: FOO.repo_id, versions: "0.1.0", reason_code: "broken" })] });
  assert.deepEqual(stateOf(p).held.map((h) => h.row.act), ["yank"]);
  assert.deepEqual(problemsOf(p.sign({ acts: [lift({ ...dep, kinds: ["deprecate"] })] })), [[told(["deprecate"], "deprecate, yank")]]);
  assert.equal(stateOf(p).held.length, 1);
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
