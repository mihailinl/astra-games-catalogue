// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// THE SIGN GATE (plugins 0144, bead minice-71s): the sign job lists ONLY
// candidates whose request.lease_id is in the work answer's `signable`, the
// leases the plugins service would settle as signed now. Absent or malformed
// lists none; acts, health and the re-sign go on, and nothing listed moves.
//
// Mutations (2026-11-14), each run against this file, each fails at least one
// test here:
//   C1 gateCandidates admits every candidate (`allowed === null ||` in front)  -> "absent signable" fails
//   C2 gateCandidates ignores membership (`allowed !== null && lease !== null`) -> "outside the set" fails
//   C3 checkSignable keeps a list holding a non-lease item                      -> "malformed" fails
//   C4 checkSignable drops the MAX_SIGNABLE bound                               -> "malformed" fails
//   C5 readWorkFiles reads signable.json without checkSignable                  -> "the files" fails
//   C6 signWork stops writing signable.json                                     -> "sign-work writes" fails
//   C7 sign.yml stops passing --signable                                        -> "sign.yml passes" fails
//   C8 runSign defaults signable to "everything" (`signable = undefined` -> all) -> "the compiled default" fails
//   C9 gateCandidates drops `&& !taken.has(lease)` (a second candidate of a lease is admitted) -> "duplicate" fails
//   C10 sign.yml's download path differs from the upload / sign-work --out directory           -> "work artifact path" fails
//   C11 readWorkFiles drops the age check (`now - readAt > SIGNABLE_MAX_AGE_MS` never true)       -> "stale" fails
//   C12 readWorkFiles accepts the bare-list shape again                                       -> "the pre-stamp shape" fails

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { signWork } from "../bin/service.mjs";
import { readWorkFiles, SIGNABLE_MAX_AGE_MS } from "../bin/sign.mjs";
import { gateCandidates, runSign } from "../lib/pipeline.mjs";
import { checkSignable, MAX_ACCEPTED, MAX_SIGNABLE, readWork, signResultBody } from "../lib/service.mjs";
import { act, candidate, makeCatalogue } from "./catalogue.mjs";
import { ROOT, tmpdir } from "./helpers.mjs";

const listedIds = (c) => c.dist("games-index.json").signed.entries.map((e) => e.id);
const quiet = { log() {}, warn() {}, error() {} };

test("the sign gate: an absent signable (a service before 0144) lists NO new candidate, but acts and health still apply and nothing listed moves", () => {
  const c = makeCatalogue();
  const a = candidate({ slug: "kept" });
  c.sign({ candidates: [a] });
  assert.deepEqual(listedIds(c), ["author/kept"], "listed by an earlier run");

  const b = candidate({ slug: "new" });
  const victim = candidate({ slug: "victim" });
  c.sign({ candidates: [victim] });
  const r = c.sign({
    candidates: [b],
    signable: null,
    health: { "author/kept": { rating_avg: 400, rating_count: 2, open_reports_unanswered: 0, reports_sent: 0, reports_failed: 0 } },
    acts: [act("M_YANK", { repo_id: victim.request.repo_id, versions: "*", reason_code: "broken" })],
  });
  assert.deepEqual(r.accepted, [], "nothing accepted");
  assert.deepEqual(r.leftOut.map((l) => l.lease_id), [b.request.lease_id]);
  assert.match(r.leftOut[0].reason, /named no signable list/);
  assert.equal(r.acts.length, 1, "the act applied");
  assert.deepEqual(c.state("health.json"), { "author/kept": { rating_avg: 400, rating_count: 2, open_reports_unanswered: 0, reports_sent: 0, reports_failed: 0 } });
  assert.ok(listedIds(c).includes("author/kept"), "an entry listed before stays listed");
  assert.ok(!listedIds(c).includes("author/new"), "the new candidate is not listed");
  assert.deepEqual(signResultBody({ runId: 9, dataSha: "a".repeat(40), report: r }).accepted, [], "and no accepted[] item settles it");
});

test("the sign gate: a candidate outside the set is left out and reported; one inside is listed; the sign result names only the listed one", () => {
  const c = makeCatalogue();
  const inside = candidate({ slug: "inside" });
  const outside = candidate({ slug: "outside" });
  const unnamed = candidate({ slug: "unnamed" });
  delete unnamed.request.lease_id;
  const r = c.sign({ candidates: [inside, outside, unnamed], signable: [inside.request.lease_id, "some-other-lease"] });
  assert.deepEqual(r.accepted.map((a) => [a.request.lease_id, a.result]), [[inside.request.lease_id, "listed"]]);
  assert.deepEqual(r.leftOut.map((l) => l.lease_id), [outside.request.lease_id, null]);
  assert.match(r.leftOut[0].reason, /^not signable/);
  assert.deepEqual(listedIds(c), ["author/inside"]);
  const body = signResultBody({ runId: 9, dataSha: "a".repeat(40), report: r });
  assert.deepEqual(body.accepted.map((a) => a.request.lease_id), [inside.request.lease_id], "a left-out candidate is in no accepted[] item");
  assert.deepEqual(Object.keys(body).sort(), ["accepted", "acts", "data_sha", "issued_at", "key_id", "run_id", "schema"], "the sign result's shape is unchanged");
});

test("the sign gate: the compiled default is the refusing answer -- runSign without `signable` lists nothing", () => {
  const c = makeCatalogue();
  const x = candidate({ slug: "x" });
  const r = runSign({ dataDir: c.data, root: c.root, env: c.env, now: 1793448000, trustFile: c.trustFile, roots: c.roots, candidates: [x] });
  assert.deepEqual(r.accepted, []);
  assert.equal(r.leftOut.length, 1);
  assert.deepEqual(gateCandidates([x]).admitted, [], "gateCandidates' default too");
});

test("checkSignable / readWork: a list of lease ids is kept once each; absent, not a list, over MAX_SIGNABLE, or one item not a lease id is null (fail closed), and acts and health are still read", () => {
  assert.equal(MAX_SIGNABLE, MAX_ACCEPTED);
  assert.equal(MAX_SIGNABLE, 255);
  assert.deepEqual(checkSignable(["L1", "L2", "L1"]), { signable: ["L1", "L2"], signableProblem: null });
  assert.deepEqual(checkSignable([]).signable, [], "an empty list is the service's word: sign nothing new");
  const ids = (n) => Array.from({ length: n }, (_, i) => `L${i}`);
  assert.equal(checkSignable(ids(MAX_SIGNABLE)).signable.length, MAX_SIGNABLE);
  for (const [bad, why] of [
    [undefined, /no signable list/],
    [null, /not a list/],
    ["L1", /not a list/],
    [{ L1: true }, /not a list/],
    [ids(MAX_SIGNABLE + 1), /more than 255/],
    [["L1", "bad id"], /not a lease id/],
    [["L1", 7], /not a lease id/],
    [["L1", "x".repeat(65)], /not a lease id/],
    [["L1", ""], /not a lease id/],
  ]) {
    const r = checkSignable(bad);
    assert.equal(r.signable, null, JSON.stringify(bad)?.slice(0, 40));
    assert.match(r.signableProblem, why);
  }
  const w = readWork({ schema: "astra.games.work/1", acts: [{ type: "M_YANK" }], health: { a: 1 }, signable: ["L1", "bad id"] });
  assert.deepEqual([w.acts, w.health, w.signable], [[{ type: "M_YANK" }], { a: 1 }, null], "a malformed signable never fails the work read");
  assert.equal(readWork({ acts: [], health: null }).signable, null, "absent: an older service");
});

test("bin/sign.mjs reads signable.json again and fails closed: a list kept, absent, null, unreadable, malformed, unstamped, stale or future is null", () => {
  const dir = tmpdir();
  const NOW = Date.parse("2026-11-17T12:00:00Z");
  const file = (name, value) => {
    const p = path.join(dir, name);
    fs.writeFileSync(p, typeof value === "string" ? value : JSON.stringify(value));
    return p;
  };
  const at = (min) => new Date(NOW + min * 60000).toISOString();
  const read = (signableFile) => readWorkFiles({ actsFile: null, healthFile: null, signableFile, now: NOW });
  assert.deepEqual(read(file("ok.json", { read_at: at(-1), leases: ["L1", "L2"] })).signable, ["L1", "L2"]);
  assert.equal(read(file("ok.json", { read_at: at(-1), leases: ["L1"] })).signableProblem, null);
  assert.deepEqual(read(file("edge.json", { read_at: at(-19.9), leases: ["L1"] })).signable, ["L1"], "inside 20 minutes");
  assert.equal(read(null).signable, null);
  assert.equal(read(path.join(dir, "absent.json")).signable, null);
  assert.equal(read(file("null.json", "null")).signable, null);
  assert.equal(read(file("leases-null.json", { read_at: at(-1), leases: null })).signable, null);
  assert.equal(read(file("garbage.json", "{not json")).signable, null, "unreadable is not a refused run");
  assert.equal(read(file("bad.json", { read_at: at(-1), leases: ["L1", "../x"] })).signable, null);
  // Opus review of minice-71s (2026-11-17, S2): "Re-run failed jobs" reuses the work job's artifact without
  // asking the service again. A list older than SIGNABLE_MAX_AGE_MS, unstamped (the old bare-list shape) or
  // dated in the future signs nothing new, and says why.
  const stale = read(file("stale.json", { read_at: at(-21), leases: ["L1"] }));
  assert.equal(stale.signable, null);
  assert.match(stale.signableProblem, /more than 20 minutes ago/);
  assert.equal(SIGNABLE_MAX_AGE_MS, 20 * 60 * 1000, "under the service's requeue grace");
  const bare = read(file("bare.json", ["L1"]));
  assert.equal(bare.signable, null, "the pre-stamp shape is not trusted");
  assert.match(bare.signableProblem, /no read_at/);
  assert.equal(read(file("future.json", { read_at: at(6), leases: ["L1"] })).signable, null);
  assert.deepEqual(read(file("skew.json", { read_at: at(4), leases: ["L1"] })).signable, ["L1"], "a few minutes of clock skew is tolerated");
  assert.equal(read(file("bad-date.json", { read_at: "yesterday", leases: ["L1"] })).signable, null);
});

test("sign-work writes signable.json: the service's list, or null with a warning when it names none or a malformed one", async () => {
  const run = async (answer) => {
    const dir = tmpdir();
    const logs = [];
    const client = { async work() { return answer; } };
    await signWork({ out: path.join(dir, "w"), env: { GITHUB_RUN_ID: "4242", GITHUB_OUTPUT: path.join(dir, "out.txt") }, client, github: null, log: { ...quiet, log: (m) => logs.push(m) }, now: () => Date.parse("2026-11-17T12:00:00Z") });
    const written = JSON.parse(fs.readFileSync(path.join(dir, "w", "signable.json"), "utf8"));
    // stamped with the moment the service was asked, so the signer can refuse a stale re-run
    assert.equal(written.read_at, "2026-11-17T12:00:00.000Z");
    return { signable: written.leases, logs };
  };
  assert.deepEqual((await run({ acts: [], health: null, signable: ["L1"] })).signable, ["L1"]);
  const absent = await run({ acts: [], health: null });
  assert.equal(absent.signable, null);
  assert.ok(absent.logs.some((m) => /^::warning::the work answer names no signable list.*no new candidate is signed/.test(m)), absent.logs.join("\n"));
  assert.equal((await run({ acts: [], health: null, signable: ["L1", 2] })).signable, null);
});

test("sign.yml passes the work job's signable.json to the signer", () => {
  const yml = fs.readFileSync(path.join(ROOT, ".github", "workflows", "sign.yml"), "utf8");
  assert.match(yml, /node bin\/sign\.mjs [^\n]*--signable "\$RUNNER_TEMP\/work\/signable\.json"/);
});

test("a second candidate naming an already-admitted lease is left out as a duplicate: only the first is signed", () => {
  const first = candidate({ slug: "first" });
  const second = candidate({ slug: "second" });
  const lease = first.request.lease_id;
  second.request.lease_id = lease;
  const { admitted, leftOut } = gateCandidates([first, second], [lease]);
  assert.deepEqual(admitted, [first], "the first candidate of the lease only");
  assert.equal(leftOut.length, 1);
  assert.equal(leftOut[0].lease_id, lease);
  assert.match(leftOut[0].reason, /^duplicate lease/);
  assert.deepEqual(gateCandidates([second, first], [lease]).admitted, [second], "first in order wins, whichever it is");

  // and through the signer: the second never lists
  const c = makeCatalogue();
  const r = c.sign({ candidates: [first, second], signable: [lease] });
  assert.deepEqual(listedIds(c), ["author/first"]);
  assert.ok(r.leftOut.some((l) => /^duplicate lease/.test(l.reason)));
});

test("the sign.yml work artifact path is the one sign.mjs reads: sign-work --out, the upload, the download and --signable agree", () => {
  const yml = fs.readFileSync(path.join(ROOT, ".github", "workflows", "sign.yml"), "utf8");
  const out = /sign-work --out "\$RUNNER_TEMP\/(\w+)"/.exec(yml);
  assert.ok(out, "the work job names the directory sign-work writes");
  const dir = out[1];
  // the work job uploads that directory as games-work; the sign job downloads games-work into the same one
  const sections = [...yml.matchAll(/name: games-work\n\s+path: \$\{\{ runner\.temp \}\}\/(\w+)/g)].map((m) => m[1]);
  assert.deepEqual(sections, [dir, dir], "upload and download both use the directory sign-work writes");
  assert.match(yml, new RegExp(`--signable "\\$RUNNER_TEMP/${dir}/signable\\.json"`), "the signer reads signable.json from it");
  const service = fs.readFileSync(path.join(ROOT, "bin", "service.mjs"), "utf8");
  assert.match(service, /path\.join\(out, "signable\.json"\)/, "and sign-work writes that file name");
});
