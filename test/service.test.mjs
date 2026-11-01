// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The pull model's client (lib/service.mjs, bin/service.mjs), driven by a
// fake service and a fake GitHub: what the work job leases and writes, what
// the report job posts, and what never leaves this repository.

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { ingestReport, ingestWork, signReport, signWork } from "../bin/service.mjs";
import { readCandidates, readWorkFiles } from "../bin/sign.mjs";
import {
  clipBytes, DEFAULT_AUDIENCE, DEFAULT_BASE, ingestResultBody, oidcToken, projectCandidate, serviceBase, serviceClient, ServiceRefused, signResultBody,
} from "../lib/service.mjs";
import { tmpdir } from "./helpers.mjs";

const H = (c) => c.repeat(64);
const quiet = { log() {}, warn() {}, error() {} };

function fakeService(answers = {}) {
  const calls = [];
  const door = (name) => async (body) => {
    calls.push([name, body]);
    const a = answers[name];
    if (a instanceof Error) throw a;
    return typeof a === "function" ? a(body) : a;
  };
  return { calls, leases: door("leases"), releases: door("releases"), ingestResult: door("ingestResult"), work: door("work"), signResults: door("signResults"), signedWake: door("signedWake") };
}

const ENV = (dir, extra = {}) => ({ GITHUB_RUN_ID: "4242", GITHUB_RUN_ATTEMPT: "2", GITHUB_OUTPUT: path.join(dir, "out.txt"), ...extra });
const outputs = (dir) => Object.fromEntries(fs.readFileSync(path.join(dir, "out.txt"), "utf8").trim().split("\n").map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));

test("ingest-work: leases with the run's id, writes one request file per lease with only what ingest reads, and outputs the lease ids", async () => {
  const dir = tmpdir();
  const service = fakeService({
    leases: { schema: "astra.games.leases/1", items: [
      { lease_id: "L1", repo_id: 900000001, tag: "v1.0.0", binding_token_sha256: H("a"), confirmed: [], extra_member: "ignored" },
      { lease_id: "L2", repo_id: 900000002, tag: null, confirmed: [{ path: "a.png", sha256: H("b"), text_id: "market.rights.art", text_version: 1 }] },
    ], poll: [] },
  });
  const r = await ingestWork({ out: path.join(dir, "req"), env: ENV(dir), client: service, github: null, log: quiet });
  assert.deepEqual(service.calls, [["leases", { run_id: 4242, run_attempt: 2, max: 5 }]]);
  assert.deepEqual(r.leases, ["L1", "L2"]);
  assert.deepEqual(JSON.parse(outputs(dir).leases), ["L1", "L2"]);
  assert.equal(outputs(dir).malformed, "0");
  const l1 = JSON.parse(fs.readFileSync(path.join(dir, "req", "games-request-L1.json"), "utf8"));
  assert.deepEqual(l1, { lease_id: "L1", repo_id: 900000001, tag: "v1.0.0", binding_token_sha256: H("a"), confirmed: [] });
});

test("ingest-work: a lease carrying an account, a plaintext token or a subject is never written (BOT-10) and is counted", async () => {
  const dir = tmpdir();
  const service = fakeService({
    leases: { items: [
      { lease_id: "L1", repo_id: 1, tag: "v1", account: "minice-subject-7" },
      { lease_id: "L2", repo_id: 2, tag: "v1", binding_token: "plaintextToken_0123456789" },
      { lease_id: "L3", repo_id: 3, tag: "v1" },
    ], poll: [] },
  });
  const r = await ingestWork({ out: path.join(dir, "req"), env: ENV(dir), client: service, github: null, log: quiet });
  assert.deepEqual(r.leases, ["L3"]);
  assert.equal(r.malformed.length, 2);
  assert.equal(outputs(dir).malformed, "2");
  const written = fs.readdirSync(path.join(dir, "req"));
  assert.deepEqual(written, ["games-request-L3.json"]);
  for (const f of written) assert.ok(!fs.readFileSync(path.join(dir, "req", f), "utf8").includes("minice-subject-7"));
});

test("ingest-work: polls the named repositories and registers what it found; the created leases are ingested in the same run", async () => {
  const dir = tmpdir();
  const github = {
    calls: [],
    async releases(id) {
      this.calls.push(id);
      if (id === 1409552680) return { status: "found", releases: [{ tag_name: "v2.0.0-rc1", prerelease: true }, { tag_name: "v1.0.0" }] };
      if (id === 900000001) return { status: "found", releases: [{ tag_name: "v3", draft: true }, { tag_name: "v2-beta", prerelease: true }, { tag_name: "v1.1.0" }] };
      return { status: "transient", reason: "HTTP 502" };
    },
  };
  const service = fakeService({
    leases: { items: [], poll: [900000001, 1409552680, 77] },
    releases: (body) => ({ created: body.found.map((f, i) => ({ lease_id: `P${i}`, repo_id: f.repo_id, tag: f.tag, confirmed: [] })) }),
  });
  const r = await ingestWork({ out: path.join(dir, "req"), env: ENV(dir), client: service, github, log: quiet });
  const reg = service.calls.find(([n]) => n === "releases")[1];
  assert.equal(reg.run_id, 4242);
  assert.deepEqual(reg.found, [
    { repo_id: 900000001, tag: "v1.1.0" },
    { repo_id: 1409552680, tag: "v2.0.0-rc1" },
    { repo_id: 1409552680, tag: "v1.0.0" },
  ], "no draft; a prerelease only from a first-party repository; a repository GitHub did not answer is left out");
  assert.deepEqual(r.leases, ["P0", "P1", "P2"]);
});

test("ingest-report: one ingest-result per lease that has a candidate, the projection only", async () => {
  const dir = tmpdir();
  const cand = (lease, extra = {}) => {
    fs.mkdirSync(path.join(dir, `games-candidate-${lease}`), { recursive: true });
    fs.writeFileSync(path.join(dir, `games-candidate-${lease}`, "candidate.json"), JSON.stringify({
      schema: "astra.games.candidate/1", request: { lease_id: lease, repo_id: 1, tag: "v1" }, verdict: "wait",
      findings: [{ code: "W_CONTENT_UNCONFIRMED", message: "1 content part(s) wait" }], flags: [], ingested_at: 5,
      parts: [{ path: "art/a.png", kind: "art", sha256: H("c"), title: "A", credit: "me", licence_source: "declared" }], ...extra,
    }));
  };
  cand("L1");
  cand("L2", { request: { lease_id: "OTHER", repo_id: 1, tag: "v1" } });
  const service = fakeService({ ingestResult: { ok: true } });
  const r = await ingestReport({ candidates: dir, env: { LEASES: JSON.stringify(["L1", "L2", "L3"]), MALFORMED: "0" }, client: service, log: quiet });
  assert.deepEqual(r.posted, ["L1"]);
  assert.equal(r.failed.length, 1, "a candidate naming another lease is never posted for this one");
  const [, body] = service.calls[0];
  assert.equal(body.schema, "astra.games.ingest-result/1");
  assert.equal(body.lease_id, "L1");
  assert.deepEqual(body.candidate.parts, [{ path: "art/a.png", kind: "art", sha256: H("c"), title: "A" }]);
});

test("ingest-report: a lease the service no longer holds is a warning; any other refusal, or a malformed lease, fails the job", async () => {
  const dir = tmpdir();
  fs.mkdirSync(path.join(dir, "games-candidate-L1"), { recursive: true });
  fs.writeFileSync(path.join(dir, "games-candidate-L1", "candidate.json"), JSON.stringify({ schema: "astra.games.candidate/1", request: { lease_id: "L1", repo_id: 1, tag: "v1" }, verdict: "accept", findings: [] }));
  const gone = await ingestReport({ candidates: dir, env: { LEASES: '["L1"]' }, client: fakeService({ ingestResult: new ServiceRefused("bot/games/ingest-results", 409, "lease_not_held") }), log: quiet });
  assert.deepEqual(gone.failed, []);
  const invalid = await ingestReport({ candidates: dir, env: { LEASES: '["L1"]' }, client: fakeService({ ingestResult: new ServiceRefused("bot/games/ingest-results", 400, "invalid") }), log: quiet });
  assert.equal(invalid.failed.length, 1);
  const malformed = await ingestReport({ candidates: dir, env: { LEASES: '["L1"]', MALFORMED: "1" }, client: fakeService({ ingestResult: {} }), log: quiet });
  assert.equal(malformed.failed.length, 1);
  await assert.rejects(ingestReport({ candidates: dir, env: { LEASES: '["../x"]' }, client: fakeService({}), log: quiet }), /lease ids/);
});

test("the projection: at most 64 findings, refusals first, each message at most 2 KiB; never the entry's files or meta", () => {
  const findings = [
    ...Array.from({ length: 70 }, (_, i) => ({ code: "F_PROBE", message: `flag ${i}` })),
    { code: "E_PROBE", message: "x".repeat(5000) },
  ];
  const p = projectCandidate({ schema: "astra.games.candidate/1", request: { lease_id: "L", repo_id: 1, tag: "v1" }, verdict: "refuse", findings, flags: ["F_PROBE", "F_PROBE"], entry: { id: "a/b", version: "1.0.0", kind: "integration", source: { sha256: H("d") } }, meta: { files: { x: H("e") } } });
  assert.equal(p.findings.length, 64);
  assert.equal(p.findings_total, 71);
  assert.equal(p.findings[0].code, "E_PROBE");
  assert.ok(Buffer.byteLength(p.findings[0].message) <= 2048);
  assert.deepEqual(p.flags, ["F_PROBE"]);
  assert.deepEqual(p.entry, { id: "a/b", version: "1.0.0", kind: "integration", sha256: H("d") });
  assert.ok(!("meta" in p) && !JSON.stringify(p).includes(H("e")));
  assert.equal(ingestResultBody("L", { findings: [] }).lease_id, "L");
  assert.equal(clipBytes("ё".repeat(2000)).length < 2000, true, "clipped between code points");
});

test("the client: an https base from GAMES_SERVICE_URL (production by default), a Bearer OIDC token for the pinned audience, and the doors' paths", async () => {
  assert.equal(serviceBase({}), DEFAULT_BASE);
  assert.equal(serviceBase({ GAMES_SERVICE_URL: "https://staging.example/plugins/v1/" }), "https://staging.example/plugins/v1");
  for (const bad of ["http://api.minice.ai/plugins/v1", "https://u:p@api.minice.ai/x", "https://api.minice.ai/x?y=1", "nonsense"]) {
    assert.throws(() => serviceBase({ GAMES_SERVICE_URL: bad }), /GAMES_SERVICE_URL/);
  }
  const seen = [];
  const fetchImpl = async (url, init = {}) => {
    seen.push([url, init.method ?? "GET", init.headers?.Authorization ?? null]);
    if (url.startsWith("https://token.example")) return new Response(JSON.stringify({ value: "oidc-jwt" }));
    if (url.endsWith("/bot/games/work")) return new Response(JSON.stringify({ acts: [], health: null }));
    if (url.endsWith("/games/signed-wake")) return new Response(null, { status: 202 });
    return new Response(JSON.stringify({ error: "invalid" }), { status: 400 });
  };
  const env = { ACTIONS_ID_TOKEN_REQUEST_URL: "https://token.example/t?x=1", ACTIONS_ID_TOKEN_REQUEST_TOKEN: "rt" };
  assert.equal(await oidcToken({ env, fetchImpl }), "oidc-jwt");
  assert.equal(seen[0][0], `https://token.example/t?x=1&audience=${encodeURIComponent(DEFAULT_AUDIENCE)}`);
  const c = serviceClient({ env, fetchImpl });
  assert.deepEqual(await c.work(), { acts: [], health: null });
  assert.deepEqual(seen.at(-1), [`${DEFAULT_BASE}/bot/games/work`, "GET", "Bearer oidc-jwt"]);
  await assert.rejects(c.leases({}), (e) => e instanceof ServiceRefused && e.status === 400 && e.token === "invalid");
  assert.equal(await c.signedWake(), 202);
  assert.deepEqual(seen.at(-1), [`${DEFAULT_BASE}/games/signed-wake`, "POST", null], "the wake carries no credential");
  await assert.rejects(oidcToken({ env: {}, fetchImpl }), /id-token: write/);
});

// ── sign.yml's work and report jobs ──────────────────────────────────────


test("sign-work: pulls acts and health into files, counts the Ingest run's candidates, and says when there is nothing to sign", async () => {
  const github = (names) => ({ async runArtifacts(repo, id) { return names === null ? { status: "transient", reason: "HTTP 502" } : { status: "found", names }; } });
  const run = async (answer, names, extra = {}) => {
    const dir = tmpdir();
    const r = await signWork({ out: path.join(dir, "w"), env: { ...ENV(dir), INGEST_RUN_ID: "77", GITHUB_REPOSITORY: "mihailinl/astra-games-catalogue", ...extra }, client: fakeService({ work: answer }), github: github(names), log: quiet });
    return { r, dir, out: outputs(dir) };
  };
  const idle = await run({ schema: "astra.games.work/1", acts: [], health: null }, ["games-requests"]);
  assert.equal(idle.r.todo, false);
  assert.equal(idle.out.todo, "false");
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(idle.dir, "w", "acts.json"), "utf8")), []);
  assert.equal(JSON.parse(fs.readFileSync(path.join(idle.dir, "w", "health.json"), "utf8")), null);
  assert.equal((await run({ acts: [{ type: "M_YANK" }], health: null }, [])).out.todo, "true");
  assert.equal((await run({ acts: [], health: { "a/b": { rating_count: 1 } } }, [])).out.todo, "true");
  const cands = await run({ acts: [], health: null }, ["games-requests", "games-candidate-L1", "games-candidate-L2"]);
  assert.equal(cands.out.candidates, "2");
  assert.equal(cands.out.todo, "true");
  assert.equal((await run({ acts: [], health: null }, null)).out.todo, "true", "an unanswered listing never skips a run that may have candidates");
  assert.equal((await run({ acts: [], health: null }, ["x"], { INGEST_RUN_ID: "" })).out.todo, "false", "a dispatched run has no Ingest run");
});

test("bin/sign.mjs reads the work files and both candidate layouts", () => {
  const dir = tmpdir();
  fs.writeFileSync(path.join(dir, "acts.json"), JSON.stringify([{ type: "M_YANK" }]));
  fs.writeFileSync(path.join(dir, "health.json"), "null");
  assert.deepEqual(readWorkFiles({ actsFile: path.join(dir, "acts.json"), healthFile: path.join(dir, "health.json") }), { acts: [{ type: "M_YANK" }], health: undefined });
  assert.deepEqual(readWorkFiles({ actsFile: path.join(dir, "none.json"), healthFile: null }), { acts: [], health: undefined });
  const c = path.join(dir, "c");
  fs.mkdirSync(path.join(c, "games-candidate-L2"), { recursive: true });
  fs.writeFileSync(path.join(c, "games-candidate-L2", "candidate.json"), JSON.stringify({ n: 2 }));
  fs.writeFileSync(path.join(c, "a.json"), JSON.stringify({ n: 1 }));
  assert.deepEqual(readCandidates(c), [{ n: 1 }, { n: 2 }]);
});

const REPORT = {
  accepted: [{ request: { lease_id: "L1", repo_id: 1, tag: "v1" }, result: "listed", reason: "listed" }],
  acts: [{ confirmation: { kind: "console-2fa", ref: "act-9" }, type: "M_YANK", seq: 12 }],
  duplicateActs: [{ ref: "act-7", type: "M_REVOKE", seq: 10 }],
  refusedActs: [],
  issuedAt: 1793448000,
  keyId: "astra-games-2026a",
};

test("the sign result names every act by its ref: applied with its seq, a duplicate applied with its FIRST seq, a refusal with its problems", () => {
  const body = signResultBody({ runId: "555", dataSha: "f".repeat(40), report: { ...REPORT, refusedActs: [{ ref: "act-8", type: "M_PROMOTE", problems: ["not a prerelease"] }] } });
  assert.deepEqual(body, {
    schema: "astra.games.sign-result/1", run_id: 555, data_sha: "f".repeat(40), issued_at: 1793448000, key_id: "astra-games-2026a",
    accepted: [{ request: { lease_id: "L1", repo_id: 1, tag: "v1" }, result: "listed", reason: "listed" }],
    acts: [
      { ref: "act-9", outcome: "applied", seq: 12 },
      { ref: "act-7", outcome: "applied", seq: 10 },
      { ref: "act-8", outcome: "refused", problems: ["not a prerelease"] },
    ],
  });
});

test("sign-report: posts the result, wakes the service, and fails only after both when an act was refused", async () => {
  const dir = tmpdir();
  const write = (r) => { const f = path.join(dir, `r${Math.random()}.json`); fs.writeFileSync(f, JSON.stringify(r)); return f; };
  const env = { GITHUB_RUN_ID: "555", DATA_SHA: "a".repeat(40) };
  const ok = fakeService({ signResults: {}, signedWake: 202 });
  assert.deepEqual((await signReport({ reportFile: write(REPORT), env, client: ok, log: quiet })).failed, []);
  assert.deepEqual(ok.calls.map(([n]) => n), ["signResults", "signedWake"]);
  const refused = fakeService({ signResults: {}, signedWake: 202 });
  const r = await signReport({ reportFile: write({ ...REPORT, refusedActs: [{ ref: "act-8", type: "M_PROMOTE", problems: ["x"] }] }), env, client: refused, log: quiet });
  assert.equal(r.failed.length, 1);
  assert.deepEqual(refused.calls.map(([n]) => n), ["signResults", "signedWake"], "reported and woken before failing");
  const noWake = fakeService({ signResults: {}, signedWake: new Error("ECONNREFUSED") });
  assert.deepEqual((await signReport({ reportFile: write(REPORT), env, client: noWake, log: quiet })).failed, [], "a failed wake is not a failed signing");
  await assert.rejects(signReport({ reportFile: write(REPORT), env: { ...env, DATA_SHA: "" }, client: ok, log: quiet }), /DATA_SHA/);
});
