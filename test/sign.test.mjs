// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Signing both documents (A§5.3-5.4; merged §2.2): the envelope verifies
// under the vendored registry verifier, the bodies validate against the S
// schemas through schemalite, serial = issued_at with a per-key floor, the
// 7-day expiry, current/next and the ratchet, and the keys.json canary (K14).

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { verifyEnvelope, publicKeyFromBase64 } from "../lib/vendor/astra-registry/bot/lib/sign.mjs";
import { bodyProblemsMany, declaredMembers, INDEX_SCHEMA, verifyDocument, WITHDRAWN_SCHEMA, buildIndexBody } from "../lib/documents.mjs";
import { validateMany } from "../lib/schemas.mjs";
import { nextIssuedAt, selectSigner } from "../lib/signing.mjs";
import { emptyModeration } from "../lib/state.mjs";
import { candidate, FOO_DESCRIPTOR, makeCatalogue, T0 } from "./catalogue.mjs";
import { throwawayKey } from "./helpers.mjs";

test("both documents are signed in one run, verify under the registry's verifier, and validate through schemalite", () => {
  const c = makeCatalogue();
  const r = c.sign({ candidates: [candidate(), candidate({ kind: "foundation", slug: "foo", engine: "foo-engine", descriptor: FOO_DESCRIPTOR })] });
  assert.deepEqual(r.accepted.map((a) => a.result), ["listed", "listed"]);
  const index = c.dist("games-index.json");
  const withdrawn = c.dist("games-withdrawn.json");
  const pub = [{ key_id: "games-current", publicKey: publicKeyFromBase64(c.current.publicB64) }];
  assert.equal(verifyEnvelope(index, INDEX_SCHEMA, pub).ok, true);
  assert.equal(verifyEnvelope(withdrawn, WITHDRAWN_SCHEMA, pub).ok, true);
  assert.equal(verifyEnvelope(index, WITHDRAWN_SCHEMA, pub).ok, false, "the domain is the verifier's, so an index is not a withdrawn list");
  const [a, b] = validateMany([{ schema: "games-index-v1", doc: index.signed }, { schema: "games-withdrawn-v1", doc: withdrawn.signed }]);
  assert.ok(a.ok, a.error);
  assert.ok(b.ok, b.error);
  assert.equal(index.signed.serial, T0);
  assert.equal(index.signed.issued_at, T0);
  assert.equal(index.signed.expires_at, T0 + 7 * 86400);
  assert.equal(withdrawn.signed.issued_at, index.signed.issued_at, "one issued_at for both");
  assert.equal(index.signed.key_id, "games-current");
  assert.deepEqual(index.signed.engine_codes, { "foo-engine": { account: "author", repo_id: index.signed.entries.find((e) => e.kind === "foundation").publisher.repo_id, repo_owner_id: 800000001 } });
  assert.equal(index.signed.loaders[0].name, "doorstop-winhttp", "the loaders.json seed is served");
});

test("serial = issued_at, strictly above the key's floor; a floor more than a day ahead refuses", () => {
  const c = makeCatalogue();
  c.sign();
  c.sign();
  assert.equal(c.dist("games-index.json").signed.serial, T0 + 1, "a second run in the same second still moves forward");
  assert.equal(nextIssuedAt({ now: 100, floors: { "games-current": { index: 50, withdrawn: 99 } }, keyId: "games-current" }), 100);
  assert.throws(() => nextIssuedAt({ now: 100, floors: { "games-current": { index: 100 + 86400, withdrawn: 0 } }, keyId: "games-current" }), /E_SERIAL_AHEAD/);
});

test("current signs until next is provisioned; next then signs, and current is retired for good", () => {
  const c = makeCatalogue();
  c.sign();
  assert.equal(c.dist("games-index.json").signed.key_id, "games-current");
  const withNext = { ...c.env, GAMES_SIGNING_KEY_NEXT: c.next.seedB64 };
  c.sign({ env: withNext });
  const idx = c.dist("games-index.json");
  assert.equal(idx.signed.key_id, "games-next");
  assert.equal(idx.signatures[0].key_id, "games-next");
  assert.throws(() => c.sign({ env: { GAMES_SIGNING_KEY_CURRENT: c.current.seedB64 } }), /E_KEY_RETIRED/);
});

test("K14: the signer refuses a key keys.json does not publish, and refuses to run with no key", () => {
  const c = makeCatalogue();
  const stranger = throwawayKey();
  assert.throws(() => c.sign({ env: { GAMES_SIGNING_KEY_CURRENT: stranger.seedB64 } }), /E_KEY_NOT_PUBLISHED/);
  assert.throws(() => c.sign({ env: {} }), /E_KEY_ABSENT/);
  assert.throws(() => selectSigner({ env: { GAMES_SIGNING_KEY_CURRENT: c.current.seedB64 }, floors: {}, keys: [{ key_id: "games-current", public_key: null }] }), /E_KEY_NOT_PUBLISHED/);
  assert.equal(fs.existsSync(path.join(c.data, "dist")), false, "a refused run writes nothing");
});

test("K14: the repository's keys.json names exactly the two compiled key ids", () => {
  const keys = JSON.parse(fs.readFileSync(new URL("../keys.json", import.meta.url), "utf8"));
  assert.deepEqual(keys.keys.map((k) => k.key_id).sort(), ["games-current", "games-next"]);
  const schema = JSON.parse(fs.readFileSync(new URL("../lib/vendor/astraplugins/spec/games/schemas/games-index-v1.schema.json", import.meta.url), "utf8"));
  assert.deepEqual([...schema.properties.key_id.enum].sort(), ["games-current", "games-next"]);
});

test("a tampered document fails verification", () => {
  const c = makeCatalogue();
  c.sign({ candidates: [candidate()] });
  const idx = c.dist("games-index.json");
  idx.signed.entries[0].source.sha256 = "0".repeat(64);
  assert.ok(verifyDocument(idx, { domain: INDEX_SCHEMA, keys: c.keys, now: T0 }).some((p) => p.startsWith("signature")));
});

test("first-party prereleases are stored, not listed", () => {
  const c = makeCatalogue();
  const r = c.sign({ candidates: [candidate({ account: "mihailinl", slug: "astra-peak", repo_id: 1409552680, owner_id: 193032699, status: "prerelease", first_party: true })] });
  assert.equal(r.accepted[0].result, "prerelease");
  assert.equal(c.dist("games-index.json").signed.entries.length, 0);
});

test("the signer re-checks engine-code ownership: the second of two racing claims is refused", () => {
  const c = makeCatalogue();
  const a = candidate({ kind: "foundation", slug: "foo-a", engine: "foo-engine", descriptor: FOO_DESCRIPTOR, account: "first" });
  const b = candidate({ kind: "foundation", slug: "foo-b", engine: "foo-engine", descriptor: FOO_DESCRIPTOR, account: "second" });
  const r = c.sign({ candidates: [a, b] });
  assert.deepEqual(r.accepted.map((x) => x.result), ["listed", "refused"]);
  assert.match(r.accepted[1].reason, /engine-code-taken/);
});

test("a held candidate (changed hands) is parked for a person, not listed", () => {
  const c = makeCatalogue();
  const h = candidate({ verdict: "hold", findings: [{ code: "R_IDENTITY_CHANGED", message: "moved" }] });
  const r = c.sign({ candidates: [h] });
  assert.equal(r.accepted[0].result, "held");
  assert.equal(c.dist("games-index.json").signed.entries.length, 0);
  assert.equal(c.state("holds.json").length, 1);
});

// ── merged §5.2 members wait for the schema ────────────────────────────────

test("§5.2: health, unmaintained and recommended_foundations are emitted only when the pinned schema declares them", () => {
  const members = declaredMembers();
  assert.deepEqual(members, { health: false, unmaintained: false, successor_entry_id: false, recommended_foundations: false }, "S has not declared them at d46e44a; when it does, re-pin and this flips");
  const c = makeCatalogue();
  c.sign({ candidates: [candidate({ slug: "h1" })], health: { "author/h1": { rating_avg: 437, rating_count: 12, open_reports_unanswered: 1, reports_sent: 25, reports_failed: 5 } } });
  const idx = c.dist("games-index.json").signed;
  assert.equal("health" in idx.entries[0], false);

  // with every member declared (what S will publish), they appear, integers only
  const state = {
    entries: [{ entry: idx.entries[0], meta: { status: "listed", released_at: T0 - 3600 } }],
    engineCodes: {}, moderation: { ...emptyModeration(), recommended_foundations: { "foo-engine": "author/h1" } }, withdrawn: { rows: [], held: [] },
    health: { "author/h1": { rating_avg: 437, rating_count: 12, open_reports_unanswered: 1, reports_sent: 25, reports_failed: 5 } },
  };
  const body = buildIndexBody({ state, seedLoaders: { loaders: [] }, issuedAt: T0, keyId: "games-current", members: { health: true, unmaintained: true, successor_entry_id: true, recommended_foundations: true } });
  assert.deepEqual(body.entries[0].health, { last_release_at: T0 - 3600, rating_avg: 437, rating_count: 12, open_reports_unanswered: 1, failure_rate: 2000 });
  assert.deepEqual(body.recommended_foundations, { "foo-engine": "author/h1" });
  state.health["author/h1"].reports_sent = 19;
  const fewer = buildIndexBody({ state, seedLoaders: { loaders: [] }, issuedAt: T0, keyId: "games-current", members: { health: true } });
  assert.equal("failure_rate" in fewer.entries[0].health, false, "fewer than 20 reports means no value");
});

// ── K12: AstraPlugins' index and withdrawn goldens through this validator ──

test("K12: every index and withdrawn golden gets the verdict vectors.json records", () => {
  const AP = new URL("../lib/vendor/astraplugins/testdata/games/", import.meta.url);
  const vectors = JSON.parse(fs.readFileSync(new URL("vectors.json", AP), "utf8"));
  const load = (rel) => JSON.parse(fs.readFileSync(new URL(rel, AP), "utf8"));
  const referenceNow = load(vectors.index.valid[0].file).issued_at;
  const cases = [];
  for (const [domain, group] of [[INDEX_SCHEMA, vectors.index], [WITHDRAWN_SCHEMA, vectors.withdrawn]]) {
    for (const v of [...group.valid, ...group.invalid]) cases.push({ v, domain, body: load(v.file) });
  }
  const results = bodyProblemsMany(cases, { now: referenceNow });
  cases.forEach(({ v }, i) => {
    const problems = results[i];
    assert.equal(problems.length === 0, v.verdict === "accept", `${v.file}: ${problems.join("; ") || "no problems"}`);
    if (v.check === "semantic") assert.ok(problems.some((p) => p.startsWith(v.rule)), `${v.file}: ${v.rule} not among ${problems}`);
  });
});

test("bin/keygen.mjs writes a 0600 seed, refuses to overwrite, and prints only the public half", async () => {
  const { execFileSync } = await import("node:child_process");
  const { tmpdir } = await import("./helpers.mjs");
  const out = path.join(tmpdir(), "games-current.ed25519"); // a throwaway path, never the real key directory
  const printed = execFileSync(process.execPath, [new URL("../bin/keygen.mjs", import.meta.url).pathname, "--key-id", "games-current", "--out", out], { encoding: "utf8" });
  const row = JSON.parse(printed);
  assert.equal(row.key_id, "games-current");
  assert.equal(Buffer.from(row.public_key, "base64").length, 32);
  assert.equal(fs.statSync(out).mode & 0o777, 0o600);
  const seed = fs.readFileSync(out, "utf8").trim();
  assert.ok(!printed.includes(seed), "the seed is never printed");
  const signer = selectSigner({ env: { GAMES_SIGNING_KEY_CURRENT: seed }, floors: {}, keys: [row] });
  assert.equal(signer.public_key, row.public_key);
  assert.throws(() => execFileSync(process.execPath, [new URL("../bin/keygen.mjs", import.meta.url).pathname, "--key-id", "games-current", "--out", out], { stdio: "pipe" }));
});
