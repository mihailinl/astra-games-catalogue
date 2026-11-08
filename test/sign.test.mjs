// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Signing both documents (A§5.3; merged §2.2): the envelope verifies under
// the vendored registry verifier, the bodies validate against the S schemas
// through schemalite, serial = issued_at with the per-kind floor, and the
// signature's life under 8 days. Which keys may sign is test/trust.test.mjs.

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { verifyEnvelope, publicKeyFromBase64 } from "../lib/vendor/astra-registry/bot/lib/sign.mjs";
import { bodyProblemsMany, declaredMembers, INDEX_SCHEMA, verifyDocument, verifyEnvelopeAll, WITHDRAWN_SCHEMA, buildIndexBody } from "../lib/documents.mjs";
import { verifyingKeys } from "../lib/trust.mjs";
import { validateMany } from "../lib/schemas.mjs";
import { nextIssuedAt, selectSigner, selectSigners, signBoth } from "../lib/signing.mjs";
import { emptyModeration } from "../lib/state.mjs";
import { candidate, FOO_DESCRIPTOR, makeCatalogue, T0 } from "./catalogue.mjs";
import { throwawayKey } from "./helpers.mjs";

test("both documents are signed in one run, verify under the registry's verifier, and validate through schemalite", () => {
  const c = makeCatalogue();
  const r = c.sign({ candidates: [candidate(), candidate({ kind: "foundation", slug: "foo", engine: "foo-engine", descriptor: FOO_DESCRIPTOR })] });
  assert.deepEqual(r.accepted.map((a) => a.result), ["listed", "listed"]);
  const index = c.dist("games-index.json");
  const withdrawn = c.dist("games-withdrawn.json");
  const pub = [{ key_id: "astra-games-2026a", publicKey: publicKeyFromBase64(c.current.publicB64) }];
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
  assert.equal(index.signed.key_id, "games-current", "the body names the ROLE (the schema's enum)");
  assert.equal(index.signatures[0].key_id, "astra-games-2026a", "the signature names the kind key");
  assert.deepEqual(index.signed.engine_codes, { "foo-engine": { account: "author", repo_id: index.signed.entries.find((e) => e.kind === "foundation").publisher.repo_id, repo_owner_id: 800000001 } });
  assert.equal(index.signed.loaders[0].name, "doorstop-winhttp", "the loaders.json seed is served");
});

test("serial = issued_at, strictly above the kind's floor; a floor more than a day ahead refuses", () => {
  const c = makeCatalogue();
  c.sign();
  c.sign();
  assert.equal(c.dist("games-index.json").signed.serial, T0 + 1, "a second run in the same second still moves forward");
  assert.deepEqual(c.state("floors.json"), { kind: "games", index: T0 + 1, withdrawn: T0 + 1, spent: { [INDEX_SCHEMA]: [], [WITHDRAWN_SCHEMA]: [] } });
  assert.equal(nextIssuedAt({ now: 100, floors: { index: 50, withdrawn: 99 } }), 100);
  assert.equal(nextIssuedAt({ now: 100, floors: { index: 150, withdrawn: 99 } }), 151);
  assert.throws(() => nextIssuedAt({ now: 100, floors: { index: 100 + 86400, withdrawn: 0 } }), /E_SERIAL_AHEAD/);
});

test("expiry: a signature lives 7 days, and nothing longer than 8 days is ever signed", () => {
  const c = makeCatalogue();
  c.sign();
  for (const f of ["games-index.json", "games-withdrawn.json"]) {
    const b = c.dist(f).signed;
    assert.equal(b.expires_at - b.issued_at, 7 * 86400);
    assert.ok(b.expires_at - b.issued_at <= 8 * 86400);
  }
  const signers = selectSigners({ env: c.env, floors: {}, kindKeys: c.kindKeys, now: T0 });
  const state = { entries: [], engineCodes: {}, moderation: emptyModeration(), withdrawn: { rows: [], held: [] }, health: {}, floors: {} };
  assert.throws(() => signBoth({ state, seedLoaders: { loaders: [] }, signers, kindKeys: c.kindKeys, now: T0, expirySeconds: 8 * 86400 + 1 }), /E_EXPIRY_TOO_LONG/);
  const eight = signBoth({ state, seedLoaders: { loaders: [] }, signers, kindKeys: c.kindKeys, now: T0, expirySeconds: 8 * 86400 });
  assert.equal(eight.index.signed.expires_at - eight.index.signed.issued_at, 8 * 86400, "exactly 8 days is within the cap");
});

test("the signer refuses to run with no key, and a refused run writes nothing", () => {
  const c = makeCatalogue();
  assert.throws(() => c.sign({ env: {} }), /E_KEY_ABSENT/);
  assert.throws(() => c.sign({ env: { GAMES_SIGNING_KEY_CURRENT: throwawayKey().seedB64 } }), /E_KEY_NOT_AUTHORISED/);
  assert.equal(fs.existsSync(path.join(c.data, "dist")), false);
});

test("B alone under N still signs games-next", () => {
  for (const slot of ["GAMES_SIGNING_KEY_NEXT", "GAMES_SIGNING_KEY_CURRENT"]) {
    const c = makeCatalogue();
    const r = c.sign({ env: { [slot]: c.next.seedB64 }, candidates: [candidate()] });
    for (const [f, domain] of [["games-index.json", INDEX_SCHEMA], ["games-withdrawn.json", WITHDRAWN_SCHEMA]]) {
      const d = c.dist(f);
      assert.deepEqual(d.signatures.map((x) => x.key_id), ["astra-games-2026b"], `${slot}: one signature`);
      assert.equal(d.signed.key_id, "games-next", `${slot}: today's routine rotation, unchanged`);
      assert.deepEqual(verifyDocument(d, { domain, kindKeys: c.kindKeys, now: T0, indexBody: c.dist("games-index.json").signed }), []);
    }
    assert.equal(r.keyId, "astra-games-2026b");
    assert.deepEqual(c.state("floors.json").spent[INDEX_SCHEMA], [{ key_id: "astra-games-2026a", public_key: c.current.publicB64 }]);
  }
});

test("the verifier collects every key, so the order of signatures does not matter", () => {
  const c = makeCatalogue({ withNext: true });
  c.sign({ candidates: [candidate()] });
  const idx = c.dist("games-index.json"); // signed B then A, body games-current
  const reversed = { ...idx, signatures: [...idx.signatures].reverse() };
  const trusted = verifyingKeys(c.kindKeys);
  for (const [order, e] of [["next first", idx], ["current first", reversed]]) {
    assert.deepEqual(verifyEnvelopeAll(e, INDEX_SCHEMA, trusted).verified.map((k) => k.key_id), ["astra-games-2026a", "astra-games-2026b"], order);
    assert.deepEqual(verifyDocument(e, { domain: INDEX_SCHEMA, kindKeys: c.kindKeys, now: T0 }), [], order);
  }
  // the vendored first-wins verifier sees one key, and which one is up to the order
  assert.equal(verifyEnvelope(idx, INDEX_SCHEMA, trusted).key_id, "astra-games-2026b");
  assert.equal(verifyEnvelope(reversed, INDEX_SCHEMA, trusted).key_id, "astra-games-2026a");
  // an entry naming a key id the verifier does not trust, or a malformed entry, is not counted and is no error
  const extra = { ...idx, signatures: [{ key_id: "astra-games-1999z", sig: c.dist("games-withdrawn.json").signatures[0].sig }, { key_id: "x", sig: "not base64!" }, { key_id: 7 }, ...idx.signatures] };
  assert.deepEqual(verifyDocument(extra, { domain: INDEX_SCHEMA, kindKeys: c.kindKeys, now: T0 }), []);
  // the claim must be among the verifying keys' roles in every order: drop A and the games-current body is refused
  for (const e of [idx, reversed]) {
    const bOnly = { ...e, signatures: e.signatures.filter((x) => x.key_id === "astra-games-2026b") };
    assert.ok(verifyDocument(bOnly, { domain: INDEX_SCHEMA, kindKeys: c.kindKeys, now: T0 }).some((p) => p.startsWith("the body names games-current")));
  }
  assert.equal(verifyEnvelopeAll(idx, WITHDRAWN_SCHEMA, trusted).ok, false, "the domain is still the verifier's");
});

test("the body's key_id enum in the pinned schema names roles, which is what the body carries", () => {
  const schema = JSON.parse(fs.readFileSync(new URL("../lib/vendor/astraplugins/spec/games/schemas/games-index-v1.schema.json", import.meta.url), "utf8"));
  assert.deepEqual([...schema.properties.key_id.enum].sort(), ["games-current", "games-next"]);
});

test("a tampered document fails verification", () => {
  const c = makeCatalogue();
  c.sign({ candidates: [candidate()] });
  const idx = c.dist("games-index.json");
  idx.signed.entries[0].source.sha256 = "0".repeat(64);
  assert.ok(verifyDocument(idx, { domain: INDEX_SCHEMA, kindKeys: c.kindKeys, now: T0 }).some((p) => p.startsWith("signature")));
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

test("bin/keygen.mjs writes a 0600 seed, refuses to overwrite, and prints only the kind_keys row", async () => {
  const { execFileSync } = await import("node:child_process");
  const { tmpdir } = await import("./helpers.mjs");
  const out = path.join(tmpdir(), "astra-games-2026a.ed25519"); // a throwaway path, never the real key directory
  const keygen = new URL("../bin/keygen.mjs", import.meta.url).pathname;
  const argv = ["--role", "current", "--key-id", "astra-games-2026a", "--not-before", "2026-10-01T00:00:00Z", "--out", out];
  const printed = execFileSync(process.execPath, [keygen, ...argv], { encoding: "utf8" });
  const row = JSON.parse(printed);
  assert.deepEqual(Object.keys(row).sort(), ["alg", "key_id", "kind", "not_before", "public_key", "role"]);
  assert.equal(row.kind, "games");
  assert.equal(row.alg, "ed25519");
  assert.equal(Buffer.from(row.public_key, "base64").length, 32);
  assert.equal(fs.statSync(out).mode & 0o777, 0o600);
  const seed = fs.readFileSync(out, "utf8").trim();
  assert.ok(!printed.includes(seed), "the seed is never printed");
  const other = throwawayKey();
  const kindKeys = { current: { ...row, notBefore: Math.floor(Date.parse(row.not_before) / 1000) }, next: { ...row, role: "next", key_id: "astra-games-2026b", public_key: other.publicB64, notBefore: 0 } };
  const signer = selectSigner({ env: { GAMES_SIGNING_KEY_CURRENT: seed }, floors: {}, kindKeys, now: T0, schema: INDEX_SCHEMA });
  assert.equal(signer.public_key, row.public_key);
  assert.throws(() => execFileSync(process.execPath, [keygen, ...argv], { stdio: "pipe" }));
});

test("rights gate, sign side: a candidate whose findings hold a wait, or whose parts carry no content_confirmed, is never listed", () => {
  const c = makeCatalogue();
  const part = { path: "art/cover.png", kind: "art", title: "Cover", credit: "author", licence: "CC0-1.0", licence_source: "declared", sha256: "e".repeat(64) };
  const forged = candidate();
  forged.findings = [{ code: "W_CONTENT_UNCONFIRMED", message: "1 content part(s) wait" }]; // verdict still says accept
  const unconfirmed = candidate();
  unconfirmed.entry.content = [part];
  const confirmed = candidate();
  confirmed.entry.content = [part];
  confirmed.entry.content_confirmed = { "market.rights.art": 2 };
  const r = c.sign({ candidates: [forged, unconfirmed, confirmed] });
  assert.deepEqual(r.accepted.map((a) => a.result), ["refused", "refused", "listed"], JSON.stringify(r.accepted));
  assert.match(r.accepted[0].reason, /W_CONTENT_UNCONFIRMED/);
  assert.match(r.accepted[1].reason, /content_confirmed/);
  const listed = c.dist("games-index.json").signed.entries.find((e) => e.id === confirmed.entry.id);
  assert.deepEqual(listed.content_confirmed, { "market.rights.art": 2 });
});

test("an accepted candidate clears its own stale hold, and only its own", () => {
  const c = makeCatalogue();
  const fp = { account: "mihailinl", slug: "astra-peak", repo_id: 1409552680, owner_id: 193032699, first_party: true };
  const unpinned = candidate({ ...fp, verdict: "hold", findings: [{ code: "H_FIRST_PARTY_UNPINNED", message: "no pin" }] });
  const other = candidate({ verdict: "hold", findings: [{ code: "R_IDENTITY_CHANGED", message: "moved" }] });
  c.sign({ candidates: [unpinned, other] });
  assert.equal(c.state("holds.json").length, 2);
  // the owner added the pin; the same release is leased and ingested again
  const pinned = candidate({ ...fp });
  const r = c.sign({ candidates: [pinned] });
  assert.equal(r.accepted[0].result, "listed", JSON.stringify(r.accepted));
  assert.deepEqual(c.state("holds.json").map((h) => h.hold_id), [`${other.request.repo_id}@v1.0.0`], "the listed release's hold is gone; the other stays");
});
