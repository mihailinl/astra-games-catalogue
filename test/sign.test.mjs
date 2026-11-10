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
import { bodyProblemsMany, declaredMembers, INDEX_SCHEMA, signatureCheck, successorProblems, verifyDocument, verifyEnvelopeAll, WITHDRAWN_SCHEMA, buildIndexBody } from "../lib/documents.mjs";
import { LIFT_KEEP_SECONDS, LIFTS_MAX } from "../lib/model.mjs";
import { lastWithdrawn, listProblemsIntroduced, tryAct } from "../lib/pipeline.mjs";
import { verifyingKeys } from "../lib/trust.mjs";
import { validateMany } from "../lib/schemas.mjs";
import { nextIssuedAt, selectSigner, selectSigners, signBoth } from "../lib/signing.mjs";
import { emptyModeration, loadState, writeJson } from "../lib/state.mjs";
import { act, candidate, FOO_DESCRIPTOR, makeCatalogue, T0 } from "./catalogue.mjs";
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
  assert.throws(() => signBoth({ state, seedLoaders: { loaders: [] }, previous: null, signers, kindKeys: c.kindKeys, now: T0, expirySeconds: 8 * 86400 + 1 }), /E_EXPIRY_TOO_LONG/);
  const eight = signBoth({ state, seedLoaders: { loaders: [] }, previous: null, signers, kindKeys: c.kindKeys, now: T0, expirySeconds: 8 * 86400 });
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

test("the verifier counts a signature only in the client's spelling, and a key only from its not_before", () => {
  const c = makeCatalogue({ withNext: true });
  c.sign({ candidates: [candidate()] });
  const idx = c.dist("games-index.json"); // B then A, body games-current
  const trusted = verifyingKeys(c.kindKeys);
  const withA = (sig) => ({ ...idx, signatures: idx.signatures.map((x) => (x.key_id === "astra-games-2026a" ? { ...x, sig } : x)) });
  const a = idx.signatures.find((x) => x.key_id === "astra-games-2026a").sig;
  assert.match(a, /^[A-Za-z0-9+/]{86}==$/);
  // Node's base64 decoder reads all of these as A's 64 bytes; the client's strict decoder reads none of them
  for (const [why, sig] of [["unpadded", a.slice(0, -2)], ["a newline inside", `${a.slice(0, 40)}\n${a.slice(40)}`]]) {
    assert.equal(Buffer.from(sig, "base64").length, 64, `${why}: Node decodes it`);
    assert.deepEqual(verifyEnvelopeAll(withA(sig), INDEX_SCHEMA, trusted).verified.map((k) => k.key_id), ["astra-games-2026b"], why);
    assert.ok(verifyDocument(withA(sig), { domain: INDEX_SCHEMA, kindKeys: c.kindKeys, now: T0 }).some((p) => p.startsWith("the body names games-current")), why);
  }
  assert.deepEqual(verifyDocument(withA(` ${a}\n`), { domain: INDEX_SCHEMA, kindKeys: c.kindKeys, now: T0 }), [], "surrounding whitespace is trimmed, as the service trims it");

  // a key counts only once its not_before has come (the client's valid_at(judged_at))
  const by = (now) => signatureCheck(idx, INDEX_SCHEMA, c.kindKeys, now);
  assert.deepEqual(by(c.kindKeys.next.notBefore).verifiedBy.map((k) => k.key_id), ["astra-games-2026a", "astra-games-2026b"]);
  assert.deepEqual(by(c.kindKeys.next.notBefore - 1).verifiedBy.map((k) => k.key_id), ["astra-games-2026a"], "B is not yet a key a second before its not_before");
  assert.deepEqual(by(c.kindKeys.current.notBefore - 1).problems, ["signature: no games kind key of trust.json has reached its not_before"]);
  assert.throws(() => signatureCheck(idx, INDEX_SCHEMA, c.kindKeys), /needs now/);
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

// ── a security revoke never leaves the list without its lift ──────────────
//
// A client keeps a security revoke it applied until a signed lift names it;
// a fresh install reads only the current list. So a correctly signed list
// from which such a row is merely gone releases it nowhere it was seen and
// offers the revoked versions to everybody new. The signer holds every list
// to the one it published last (documents.mjs successorProblems), read from
// dist/ (pipeline.mjs lastWithdrawn). Found on 2026-11-10 with the ops
// stand's `act lift --state-only`, which edits the state and signs no lift.

const DAY = 86400;
const REPO = 930000001;
const SUBJECT = { repo_id: REPO, versions: "<=1.0.0" };
const STICKY = { ...SUBJECT, act: "revoke", floor_effect: "no-play", reason_code: "security", reason_text: "A credential stealer.", at: T0 };
const revoke = (payload = {}, at = T0) => act("M_REVOKE", { ...SUBJECT, reason_code: "security", reason_text: "A credential stealer.", ...payload }, at);
const liftAct = (payload = {}, at = T0 + 60) => act("M_LIFT", { ...SUBJECT, lifts_at: T0, kinds: ["revoke"], reason_text: "The advisory named another package.", ...payload }, at);
const listOf = (c) => c.dist("games-withdrawn.json").signed;
const withdrawnFile = (c) => path.join(c.data, "withdrawn.json");
const distFile = (c) => path.join(c.data, "dist", "games-withdrawn.json");
/** Edit the state's withdrawn.json by hand, as nothing in the signer does. */
const editState = (c, edit) => {
  const w = c.state("withdrawn.json");
  fs.writeFileSync(withdrawnFile(c), JSON.stringify(edit(w) ?? w));
};
/** Every file of the data directory, to show a refused run wrote nothing. */
const snapshot = (c) => Object.fromEntries(fs.readdirSync(c.data, { recursive: true }).sort()
  .filter((f) => fs.statSync(path.join(c.data, f)).isFile()).map((f) => [f, fs.readFileSync(path.join(c.data, f), "utf8")]));
const refusedUnchanged = (c, run, pattern) => {
  const before = snapshot(c);
  assert.throws(run, pattern);
  assert.deepEqual(snapshot(c), before, "a refused run writes nothing");
};

/** A catalogue whose published list carries one security revoke. */
function revoked() {
  const c = makeCatalogue();
  c.sign({ candidates: [candidate({ repo_id: REPO, slug: "peak-gi" })] });
  assert.deepEqual(c.sign({ acts: [revoke()] }).refusedActs, []);
  assert.deepEqual(listOf(c).rows, [STICKY]);
  return c;
}

const VANISHED_ROW = new RegExp(`^Error: E_SELF_VERIFY: withdrawn: sticky-row-vanished: repo ${REPO}  <=1\\.0\\.0 at ${T0} is a security revoke in the list published before this one`);

test("a sticky row that stays is signed again, day after day, and so is one lifted by its act", () => {
  const c = revoked();
  c.sign({ now: T0 + DAY });
  c.sign({ now: T0 + 2 * DAY });
  assert.deepEqual(listOf(c).rows, [STICKY]);
  // lifted as the signer lifts: the row leaves and its lift is in the same list
  assert.deepEqual(c.sign({ now: T0 + 3 * DAY, acts: [liftAct({}, T0 + 3 * DAY)] }).refusedActs, []);
  assert.deepEqual(listOf(c).rows, []);
  assert.deepEqual(listOf(c).lifts, [{ ...SUBJECT, lifts_at: T0, at: T0 + 3 * DAY }]);
  c.sign({ now: T0 + 4 * DAY });
  assert.deepEqual(listOf(c).lifts.length, 1);
});

test("a sticky row dropped from the state with no lift refuses the run, naming the subject and its at, and nothing is written", () => {
  const c = revoked();
  editState(c, (w) => { w.rows = []; });
  refusedUnchanged(c, () => c.sign({ now: T0 + DAY }), VANISHED_ROW);
  // an act in the same run does not get it through, and is not blamed for it: the run stops, the act is served again
  refusedUnchanged(c, () => c.sign({ now: T0 + DAY, acts: [act("M_DEPRECATE", { repo_id: REPO, versions: "<2.0.0", reason_code: "broken" }, T0 + DAY)] }), VANISHED_ROW);
  // put back, it signs
  editState(c, (w) => { w.rows = [{ ...STICKY, act_ref: "act-x" }]; });
  c.sign({ now: T0 + DAY });
  assert.deepEqual(listOf(c).rows, [STICKY]);
});

test("a sticky row whose at was changed, or that is no longer a security revoke, is not the row clients hold", () => {
  const c = revoked();
  editState(c, (w) => { w.rows[0].at = T0 + 5; });
  refusedUnchanged(c, () => c.sign({ now: T0 + DAY }), VANISHED_ROW);
  const d = revoked();
  editState(d, (w) => { w.rows[0].reason_code = "policy"; });
  refusedUnchanged(d, () => d.sign({ now: T0 + DAY }), VANISHED_ROW);
  const e = revoked();
  editState(e, (w) => { Object.assign(w.rows[0], { act: "yank", floor_effect: "no-offer", reason_code: "broken" }); });
  refusedUnchanged(e, () => e.sign({ now: T0 + DAY }), VANISHED_ROW);
  // another version range is another subject
  const f = revoked();
  editState(f, (w) => { w.rows[0].versions = "<=1.0.1"; });
  refusedUnchanged(f, () => f.sign({ now: T0 + DAY }), VANISHED_ROW);
});

test("a row that is not sticky may vanish: clients release it by absence", () => {
  const c = makeCatalogue();
  c.sign({ candidates: [candidate({ repo_id: REPO, slug: "peak-gi" })] });
  c.sign({ acts: [act("M_YANK", { repo_id: REPO, versions: "*", reason_code: "broken" }), revoke({ versions: "<0.5.0", reason_code: "policy" }, T0 + 1)] });
  assert.deepEqual(listOf(c).rows.map((r) => [r.act, r.reason_code]), [["yank", "broken"], ["revoke", "policy"]]);
  editState(c, (w) => { w.rows = []; });
  c.sign({ now: T0 + DAY });
  assert.deepEqual(listOf(c).rows, []);
  assert.deepEqual(listOf(c).lifts, []);
});

test("a state file replaced by an older one refuses the run", () => {
  const c = makeCatalogue();
  c.sign({ candidates: [candidate({ repo_id: REPO, slug: "peak-gi" })] });
  const older = fs.readFileSync(withdrawnFile(c), "utf8");
  c.sign({ acts: [revoke()] });
  const withRow = fs.readFileSync(withdrawnFile(c), "utf8");
  fs.writeFileSync(withdrawnFile(c), older);
  refusedUnchanged(c, () => c.sign({ now: T0 + DAY }), VANISHED_ROW);
  // the file lost altogether reads as an empty state: the same refusal
  fs.rmSync(withdrawnFile(c));
  refusedUnchanged(c, () => c.sign({ now: T0 + DAY }), VANISHED_ROW);
  // and an older state from after the lift has lost the lift
  fs.writeFileSync(withdrawnFile(c), withRow);
  c.sign({ now: T0 + DAY, acts: [liftAct({}, T0 + DAY)] });
  fs.writeFileSync(withdrawnFile(c), older);
  refusedUnchanged(c, () => c.sign({ now: T0 + 2 * DAY }),
    new RegExp(`^Error: E_SELF_VERIFY: withdrawn: sticky-lift-vanished: repo ${REPO}  <=1\\.0\\.0 at ${T0} is lifted in the list published before this one .*; the state has no record of it`));
  // with the row back and the lift gone, both the row is not contradicted and the lift is still owed
  fs.writeFileSync(withdrawnFile(c), withRow);
  refusedUnchanged(c, () => c.sign({ now: T0 + 2 * DAY }), /sticky-lift-vanished/);
});

const youngLifts = (n) => Array.from({ length: n }, (_, i) => ({ repo_id: 5, versions: `<0.0.${i}`, lifts_at: T0 - 9 * DAY, at: T0 - 8 * DAY + i, applied_at: T0 - 8 * DAY, by: "mod-1", reason_text: "x", lifted: ["revoke"], sticky: true }));

test("a sticky lift younger than 365 days never leaves the list; one a year old may make room, and so may a lift of a row that was not sticky", () => {
  const c = revoked();
  editState(c, (w) => { w.lifts = youngLifts(LIFTS_MAX); });
  c.sign();
  assert.equal(listOf(c).lifts.length, LIFTS_MAX);
  const gone = `repo 5  <0\\.0\\.0 at ${T0 - 9 * DAY}`;
  // taken out of the state
  const full = c.state("withdrawn.json");
  editState(c, (w) => { w.lifts.shift(); });
  refusedUnchanged(c, () => c.sign({ now: T0 + DAY }), new RegExp(`sticky-lift-vanished: ${gone} .*; the state has no record of it, so it is read as a young lift of a security revoke`));
  // pushed off the end of the list by a record written beside it: the state knows it, and knows it is young
  editState(c, () => ({ ...full, lifts: [...full.lifts, { ...youngLifts(1)[0], versions: "<9.9.9", at: T0 }] }));
  refusedUnchanged(c, () => c.sign({ now: T0 + DAY }), new RegExp(`sticky-lift-vanished: ${gone} .*; it lifted a security revoke and the signer applied it less than 365 days ago`));
  // a year after the signer applied it, retention drops it for the next security lift, and that list is signed
  editState(c, () => ({ ...full, lifts: full.lifts.map((l, i) => (i === 0 ? { ...l, applied_at: T0 - LIFT_KEEP_SECONDS } : l)) }));
  assert.deepEqual(c.sign({ acts: [liftAct()] }).refusedActs, []);
  assert.equal(listOf(c).lifts.length, LIFTS_MAX);
  assert.ok(!listOf(c).lifts.some((l) => l.versions === "<0.0.0"), "the lift applied a year ago made room");
  assert.ok(listOf(c).lifts.some((l) => l.repo_id === REPO), "for the new one");
  // a lift of a row that was not sticky makes room at any age
  c.sign({ acts: [revoke({ versions: "*" }, T0 + 1)] });
  editState(c, (w) => { w.lifts[5].sticky = false; });
  assert.deepEqual(c.sign({ acts: [liftAct({ versions: "*", lifts_at: T0 + 1 })] }).refusedActs, []);
  assert.equal(listOf(c).lifts.length, LIFTS_MAX);
});

test("the first run has no list to answer to, signs, and leaves the one the next run answers to", () => {
  const c = makeCatalogue();
  assert.equal(lastWithdrawn({ dataDir: c.data, state: loadState(c.data), kindKeys: c.kindKeys }), null);
  c.sign({ candidates: [candidate({ repo_id: REPO, slug: "peak-gi" })] });
  const first = lastWithdrawn({ dataDir: c.data, state: loadState(c.data), kindKeys: c.kindKeys });
  assert.deepEqual(first, { body: listOf(c), lifts: [] });
  c.sign({ acts: [revoke()] });
  c.sign({ acts: [liftAct()] });
  const third = lastWithdrawn({ dataDir: c.data, state: loadState(c.data), kindKeys: c.kindKeys });
  assert.deepEqual(third.body, listOf(c));
  assert.deepEqual(third.lifts, c.state("withdrawn.json").lifts, "with what the state records of its lifts");
  // a state seeded by hand before anything was signed is still a first run
  const d = makeCatalogue();
  writeJson(withdrawnFile(d), { rows: [{ ...STICKY, act_ref: "seed" }], held: [], lifts: [], spent: [] });
  writeJson(path.join(d.data, "floors.json"), { kind: "games", index: 0, withdrawn: 0 });
  d.sign();
  assert.deepEqual(listOf(d).rows, [STICKY]);
});

test("a previous list that is missing after a signing, unreadable, unsigned or not the last one refuses the run: it is never read as nothing to compare with", () => {
  const PREVIOUS = /^Error: E_STATE_PREVIOUS: dist\/games-withdrawn\.json /;
  const whole = (re) => new RegExp(`${PREVIOUS.source}${re}; refusing to sign a withdrawn list that cannot be compared with the last one published`);
  // missing, with each trace of a signing on its own
  const c = revoked();
  const kept = fs.readFileSync(distFile(c), "utf8");
  fs.rmSync(distFile(c));
  refusedUnchanged(c, () => c.sign({ now: T0 + DAY }), whole(`is missing, and this is not a first run: floors\\.json records signed documents \\(index ${T0 + 1}, withdrawn ${T0 + 1}\\), dist/ holds a signed index, 1 applied act is recorded`));
  fs.rmSync(path.join(c.data, "dist", "games-index.json"));
  refusedUnchanged(c, () => c.sign({ now: T0 + DAY }), whole("is missing, and this is not a first run: floors\\.json records signed documents .*, 1 applied act is recorded"));
  fs.rmSync(path.join(c.data, "acts"), { recursive: true });
  refusedUnchanged(c, () => c.sign({ now: T0 + DAY }), whole("is missing, and this is not a first run: floors\\.json records signed documents \\(.*\\)"));
  const onlyActs = revoked();
  fs.rmSync(path.join(onlyActs.data, "dist"), { recursive: true });
  writeJson(path.join(onlyActs.data, "floors.json"), { kind: "games", index: 0, withdrawn: 0 });
  refusedUnchanged(onlyActs, () => onlyActs.sign({ now: T0 + DAY }), whole("is missing, and this is not a first run: 1 applied act is recorded"));
  const onlyIndex = makeCatalogue();
  onlyIndex.sign();
  fs.rmSync(distFile(onlyIndex));
  writeJson(path.join(onlyIndex.data, "floors.json"), { kind: "games", index: 0, withdrawn: 0 });
  refusedUnchanged(onlyIndex, () => onlyIndex.sign({ now: T0 + DAY }), whole("is missing, and this is not a first run: dist/ holds a signed index"));

  // not JSON
  const d = revoked();
  fs.writeFileSync(distFile(d), kept.slice(0, 40));
  refusedUnchanged(d, () => d.sign({ now: T0 + DAY }), whole("cannot be read \\(.*\\)"));
  fs.writeFileSync(distFile(d), "null");
  refusedUnchanged(d, () => d.sign({ now: T0 + DAY }), whole("does not verify: not a JSON object .*"));

  // the row edited out of the kept list itself, to go with a state that dropped it: the signature no longer covers the body
  const e = revoked();
  const edited = e.dist("games-withdrawn.json");
  edited.signed.rows = [];
  writeJson(distFile(e), edited);
  editState(e, (w) => { w.rows = []; });
  refusedUnchanged(e, () => e.sign({ now: T0 + DAY }), whole("does not verify: no trusted key signed this document \\(trusted: astra-games-2026a, astra-games-2026b; it names astra-games-2026a\\)"));
  // signed, by a key that is not a games key of trust.json (here another kind's)
  const forged = signBoth({
    state: { ...loadState(e.data), withdrawn: { rows: [], held: [], lifts: [], spent: [] } }, seedLoaders: { loaders: [] }, previous: null, now: T0,
    kindKeys: { current: { ...e.kindKeys.current, public_key: e.commandsCurrent.publicB64 }, next: e.kindKeys.next },
    signers: selectSigners({ env: { GAMES_SIGNING_KEY_CURRENT: e.commandsCurrent.seedB64 }, floors: {}, now: T0, kindKeys: { current: { ...e.kindKeys.current, public_key: e.commandsCurrent.publicB64 }, next: e.kindKeys.next } }),
  });
  writeJson(distFile(e), forged.withdrawn);
  refusedUnchanged(e, () => e.sign({ now: T0 + DAY }), whole("does not verify: no trusted key signed this document .*"));

  // the list before the last one: correctly signed, and it does not carry the newest revoke
  const f = makeCatalogue();
  f.sign({ candidates: [candidate({ repo_id: REPO, slug: "peak-gi" })] });
  const before = fs.readFileSync(distFile(f), "utf8");
  f.sign({ acts: [revoke()] });
  fs.writeFileSync(distFile(f), before);
  editState(f, (w) => { w.rows = []; });
  refusedUnchanged(f, () => f.sign({ now: T0 + DAY }), whole(`is serial ${T0} and floors\\.json says the last list signed is ${T0 + 1}: one of the two is not from the last run`));
});

test("the previous list verifies under the keys this signer signed lists with: trust.json's two, and a key floors.json records as spent for the list", () => {
  const c = revoked(); // signed by A alone
  const spentA = { key_id: "astra-games-2026a", public_key: c.current.publicB64 };
  // a ceremony drops A from trust.json; the ledger is what still names it
  const kN1 = c.useTrust(c.promotedTrust(throwawayKey()));
  const floors = c.state("floors.json");
  const state = () => loadState(c.data);
  assert.throws(() => lastWithdrawn({ dataDir: c.data, state: state(), kindKeys: kN1 }), /^Error: E_STATE_PREVIOUS: dist\/games-withdrawn\.json does not verify: no trusted key signed this document \(trusted: astra-games-2026b, astra-games-2026c; it names astra-games-2026a\)/);
  // spent for the index only is not spent for the list
  writeJson(path.join(c.data, "floors.json"), { ...floors, spent: { [INDEX_SCHEMA]: [spentA], [WITHDRAWN_SCHEMA]: [] } });
  assert.throws(() => lastWithdrawn({ dataDir: c.data, state: state(), kindKeys: kN1 }), /does not verify/);
  // a bare key id (a ledger entry from before 2026-11-07) names no public key to verify under
  writeJson(path.join(c.data, "floors.json"), { ...floors, spent: { [INDEX_SCHEMA]: [], [WITHDRAWN_SCHEMA]: ["astra-games-2026a"] } });
  assert.throws(() => lastWithdrawn({ dataDir: c.data, state: state(), kindKeys: kN1 }), /does not verify/);
  writeJson(path.join(c.data, "floors.json"), { ...floors, spent: { [INDEX_SCHEMA]: [], [WITHDRAWN_SCHEMA]: [spentA] } });
  assert.deepEqual(lastWithdrawn({ dataDir: c.data, state: state(), kindKeys: kN1 }).body.rows, [STICKY]);
});

// the rule itself, on two bodies

const prev = (rows, lifts = [], records = lifts) => ({ body: { serial: 77, rows, lifts }, lifts: records });
const next = (rows, lifts = []) => ({ rows, lifts });
const LIFT = { ...SUBJECT, lifts_at: T0, at: T0 + 60 };

test("successorProblems: a sticky row is kept or lifted, by the subject as a client reads it and by its at", () => {
  assert.deepEqual(successorProblems(null, next([]), T0), [], "no list was ever published");
  assert.throws(() => successorProblems(undefined, next([]), T0), /needs the withdrawn list published last, or null when none ever was/);
  assert.deepEqual(successorProblems(prev([STICKY]), next([STICKY]), T0), []);
  assert.deepEqual(successorProblems(prev([STICKY]), next([], [LIFT]), T0), []);
  assert.deepEqual(successorProblems(prev([STICKY]), next([]), T0), [
    `sticky-row-vanished: repo ${REPO}  <=1.0.0 at ${T0} is a security revoke in the list published before this one (serial 77), and this one neither carries that row nor lifts it; a client that applied it keeps it, and a fresh install would be offered what it revokes`,
  ]);
  // the client's reading of a subject: entry_id trimmed and lowercased, none equal to none only, versions byte for byte
  const named = { ...STICKY, entry_id: "Author/Peak-GI" };
  assert.deepEqual(successorProblems(prev([named]), next([{ ...named, entry_id: " author/peak-gi\t" }]), T0), [], "the same row, spelled as another act wrote it");
  assert.deepEqual(successorProblems(prev([named]), next([], [{ ...LIFT, entry_id: "AUTHOR/PEAK-GI" }]), T0), [], "the same subject in the lift");
  assert.deepEqual(successorProblems(prev([{ ...STICKY, entry_id: null }]), next([STICKY]), T0), [], "null is none");
  assert.match(successorProblems(prev([named]), next([STICKY]), T0)[0], /^sticky-row-vanished: repo 930000001 Author\/Peak-GI <=1\.0\.0 at /, "an entry is not no entry");
  assert.match(successorProblems(prev([named]), next([{ ...named, entry_id: "author/peak" }]), T0)[0], /^sticky-row-vanished: /);
  assert.match(successorProblems(prev([STICKY]), next([{ ...STICKY, versions: "<=1.0.0 " }]), T0)[0], /^sticky-row-vanished: /, "versions byte for byte");
  assert.match(successorProblems(prev([STICKY]), next([{ ...STICKY, repo_id: REPO + 1 }]), T0)[0], /^sticky-row-vanished: /);
  // the at is part of what a client holds, and of what a lift names
  assert.match(successorProblems(prev([STICKY]), next([{ ...STICKY, at: T0 + 1 }]), T0)[0], /^sticky-row-vanished: /);
  assert.match(successorProblems(prev([STICKY]), next([], [{ ...LIFT, lifts_at: T0 + 1 }]), T0)[0], /^sticky-row-vanished: /, "a lift of that subject's other row lifts another row");
  assert.match(successorProblems(prev([STICKY]), next([], [{ ...LIFT, lifts_at: T0 - 1, at: T0 }]), T0)[0], /^sticky-row-vanished: /);
  // still listed, as something a fresh install reads as less
  assert.match(successorProblems(prev([STICKY]), next([{ ...STICKY, act: "yank", floor_effect: "no-offer", reason_code: "broken" }]), T0)[0], /^sticky-row-vanished: /);
  // a row no client can key matches nothing
  const unreadable = { ...STICKY, entry_id: " " };
  assert.match(successorProblems(prev([unreadable]), next([unreadable], [{ ...LIFT, entry_id: " " }]), T0)[0], /^sticky-row-vanished: /);
  // rows that are not sticky owe nothing, each alone
  const banner = { ...STICKY, act: "deprecate", floor_effect: "no-offer", reason_code: "broken" };
  assert.deepEqual(successorProblems(prev([banner, { ...STICKY, reason_code: "policy" }, { ...STICKY, act: "yank", reason_code: "broken" }]), next([]), T0), []);
  // every vanished row is named
  assert.equal(successorProblems(prev([STICKY, { ...STICKY, versions: "*", at: T0 + 9 }]), next([]), T0).length, 2);
});

test("successorProblems: a lift stays unless retention may have dropped it, read from the state's record of it", () => {
  const record = (o = {}) => ({ ...LIFT, applied_at: T0, by: "mod-1", reason_text: "x", lifted: ["revoke"], sticky: true, ...o });
  const now = T0 + 400 * DAY;
  const gone = (records, at = now) => successorProblems(prev([], [LIFT], records), next([]), at);
  assert.deepEqual(successorProblems(prev([], [LIFT], [record()]), next([], [LIFT]), now), []);
  assert.deepEqual(successorProblems(prev([], [LIFT], [record()]), next([], [{ ...LIFT, entry_id: null, at: T0 + 61 }]), now), [], "kept is the subject and what it lifts");
  assert.deepEqual(gone([record({ sticky: false, lifted: ["yank"] })], T0 + 61), [], "no client needs the lift of a row that was not sticky");
  assert.deepEqual(gone([record()]), [], "applied 400 days ago");
  assert.deepEqual(gone([record()], T0 + LIFT_KEEP_SECONDS), [], "365 days to the second, as retention counts");
  assert.deepEqual(gone([record()], T0 + LIFT_KEEP_SECONDS - 1), [
    `sticky-lift-vanished: repo ${REPO}  <=1.0.0 at ${T0} is lifted in the list published before this one (serial 77), and this one does not carry that lift; it lifted a security revoke and the signer applied it less than 365 days ago; a client that has not read it yet would keep the revoke for good`,
  ]);
  // aged from when the signer applied it, never from its own at
  assert.match(gone([record({ at: T0 - 500 * DAY, applied_at: now - DAY })])[0], /^sticky-lift-vanished: /);
  assert.deepEqual(gone([record({ applied_at: undefined })]), [], "a record from before applied_at is aged by its at");
  // what the record does not say is read the safe way
  assert.match(gone([record({ sticky: undefined })], T0 + 61)[0], /^sticky-lift-vanished: /, "no `sticky`: sticky");
  assert.match(gone([])[0], /^sticky-lift-vanished: .*; the state has no record of it, so it is read as a young lift of a security revoke; /);
  assert.match(gone([record({ lifts_at: T0 + 1 })])[0], /the state has no record of it/, "another row's lift is not its record");
  assert.match(gone([record({ versions: "*" })])[0], /the state has no record of it/);
  assert.match(gone([record({ sticky: false }), record()], T0 + 61)[0], /^sticky-lift-vanished: /, "two records of it: every one must let it go");
  // a row coming back does not stand in for its lift
  assert.match(successorProblems(prev([], [LIFT], [record()]), next([STICKY]), T0 + 61)[0], /^sticky-lift-vanished: /);
});

test("the trial refuses, as an act, one whose applying drops what the last list still owes; what the state had already lost is not the act's", () => {
  const c = revoked();
  editState(c, (w) => { w.lifts = [...youngLifts(LIFTS_MAX - 1), { ...youngLifts(1)[0], versions: "<7.7.7", sticky: false }]; });
  c.sign();
  const state = loadState(c.data);
  const previous = lastWithdrawn({ dataDir: c.data, state, kindKeys: c.kindKeys });
  const o = { now: T0, reserved: undefined, seedLoaders: { add: [], remove: [] } };
  // as the run has it: the lift of a row that was not sticky makes room for the new lift
  assert.equal(tryAct(liftAct(), state, { ...o, previous }).problems, undefined);
  // had that lift been of a security revoke, applying the act would drop a lift clients still need
  const owed = { ...previous, lifts: previous.lifts.map((l) => ({ ...l, sticky: true })) };
  assert.deepEqual(tryAct(liftAct(), state, { ...o, previous: owed }).problems, [
    `applied, this act would leave a withdrawn list the signer refuses to sign: sticky-lift-vanished: repo 5  <7.7.7 at ${T0 - 9 * DAY} is lifted in the list published before this one (serial ${T0 + 2}), and this one does not carry that lift; it lifted a security revoke and the signer applied it less than 365 days ago; a client that has not read it yet would keep the revoke for good`,
  ]);
  assert.throws(() => tryAct(liftAct(), state, o), /needs the withdrawn list published last/, "the trial never runs without it");
  // introduced: after, not before
  const lost = structuredClone(state);
  lost.withdrawn.rows = [];
  assert.match(listProblemsIntroduced(state, lost, T0, previous)[0], /^sticky-row-vanished: /);
  assert.deepEqual(listProblemsIntroduced(lost, lost, T0, previous), [], "already lost is not this act's doing");
  assert.equal(tryAct(act("M_DEPRECATE", { repo_id: REPO, versions: "<2.0.0", reason_code: "broken" }), lost, { ...o, previous }).problems, undefined, "the act is applied, and the run stops at signing");
  // and signing is where it stops
  const signers = selectSigners({ env: c.env, floors: state.floors, kindKeys: c.kindKeys, now: T0 });
  assert.throws(() => signBoth({ state: lost, seedLoaders: { loaders: [] }, signers, kindKeys: c.kindKeys, now: T0, previous }), /^Error: E_SELF_VERIFY: withdrawn: sticky-row-vanished: /);
  assert.throws(() => signBoth({ state: lost, seedLoaders: { loaders: [] }, signers, kindKeys: c.kindKeys, now: T0 }), /needs the withdrawn list published last/);
  assert.equal(signBoth({ state, seedLoaders: { loaders: [] }, signers, kindKeys: c.kindKeys, now: T0, previous }).withdrawn.signed.rows.length, 1);
});
