// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// bin/ceremony-ready.mjs: before a games trust.json N+1 that promotes `next`
// to `current` is published, every served games document must verify under N
// and under N+1 (games-index-v1 §3). Trust N lists current A and next B; N+1
// lists current B and a fresh next C. Every key is a throwaway made here; the
// command's `main` takes the throwaway roots, which its command line cannot.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { main } from "../bin/ceremony-ready.mjs";
import { ceremonyChecks, duplicateMembers, promotionProblems } from "../lib/ceremony.mjs";
import { INDEX_SCHEMA, WITHDRAWN_SCHEMA } from "../lib/documents.mjs";
import { writeJson } from "../lib/state.mjs";
import { loadTrust } from "../lib/trust.mjs";
import { privateKeyFromSeed, signEnvelope } from "../lib/vendor/astra-registry/bot/lib/sign.mjs";
import { jcs } from "../lib/vendor/astra-registry/tools/lib/canonical.mjs";
import { candidate, kindKeyRow, makeCatalogue, NOT_BEFORE, NOT_BEFORE_FRESH, NOT_BEFORE_NEXT, T0 } from "./catalogue.mjs";
import { ROOT, throwawayKey, tmpdir } from "./helpers.mjs";

const CLI = path.join(ROOT, "bin", "ceremony-ready.mjs");
const HOSTS = ["https://registry.minice.ai", "https://registry.knice.tech"];

/** A catalogue that has rotated to B with A's seed beside it, its two documents, and the candidate N+1 (root-signed). */
function ceremony() {
  const c = makeCatalogue({ withNext: true });
  c.sign({ candidates: [candidate()] });
  const dir = tmpdir("agc-ceremony-");
  const trustN = path.join(dir, "trust-n.json");
  fs.copyFileSync(c.trustFile, trustN);
  const fresh = throwawayKey();
  const nextTrust = path.join(dir, "trust-n1.json");
  writeJson(nextTrust, c.promotedTrust(fresh));
  const index = path.join(c.data, "dist", "games-index.json");
  const withdrawn = path.join(c.data, "dist", "games-withdrawn.json");
  const write = (name, doc) => {
    const f = path.join(dir, name);
    fs.writeFileSync(f, typeof doc === "string" ? doc : JSON.stringify(doc));
    return f;
  };
  const kN1 = loadTrust({ doc: c.promotedTrust(fresh), now: T0, roots: c.roots }).kindKeys;
  return { c, dir, trustN, nextTrust, index, withdrawn, fresh, write, kN1 };
}

async function run(argv, { roots, fetchImpl } = {}) {
  const out = [];
  const err = [];
  const noNetwork = async (url) => {
    throw new Error(`no network in this test (${url})`);
  };
  const code = await main(argv, { roots, now: T0, fetchImpl: fetchImpl ?? noNetwork, out: (l) => out.push(l), err: (l) => err.push(l) });
  return { code, out, err, text: [...out, ...err].join("\n") };
}

const argsFor = (k, docs = [k.index, k.withdrawn], nextTrust = k.nextTrust) => ["--trust", k.trustN, "--next-trust", nextTrust, ...docs.flatMap((d) => ["--doc", d])];
const read = (f) => JSON.parse(fs.readFileSync(f, "utf8"));
const seedKey = (key) => privateKeyFromSeed(Buffer.from(key.seedB64, "base64"));
/** Sign a games body as the bridge does: each [key_id, throwaway key] in order. */
const signedBy = (domain, signed, keys) => signEnvelope({ domain, signed, signers: keys.map(([key_id, key]) => ({ key_id, privateKey: seedKey(key) })) });

/** What both hosts serve, by URL: trust.json N and the two documents, overridable per URL. */
function servedBy(k, overrides = {}) {
  const map = {};
  for (const h of HOSTS) {
    map[`${h}/registry/v1/trust.json`] = fs.readFileSync(k.trustN, "utf8");
    map[`${h}/registry/v1/games/index.json`] = fs.readFileSync(k.index, "utf8");
    map[`${h}/registry/v1/games/withdrawn.json`] = fs.readFileSync(k.withdrawn, "utf8");
  }
  Object.assign(map, overrides);
  const asked = [];
  const fetchImpl = async (url) => {
    asked.push(url);
    return url in map ? new Response(map[url], { status: 200 }) : new Response("not found", { status: 404 });
  };
  return { map, asked, fetchImpl };
}

test("ceremony-ready passes two bridged documents, naming the keys under N and N+1; a --doc run says it is not what is served", async () => {
  const k = ceremony();
  const r = await run(argsFor(k), { roots: k.c.roots });
  assert.equal(r.code, 0, r.text);
  assert.ok(r.out.includes(`ok   local:${k.index} ${INDEX_SCHEMA}: under N (serial 5) astra-games-2026a (current), astra-games-2026b (next); under N+1 (serial 6) astra-games-2026b (current); body games-current`), r.text);
  assert.ok(r.out.includes(`ok   local:${k.withdrawn} ${WITHDRAWN_SCHEMA}: under N (serial 5) astra-games-2026a (current), astra-games-2026b (next); under N+1 (serial 6) astra-games-2026b (current); body games-current`), r.text);
  assert.ok(r.out.some((l) => l.startsWith("source: local files, NOT what is served.")), r.text);
  assert.equal(r.out.at(-1), "ready (local files only, NOT what is served): both documents verify under trust.json N and N+1.");
  assert.ok(r.out.some((l) => /^trust\.json N\+1: serial 6, root-signed \(test-root\)/.test(l)), r.text);

  // the bytes the owner signs: the sha256 of N+1's JCS body, printed
  const body = read(k.nextTrust).signed;
  const sha = crypto.createHash("sha256").update(jcs(body), "utf8").digest("hex");
  assert.ok(r.out.some((l) => l.includes(`sha256(JCS(signed)) ${sha}`)), r.text);

  // N+1 need not be root-signed yet: a bare body, or an envelope with no signature, reads the same, with a warning
  for (const [name, doc] of [["bare", body], ["unsigned", { signed: body, signatures: [] }]]) {
    const u = await run(argsFor(k, undefined, k.write(`trust-n1-${name}.json`, doc)), { roots: k.c.roots });
    assert.equal(u.code, 0, `${name}: ${u.text}`);
    assert.match(u.err.join("\n"), new RegExp(`warning: trust\\.json N\\+1 carries no root signature\\. The owner must sign exactly the body whose JCS sha256 is ${sha}`));
  }
  // signatures that are there must hold
  const forged = { signed: body, signatures: read(k.nextTrust).signatures.map((s) => ({ ...s, sig: read(k.trustN).signatures[0].sig })) };
  const f = await run(argsFor(k, undefined, k.write("trust-n1-forged.json", forged)), { roots: k.c.roots });
  assert.equal(f.code, 1, f.text);
  assert.match(f.err.join("\n"), /FAIL trust\.json N\+1 .*it carries signatures, and they do not hold: E_TRUST_UNVERIFIED/);
});

test("ceremony-ready fetches trust.json and both documents from both hosts by default, and the hosts must serve one trust.json", async () => {
  const k = ceremony();
  const s = servedBy(k);
  const r = await run(["--next-trust", k.nextTrust], { roots: k.c.roots, fetchImpl: s.fetchImpl });
  assert.equal(r.code, 0, r.text);
  assert.deepEqual([...s.asked].sort(), Object.keys(s.map).sort(), "trust.json and both documents, from both hosts");
  for (const host of ["registry.minice.ai", "registry.knice.tech"]) {
    for (const schema of [INDEX_SCHEMA, WITHDRAWN_SCHEMA]) assert.ok(r.out.some((l) => l.startsWith(`ok   ${host} ${schema}: `)), `${host} ${schema}\n${r.text}`);
  }
  assert.equal(r.out.at(-1), "ready: all 4 documents served by registry.minice.ai and registry.knice.tech verify under trust.json N and N+1.");

  // one host still serves an older trust.json
  const older = k.c.trustWith([kindKeyRow("games", "current", "astra-games-2026a", k.c.current), kindKeyRow("games", "next", "astra-games-2026b", k.c.next)], { serial: 4 });
  const split = servedBy(k, { "https://registry.knice.tech/registry/v1/trust.json": JSON.stringify(older) });
  const d = await run(["--next-trust", k.nextTrust], { roots: k.c.roots, fetchImpl: split.fetchImpl });
  assert.equal(d.code, 1, d.text);
  assert.match(d.err.join("\n"), /FAIL trust\.json N: .*registry\.minice\.ai.* serves serial 5, .*registry\.knice\.tech.* serves serial 4; the hosts must serve the same trust\.json/);
  // the same bytes in another layout are the same document
  const pretty = servedBy(k, { "https://registry.knice.tech/registry/v1/trust.json": JSON.stringify(read(k.trustN), null, 4) });
  assert.equal((await run(["--next-trust", k.nextTrust], { roots: k.c.roots, fetchImpl: pretty.fetchImpl })).code, 0);
});

test("ceremony-ready requires both schemas from every source", async () => {
  const k = ceremony();
  const only = await run(argsFor(k, [k.index]), { roots: k.c.roots });
  assert.equal(only.code, 1, only.text);
  assert.ok(only.out.includes(`FAIL local files ${WITHDRAWN_SCHEMA}: 0 of the --doc files are one; pass exactly one index and one withdrawn list`), only.text);
  const twice = await run(argsFor(k, [k.index, k.write("index-copy.json", read(k.index)), k.withdrawn]), { roots: k.c.roots });
  assert.equal(twice.code, 1, twice.text);
  assert.ok(twice.out.includes(`FAIL local files ${INDEX_SCHEMA}: 2 of the --doc files are one; pass exactly one index and one withdrawn list`), twice.text);
  // there is no way to check fewer hosts than both
  assert.equal((await run(["--next-trust", k.nextTrust, "--host", "https://registry.minice.ai"], { roots: k.c.roots })).code, 2);
  // a host that serves only one of the two documents is unreadable, never half a pass
  const half = servedBy(k);
  delete half.map["https://registry.knice.tech/registry/v1/games/withdrawn.json"];
  assert.equal((await run(["--next-trust", k.nextTrust], { roots: k.c.roots, fetchImpl: half.fetchImpl })).code, 2);
});

test("ceremony-ready fails (b) on a B-only games-next document: N+1 makes B current, and the body names next", async () => {
  const k = ceremony();
  // what is served when B signs alone: the routine rotation as it was before the bridge
  k.c.sign({ env: { GAMES_SIGNING_KEY_NEXT: k.c.next.seedB64 } });
  const r = await run(argsFor(k), { roots: k.c.roots });
  assert.equal(r.code, 1, r.text);
  const line = r.out.find((l) => l.startsWith(`FAIL local:${k.index} ${INDEX_SCHEMA}: `));
  assert.ok(line, r.text);
  assert.match(line, /\(b\) under trust N\+1: the body names games-next and the keys that verified it are the current key astra-games-2026b/);
  assert.doesNotMatch(line, /\(a\)|\(c\)/, "under N it is fine, and N+1's current key does verify it: the claimed role is what fails");
  assert.ok(r.out.some((l) => l.startsWith(`FAIL local:${k.withdrawn} ${WITHDRAWN_SCHEMA}: (b)`)), r.text);
  assert.match(r.err.at(-1), /not ready: 2 check\(s\) fail/);
});

test("ceremony-ready fails (a) on a document signed only by B with games-current: under N, B is next", async () => {
  const k = ceremony();
  const bridged = read(k.index);
  const bOnly = k.write("b-only-current.json", { ...bridged, signatures: bridged.signatures.filter((s) => s.key_id === "astra-games-2026b") });
  const r = await run(argsFor(k, [bOnly, k.withdrawn]), { roots: k.c.roots });
  assert.equal(r.code, 1, r.text);
  const line = r.out.find((l) => l.startsWith(`FAIL local:${bOnly} ${INDEX_SCHEMA}: `));
  assert.match(line, /^FAIL .*: \(a\) under trust N: the body names games-current and the keys that verified it are the next key astra-games-2026b$/);
  assert.ok(r.out.some((l) => l.startsWith(`ok   local:${k.withdrawn}`)), "the bridged withdrawn list still passes");
});

test("ceremony-ready runs every body check a verifier makes, the byte cap, and a strict parse, under both trust.json", async () => {
  const k = ceremony();
  const good = read(k.index);
  const bridge = (signed) => signedBy(INDEX_SCHEMA, signed, [["astra-games-2026b", k.c.next], ["astra-games-2026a", k.c.current]]);
  const cases = [
    ["serial is not issued_at", { ...good.signed, serial: good.signed.issued_at + 1 }, /\(a\)\+\(b\) serial \d+ is not issued_at \d+/],
    ["a 30-day span", { ...good.signed, expires_at: good.signed.issued_at + 30 * 86400 }, /\(a\)\+\(b\) expiry-span-too-long/],
    ["entries is not a list", { ...good.signed, entries: "not-a-list" }, /\(a\)\+\(b\) schema: /],
    ["issued two days ahead", { ...good.signed, serial: T0 + 2 * 86400, issued_at: T0 + 2 * 86400, expires_at: T0 + 9 * 86400 }, /\(a\)\+\(b\) issued-at-too-far-ahead/],
  ];
  for (const [why, signed, expect] of cases) {
    const f = k.write(`body-${why.replaceAll(" ", "-")}.json`, bridge(signed));
    const r = await run(argsFor(k, [f, k.withdrawn]), { roots: k.c.roots });
    assert.equal(r.code, 1, `${why}: ${r.text}`);
    assert.match(r.out.find((l) => l.startsWith(`FAIL local:${f}`)) ?? "", expect, `${why}: ${r.text}`);
  }
  // over the client's byte cap: the unsigned $comment is enough to make the whole document refused
  const big = k.write("big.json", { ...good, $comment: "x".repeat(1_048_576) });
  const b = await run(argsFor(k, [big, k.withdrawn]), { roots: k.c.roots });
  assert.equal(b.code, 1, b.text);
  assert.match(b.out.find((l) => l.startsWith(`FAIL local:${big}`)), /\(a\)\+\(b\) it is \d+ bytes, over the 1048576-byte ceiling a client refuses whole/);
  // a repeated member: JSON.parse keeps the last one silently, a strict client refuses the document
  const text = fs.readFileSync(k.index, "utf8").replace(/"signed": \{/, `"signed": {"key_id": "games-next",`);
  assert.notEqual(text, fs.readFileSync(k.index, "utf8"));
  const dup = k.write("dup.json", text);
  const d = await run(argsFor(k, [dup, k.withdrawn]), { roots: k.c.roots });
  assert.equal(d.code, 1, d.text);
  assert.match(d.out.find((l) => l.startsWith(`FAIL local:${dup}`)), /\(a\)\+\(b\) it repeats the member\(s\) "key_id", which a strict parser refuses/);
  assert.deepEqual(duplicateMembers('{"a": {"b": 1, "b": 2}, "c": [{"d": 1}, {"d": 2}], "\\u0061": "x", "s": "\\"a\\": 1"}'), ["b", "a"], "per object, after unescaping, and never inside a string");
});

test("ceremony-ready exits 2 when anything cannot be fetched or read, never 0", async () => {
  const k = ceremony();
  const cases = {
    "network down": async (url) => {
      throw new TypeError("fetch failed", { cause: { code: "ECONNREFUSED", url } });
    },
    "one document 404s": (() => {
      const s = servedBy(k);
      delete s.map["https://registry.knice.tech/registry/v1/games/withdrawn.json"];
      return s.fetchImpl;
    })(),
    "one host's trust.json 404s": (() => {
      const s = servedBy(k);
      delete s.map["https://registry.knice.tech/registry/v1/trust.json"];
      return s.fetchImpl;
    })(),
    "a CDN error page": servedBy(k, { "https://registry.minice.ai/registry/v1/games/index.json": "<html>502</html>" }).fetchImpl,
  };
  for (const [name, fetchImpl] of Object.entries(cases)) {
    const r = await run(["--next-trust", k.nextTrust], { roots: k.c.roots, fetchImpl });
    assert.equal(r.code, 2, `${name}: ${r.text}`);
    assert.match(r.err.join("\n"), /could not read .*that is not a pass/, name);
  }
  assert.equal((await run(argsFor(k, [path.join(k.dir, "missing.json")]), { roots: k.c.roots })).code, 2, "a --doc that is not there");
  assert.equal((await run(["--trust", k.trustN, "--doc", k.index])).code, 2, "no --next-trust is a usage error");

  // the command itself, as the operator runs it: a refused connection is exit 2
  const p = spawnSync(process.execPath, [CLI, "--trust", "http://127.0.0.1:1/registry/v1/trust.json", "--next-trust", k.nextTrust, "--doc", k.index], { encoding: "utf8" });
  assert.equal(p.status, 2, p.stderr);
  assert.match(p.stderr, /could not read http:\/\/127\.0\.0\.1:1\/registry\/v1\/trust\.json/);
  const help = spawnSync(process.execPath, [CLI, "--help"], { encoding: "utf8" });
  assert.equal(help.status, 0);
  assert.match(help.stdout, /need not be root-signed yet/);
});

test("ceremony-ready verifies trust.json N under the compiled roots: the operator cannot hand it others", async () => {
  const k = ceremony();
  const r = await run(argsFor(k)); // no injected roots: the compiled set, which never signed this throwaway N
  assert.equal(r.code, 1, r.text);
  assert.match(r.err.join("\n"), /FAIL trust\.json N .*E_TRUST_UNVERIFIED/);
});

test("ceremony-ready refuses a trust.json N+1 that is not the promotion it checks for", async () => {
  const k = ceremony();
  const { c } = k;
  const X = throwawayKey();
  const cases = [
    ["a fresh current", [kindKeyRow("games", "current", "astra-games-2026x", X, NOT_BEFORE_NEXT), kindKeyRow("games", "next", "astra-games-2026y", throwawayKey(), NOT_BEFORE_FRESH)],
      [/not a promotion: N\+1's current key astra-games-2026x is not N's next key astra-games-2026b/]],
    ["keeps A current", [kindKeyRow("games", "current", "astra-games-2026a", c.current, NOT_BEFORE), kindKeyRow("games", "next", "astra-games-2026c", k.fresh, NOT_BEFORE_FRESH)],
      [/not a promotion: N\+1's current key astra-games-2026a is not/, /N\+1 keeps N's current key astra-games-2026a \(as current astra-games-2026a\)/]],
    ["swaps A and B", [kindKeyRow("games", "current", "astra-games-2026b", c.next, NOT_BEFORE_NEXT), kindKeyRow("games", "next", "astra-games-2026a", c.current, NOT_BEFORE_FRESH)],
      [/N\+1 keeps N's current key astra-games-2026a \(as next astra-games-2026a\); a promotion drops it/]],
    ["renames B", [kindKeyRow("games", "current", "astra-games-2026z", c.next, NOT_BEFORE_NEXT), kindKeyRow("games", "next", "astra-games-2026c", k.fresh, NOT_BEFORE_FRESH)],
      [/N\+1 renames N's next key astra-games-2026b to astra-games-2026z/]],
  ];
  for (const [why, rows, expect] of cases) {
    const r = await run(argsFor(k, undefined, k.write(`n1-${why.replaceAll(" ", "-")}.json`, c.trustWith(rows, { serial: 6 }))), { roots: c.roots });
    assert.equal(r.code, 1, `${why}: ${r.text}`);
    for (const e of expect) assert.match(r.err.join("\n"), e, `${why}: ${r.text}`);
  }
  assert.deepEqual(promotionProblems(c.kindKeys, k.kN1), [], "the promotion itself");
});

test("a client that already retired A: the bridged document passes, and a document only A verifies under N fails (c) under N", () => {
  const k = ceremony();
  const { c } = k;
  const bridged = read(k.index);
  const ok = ceremonyChecks({ envelope: bridged, domain: INDEX_SCHEMA }, { trustN: c.kindKeys, trustN1: k.kN1, now: T0 });
  assert.equal(ok.ok, true, ok.failures.join("; "));
  assert.deepEqual(ok.underN.map((x) => x.key_id), ["astra-games-2026a", "astra-games-2026b"], "under N, B verifies it beside A: a client whose mark retired A accepts it");
  assert.deepEqual(ok.underN1.map((x) => x.key_id), ["astra-games-2026b"]);

  // the review's case: N+1 makes a fresh X current, and the signer co-signs X with A.
  // Under N only A verifies, so every client on N that retired A refuses it (key-retired),
  // and that refusal does not make it refresh trust.json.
  const X = throwawayKey();
  const n1x = loadTrust({ doc: c.trustWith([kindKeyRow("games", "current", "astra-games-2026x", X, NOT_BEFORE_NEXT), kindKeyRow("games", "next", "astra-games-2026y", throwawayKey(), NOT_BEFORE_FRESH)], { serial: 6 }), now: T0, roots: c.roots }).kindKeys;
  const xa = signedBy(INDEX_SCHEMA, bridged.signed, [["astra-games-2026x", X], ["astra-games-2026a", c.current]]);
  const r = ceremonyChecks({ envelope: xa, domain: INDEX_SCHEMA }, { trustN: c.kindKeys, trustN1: n1x, now: T0 });
  assert.deepEqual(r.failures, [`(c) under trust N, a client that already retired astra-games-2026a for ${INDEX_SCHEMA} refuses it (key-retired): no other key verifies it`],
    "(a) and (b) pass, and N+1's current key verifies it: only the retired client under N catches it");

  // and (c)'s first half: N+1's current key must be among the verifiers
  const D = throwawayKey();
  const n1d = loadTrust({ doc: c.trustWith([kindKeyRow("games", "current", "astra-games-2026d", D, NOT_BEFORE), kindKeyRow("games", "next", "astra-games-2026b", c.next, NOT_BEFORE_NEXT)], { serial: 6 }), now: T0, roots: c.roots }).kindKeys;
  const bOnlyNext = signedBy(INDEX_SCHEMA, { ...bridged.signed, key_id: "games-next" }, [["astra-games-2026b", c.next]]);
  assert.deepEqual(ceremonyChecks({ envelope: bOnlyNext, domain: INDEX_SCHEMA }, { trustN: c.kindKeys, trustN1: n1d, now: T0 }).failures,
    ["(c) N+1's current key astra-games-2026d does not verify it"]);
});
