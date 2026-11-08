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
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { main } from "../bin/ceremony-ready.mjs";
import { ceremonyChecks } from "../lib/ceremony.mjs";
import { INDEX_SCHEMA, WITHDRAWN_SCHEMA } from "../lib/documents.mjs";
import { writeJson } from "../lib/state.mjs";
import { loadTrust } from "../lib/trust.mjs";
import { candidate, kindKeyRow, makeCatalogue, NOT_BEFORE, NOT_BEFORE_FRESH, NOT_BEFORE_NEXT, T0 } from "./catalogue.mjs";
import { ROOT, throwawayKey, tmpdir } from "./helpers.mjs";

const CLI = path.join(ROOT, "bin", "ceremony-ready.mjs");

/** A catalogue that has rotated to B with A's seed beside it, its two served documents, and the candidate N+1. */
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
  return { c, dir, trustN, nextTrust, index, withdrawn, fresh };
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

test("ceremony-ready passes two bridged documents, naming the keys that verified each under N and N+1", async () => {
  const k = ceremony();
  const r = await run(argsFor(k), { roots: k.c.roots });
  assert.equal(r.code, 0, r.text);
  assert.ok(r.out.includes(`ok   local:${k.index} ${INDEX_SCHEMA}: under N (serial 5) astra-games-2026a (current), astra-games-2026b (next); under N+1 (serial 6) astra-games-2026b (current); body games-current`), r.text);
  assert.ok(r.out.includes(`ok   local:${k.withdrawn} ${WITHDRAWN_SCHEMA}: under N (serial 5) astra-games-2026a (current), astra-games-2026b (next); under N+1 (serial 6) astra-games-2026b (current); body games-current`), r.text);
  assert.match(r.out.at(-1), /^ready: all 2 document\(s\)/);

  // N+1 need not be root-signed yet: a bare body, or an envelope with no signature, reads the same
  const n1 = JSON.parse(fs.readFileSync(k.nextTrust, "utf8"));
  for (const [name, doc] of [["bare", n1.signed], ["unsigned", { signed: n1.signed, signatures: [] }]]) {
    const f = path.join(k.dir, `trust-n1-${name}.json`);
    writeJson(f, doc);
    assert.equal((await run(argsFor(k, undefined, f), { roots: k.c.roots })).code, 0, name);
  }
});

test("ceremony-ready fetches both documents from both hosts by default, and trust.json N from the registry", async () => {
  const k = ceremony();
  const served = {
    "https://registry.minice.ai/registry/v1/trust.json": fs.readFileSync(k.trustN, "utf8"),
    "https://registry.minice.ai/registry/v1/games/index.json": fs.readFileSync(k.index, "utf8"),
    "https://registry.minice.ai/registry/v1/games/withdrawn.json": fs.readFileSync(k.withdrawn, "utf8"),
    "https://registry.knice.tech/registry/v1/games/index.json": fs.readFileSync(k.index, "utf8"),
    "https://registry.knice.tech/registry/v1/games/withdrawn.json": fs.readFileSync(k.withdrawn, "utf8"),
  };
  const asked = [];
  const fetchImpl = async (url) => {
    asked.push(url);
    return url in served ? new Response(served[url], { status: 200 }) : new Response("not found", { status: 404 });
  };
  const r = await run(["--next-trust", k.nextTrust], { roots: k.c.roots, fetchImpl });
  assert.equal(r.code, 0, r.text);
  assert.deepEqual(asked.sort(), Object.keys(served).sort());
  for (const host of ["registry.minice.ai", "registry.knice.tech"]) {
    for (const schema of [INDEX_SCHEMA, WITHDRAWN_SCHEMA]) assert.ok(r.out.some((l) => l.startsWith(`ok   ${host} ${schema}: `)), `${host} ${schema}\n${r.text}`);
  }
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
  assert.match(r.err.at(-1), /not ready: 2 of 2 document\(s\) fail/);
});

test("ceremony-ready fails (a) on a document signed only by B with games-current: under N, B is next", async () => {
  const k = ceremony();
  const bridged = JSON.parse(fs.readFileSync(k.index, "utf8"));
  const bOnly = path.join(k.dir, "b-only-current.json");
  writeJson(bOnly, { ...bridged, signatures: bridged.signatures.filter((s) => s.key_id === "astra-games-2026b") });
  const r = await run(argsFor(k, [bOnly, k.withdrawn]), { roots: k.c.roots });
  assert.equal(r.code, 1, r.text);
  const line = r.out.find((l) => l.startsWith(`FAIL local:${bOnly} ${INDEX_SCHEMA}: `));
  assert.match(line, /^FAIL .*: \(a\) under trust N: the body names games-current and the keys that verified it are the next key astra-games-2026b$/);
  assert.ok(r.out.some((l) => l.startsWith(`ok   local:${k.withdrawn}`)), "the bridged withdrawn list still passes");
});

test("ceremony-ready exits 2 when anything cannot be fetched or read, never 0", async () => {
  const k = ceremony();
  const body = (f) => fs.readFileSync(f, "utf8");
  const cases = {
    "network down": async (url) => {
      throw new TypeError("fetch failed", { cause: { code: "ECONNREFUSED", url } });
    },
    "one document 404s": async (url) => (url.endsWith("withdrawn.json") && url.includes("knice") ? new Response("", { status: 404 }) : new Response(url.endsWith("trust.json") ? body(k.trustN) : body(url.endsWith("index.json") ? k.index : k.withdrawn))),
    "a CDN error page": async (url) => (url.endsWith("trust.json") ? new Response(body(k.trustN)) : new Response("<html>502</html>", { status: 200 })),
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
  assert.match(help.stdout, /need not be root-signed yet, and\s+its root signature is NOT checked here/);
});

test("ceremony-ready verifies trust.json N under the compiled roots: the operator cannot hand it others", async () => {
  const k = ceremony();
  const r = await run(argsFor(k)); // no injected roots: the compiled set, which never signed this throwaway N
  assert.equal(r.code, 1, r.text);
  assert.match(r.err.join("\n"), /FAIL trust\.json N .*E_TRUST_UNVERIFIED/);
});

test("a client that already retired A: the bridged document still passes, and a ceremony that leaves only A to verify fails (c)", async () => {
  const k = ceremony();
  const bridged = JSON.parse(fs.readFileSync(k.index, "utf8"));
  const kN1 = loadTrust({ doc: JSON.parse(fs.readFileSync(k.nextTrust, "utf8")), now: T0, roots: k.c.roots }).kindKeys;
  const ok = ceremonyChecks({ envelope: bridged, domain: INDEX_SCHEMA }, { trustN: k.c.kindKeys, trustN1: kN1, now: T0 });
  assert.equal(ok.ok, true, ok.failures.join("; "));
  assert.deepEqual(ok.underN1.map((x) => x.key_id), ["astra-games-2026b"], "B verifies it under N+1, so a client whose mark retired A accepts it");

  // a ceremony that keeps A current and replaces the next key the signer has moved to:
  // (a) and (b) pass, A is N+1's current, and yet a client that retired A refuses everything served
  const keepsA = path.join(k.dir, "trust-keeps-a.json");
  writeJson(keepsA, k.c.trustWith([kindKeyRow("games", "current", "astra-games-2026a", k.c.current, NOT_BEFORE), kindKeyRow("games", "next", "astra-games-2026c", k.fresh, NOT_BEFORE_FRESH)], { serial: 6 }));
  const r = await run(argsFor(k, [k.index], keepsA), { roots: k.c.roots });
  assert.equal(r.code, 1, r.text);
  const line = r.out.find((l) => l.startsWith("FAIL "));
  assert.match(line, /\(c\) a client that already retired astra-games-2026a for astra\.games\.index\/1 refuses it: no other key verifies it under N\+1/);
  assert.doesNotMatch(line, /\(a\)|\(b\)|N\+1's current key/);

  // and (c)'s first half: N+1's current key must be among the verifiers
  const skipsB = path.join(k.dir, "trust-current-d.json");
  writeJson(skipsB, k.c.trustWith([kindKeyRow("games", "current", "astra-games-2026d", throwawayKey(), NOT_BEFORE), kindKeyRow("games", "next", "astra-games-2026b", k.c.next, NOT_BEFORE_NEXT)], { serial: 6 }));
  const bOnlyNext = path.join(k.dir, "b-only-next.json");
  k.c.sign({ env: { GAMES_SIGNING_KEY_NEXT: k.c.next.seedB64 } });
  fs.copyFileSync(k.index, bOnlyNext);
  const s = await run(argsFor(k, [bOnlyNext], skipsB), { roots: k.c.roots });
  assert.equal(s.code, 1, s.text);
  assert.ok(s.out.includes(`FAIL local:${bOnlyNext} ${INDEX_SCHEMA}: (c) N+1's current key astra-games-2026d does not verify it`), s.text);
});
