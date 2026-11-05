// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Ingest against the staging fixtures (A§11 S1b): the good release becomes
// an unsigned candidate; every certificate field of A§4.1 refuses; a
// transferred repository is held; engine-code-taken refuses; and a missing
// gi-probe never lets a release through.

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { bindingTokenSha256, ingestRelease, parseRequest } from "../lib/ingest.mjs";
import { descriptorDigest } from "../lib/model.mjs";
import { binaryProbe } from "../lib/probe.mjs";
import { loadReserved, readTomlFile } from "../lib/schemas.mjs";
import { MAX_PARTS, projectCandidate } from "../lib/service.mjs";
import { emptyModeration } from "../lib/state.mjs";
import { PIN_051, ROOT, fakeGh, fakeGithub, fakeProbe, fakeSteam, fixture, fixtureText, makeZip, makeZipBytes, seedLoaders, sha256, tmpdir } from "./helpers.mjs";

const reserved = loadReserved();
const firstParty = JSON.parse(fs.readFileSync(path.join(ROOT, "first-party.json"), "utf8"));
const loaders = seedLoaders();
const BINDING = { account: "astra-staging-author", repo_id: 900000001, repo_owner_id: 800000001, binding_token: "stagingBindingToken_0123456789abcdef" };
const TOKEN = "stagingBindingToken_0123456789abcdef";
const REQUEST = { lease_id: "lease-1", repo_id: 900000001, tag: "v1.0.0", binding_token_sha256: bindingTokenSha256(TOKEN), confirmed: [] };

function emptyState(extra = {}) {
  return { entries: [], bindings: {}, engineCodes: {}, moderation: emptyModeration(), withdrawn: { rows: [], held: [] }, holds: [], health: {}, floors: {}, ...extra };
}

function stagingZip(manifestText = fixtureText("astra-gi.toml")) {
  return makeZip({ "astra-gi.toml": manifestText, "BepInEx/plugins/Staging.dll": "not really a dll" });
}

async function run({ zip = stagingZip(), state = emptyState(), certificate = {}, gh = null, probe = null, github = null, request = REQUEST } = {}) {
  return ingestRelease({
    request,
    policy: { firstParty, loaders },
    state,
    reserved,
    deps: {
      github: github ?? fakeGithub({ zip }),
      gh: gh ?? fakeGh({ sha: sha256(zip), certificate }),
      probe: probe ?? fakeProbe(),
      steam: fakeSteam(),
      workdir: tmpdir(),
      now: () => 1793448000,
    },
  });
}

const codes = (c) => c.findings.map((f) => f.code);

test("the staging C# GI becomes an unsigned candidate entry", async () => {
  const zip = stagingZip();
  const c = await run({ zip });
  assert.equal(c.verdict, "accept", JSON.stringify(c.findings));
  assert.equal(c.entry.id, "astra-staging-author/staging-csharp-gi");
  assert.equal(c.entry.kind, "integration");
  assert.equal(c.entry.source.sha256, sha256(zip));
  assert.equal(c.entry.source.commit, "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00", "the PEELED commit, not the tag object");
  assert.equal(c.entry.source.workflow_path, ".github/workflows/gi-release.yml");
  assert.equal(c.entry.source.event, "push");
  assert.deepEqual(c.entry.publisher, { account: "astra-staging-author", repo_id: 900000001, repo_owner_id: 800000001 });
  assert.equal(c.entry.review, "unchecked");
  assert.equal(c.meta.status, "listed");
  assert.ok(!("signatures" in c) && !("signed" in c), "ingest output is unsigned");
});

test("gh is asked about the downloaded bytes, by the repository's current name, as an argument array", async () => {
  const zip = stagingZip();
  const gh = fakeGh({ sha: sha256(zip) });
  await run({ zip, gh });
  assert.equal(gh.calls.length, 1);
  const args = gh.calls[0];
  assert.deepEqual([args[0], args[1], args[3], args[4], args[5], args[6]], ["attestation", "verify", "--repo", "astra-staging-author/staging-csharp-gi", "--format", "json"]);
});

for (const [name, v] of Object.entries(fixture("refusals.json")).filter(([k]) => !k.startsWith("$"))) {
  test(`A§11 S1b: ${name} is refused (${v.expect})`, async () => {
    const c = await run({ certificate: v.certificate });
    assert.equal(c.verdict, "refuse", JSON.stringify(c.findings));
    assert.ok(codes(c).includes(v.expect), `${v.expect} not in ${codes(c)}`);
    assert.equal(c.entry, undefined);
  });
}

test("A§11 S1b: a transferred repository is held, never listed and never refused", async () => {
  const t = fixture("transferred.json");
  const repo = { ...fixture("repo.json"), owner: t.owner, full_name: t.full_name };
  const zip = stagingZip();
  const c = await run({
    zip,
    state: emptyState({ bindings: { 900000001: BINDING } }),
    github: fakeGithub({ zip, repo }),
    gh: fakeGh({ sha: sha256(zip), certificate: t.certificate }),
  });
  assert.equal(c.verdict, "hold", JSON.stringify(c.findings));
  assert.ok(codes(c).includes("R_IDENTITY_CHANGED"));
  assert.ok(!codes(c).some((x) => x.startsWith("E_")), JSON.stringify(c.findings));
  assert.equal(c.entry.publisher.repo_owner_id, 800000001, "the entry keeps the BOUND identity until a person decides");
  assert.equal(c.entry.source.repo_owner_id, 800000002);
});

test("a binding line naming another account is held as R_BINDING_CHANGED", async () => {
  const zip = stagingZip();
  const other = "anotherAccountsToken_abcdef0123";
  const c = await run({
    zip,
    state: emptyState({ bindings: { 900000001: BINDING } }),
    github: fakeGithub({ zip, ownerFile: `astra-binding: ${other}\n` }),
    request: { ...REQUEST, binding_token_sha256: bindingTokenSha256(other) },
  });
  assert.equal(c.verdict, "hold", JSON.stringify(c.findings));
  assert.ok(codes(c).includes("R_BINDING_CHANGED"));
  assert.equal(c.meta.claimant.binding_token, other, "a person's M_RELEASE_HOLD rebinds to the line at this tag");
  assert.equal(c.meta.claimant.account, "astra-staging-author", "the claimant is the repository owner's GitHub login");
});

test("an unbound repository is refused, and a first release needs the site's binding", async () => {
  const zip = stagingZip();
  const a = await run({ zip, github: fakeGithub({ zip, ownerFile: null }) });
  assert.ok(codes(a).includes("E_UNBOUND"));
  const b = await run({ zip, request: { lease_id: "lease-1", repo_id: 900000001, tag: "v1.0.0" } });
  assert.ok(codes(b).includes("E_UNBOUND"));
});

test("a community prerelease is refused (stable releases only)", async () => {
  const zip = stagingZip();
  const release = { ...fixture("release.json"), prerelease: true };
  const c = await run({ zip, github: fakeGithub({ zip, release }) });
  assert.ok(codes(c).includes("E_PRERELEASE"));
});

test("a release carrying only astra-gi-<suffix>.zip is E_ASSET_MISSING, and the message says one GI per release", async () => {
  const zip = stagingZip();
  const release = structuredClone(fixture("release.json"));
  release.assets = release.assets.map((a) => ({ ...a, name: a.name === "astra-gi.zip" ? "astra-gi-ds1.zip" : a.name }));
  release.assets.push({ ...release.assets[0], name: "astra-gi-ds2.zip" });
  const c = await run({ zip, github: fakeGithub({ zip, release }) });
  const f = c.findings.find((x) => x.code === "E_ASSET_MISSING");
  assert.ok(f, JSON.stringify(c.findings));
  assert.match(f.message, /astra-gi-ds1\.zip, astra-gi-ds2\.zip/);
  assert.match(f.message, /one game integration per release/);
  const plain = structuredClone(fixture("release.json"));
  plain.assets = plain.assets.filter((a) => a.name !== "astra-gi.zip");
  const d = await run({ zip, github: fakeGithub({ zip, release: plain }) });
  const g = d.findings.find((x) => x.code === "E_ASSET_MISSING");
  assert.ok(g && !/one game integration per release/.test(g.message), JSON.stringify(d.findings));
});

test("an asset whose bytes are not GitHub's digest is refused", async () => {
  const zip = stagingZip();
  const release = structuredClone(fixture("release.json"));
  release.assets[0].digest = `sha256:${"0".repeat(64)}`;
  const c = await run({ zip, github: fakeGithub({ zip, release }) });
  assert.ok(codes(c).includes("E_ASSET_DIGEST_MISMATCH"));
});

test("no attestation is E_ATTESTATION_MISSING; Sigstore unreachable is a wait, not a refusal", async () => {
  const missing = await run({ gh: fakeGh({ sha: "x", fail: { stderr: "HTTP 404: Not Found (https://api.github.com/…/attestations/sha256:…)" } }) });
  assert.ok(codes(missing).includes("E_ATTESTATION_MISSING"));
  assert.equal(missing.verdict, "refuse");
  const down = await run({ gh: fakeGh({ sha: "x", fail: { stderr: "failed to fetch trusted root: dial tcp: i/o timeout" } }) });
  assert.ok(codes(down).includes("W_ATTESTATION_UNCHECKED"), JSON.stringify(down.findings));
  assert.equal(down.verdict, "wait");
});

test("a release event is accepted (A§4.1), and recorded as such", async () => {
  const c = await run({ certificate: { buildTrigger: "release" } });
  assert.equal(c.verdict, "accept", JSON.stringify(c.findings));
  assert.equal(c.entry.source.event, "release");
});

test("an attestation for other bytes is refused", async () => {
  const c = await run({ gh: fakeGh({ sha: "f".repeat(64) }) });
  assert.ok(codes(c).includes("E_ATTESTATION_SUBJECT_MISMATCH"));
});

test("gi-probe absent: production fails closed with W_PROBE_UNAVAILABLE", async () => {
  for (const probe of [binaryProbe({ env: { PATH: "", GI_PROBE: "" }, pin: PIN_051 }), binaryProbe({ env: { PATH: "", GI_PROBE: "" }, pin: { version: null } })]) {
    const c = await run({ probe });
    assert.equal(c.verdict, "wait");
    assert.ok(codes(c).includes("W_PROBE_UNAVAILABLE"));
    assert.equal(c.entry, undefined);
  }
});

// The fake answers in gi-probe 0.5.1's own spelling: a finding is {code,
// step, field?, detail, params?} (main.rs l.116-126; codes as check.rs and
// tests/gi_probe.rs l.3546-3553 raise them), and a refusal is verdict fail,
// exit 1.
test("a gi-probe check finding refuses E_PROBE, in gi-probe's own code and words", async () => {
  const c = await run({ probe: fakeProbe({ check: { findings: [{ code: "loader-undeclared", step: 2, field: "game_files", detail: "winhttp.dll is placed and [integration.loader] does not declare it", params: { file: "winhttp.dll" } }] } }) });
  assert.equal(c.verdict, "refuse");
  const f = c.findings.find((x) => x.code === "E_PROBE");
  assert.ok(f, JSON.stringify(c.findings));
  assert.equal(f.probe_code, "loader-undeclared");
  assert.match(f.message, /^gi-probe check loader-undeclared \(game_files\): winhttp\.dll is placed/);
});

test("a gi-probe mods-invalid finding (0.5.1: spec §7.9, a descriptor's own mods table) refuses E_PROBE the same as any other code — the mapping never keys off a specific gi-probe code, so a new one is never silently dropped", async () => {
  const c = await run({ probe: fakeProbe({ check: { findings: [{ code: "mods-invalid", step: 1, field: "integration.engine.mods.loader[0].id", detail: "mods (spec §7.9): ingest refuses the descriptor; a client drops only its mods and detects with it as without", params: { reason: "code-undeclared" } }] } }) });
  assert.equal(c.verdict, "refuse");
  const f = c.findings.find((x) => x.code === "E_PROBE");
  assert.ok(f, JSON.stringify(c.findings));
  assert.equal(f.probe_code, "mods-invalid");
  assert.match(f.message, /^gi-probe check mods-invalid \(integration\.engine\.mods\.loader\[0\]\.id\): mods/);
});

test("gi-probe reading another id, version or descriptor than the catalogue refuses E_PROBE_DISAGREES", async () => {
  const a = await run({ probe: fakeProbe({ check: { integration: { id: "someone.else", name: "x", version: "1.0.0", repo: null, engine: null, sdk: null } } }) });
  assert.ok(codes(a).includes("E_PROBE_DISAGREES"), JSON.stringify(a.findings));
  const b = await run({ probe: fakeProbe({ check: { integration: { id: "astra-staging-author.staging-csharp-gi", name: "x", version: "1.0.1", repo: null, engine: null, sdk: null } } }) });
  assert.ok(codes(b).includes("E_PROBE_DISAGREES"));
  const c = await run({ probe: fakeProbe({ check: { descriptor_sha256: "e".repeat(64) } }) });
  assert.ok(codes(c).includes("E_PROBE_DISAGREES"), "a descriptor the catalogue does not see");
});

test("a report the catalogue cannot read as gi-probe 0.5.1's is W_PROBE_UNAVAILABLE, never accept and never a refusal", async () => {
  const cases = {
    "stdout that is not JSON": { check: { stdout: "Segmentation fault\n", exit: 0 } },
    "another schema": { check: { patch: { schema: "astra.gi-probe/2" } } },
    "another tool.version": { tool: { version: "0.5.2" } },
    "another source tree": { tool: { source_tree_sha256: "0".repeat(64) } },
    "another subcommand's report": { check: { patch: { subcommand: "compat" } } },
    "a pass with findings": { check: { findings: [{ code: "zip-traversal", step: 1, detail: "../evil" }], exit: 0 } },
    "a fail without findings": { check: { patch: { verdict: "fail" }, exit: 1 } },
    "the old contract's finding shape": { check: { findings: [{ code: "zip-traversal", level: "error", message: "../evil" }] } },
    "exit 2, nothing concluded": { check: { patch: { error: { code: "io", detail: "x: no such file" } }, exit: 2 } },
    "a report of other bytes": { check: { patch: { input: { file: "x", kind: "zip", sha256: "a".repeat(64), provenance: "community", foundation: null, previous: null, loaders: null } } } },
    "a passing check with no integration": { check: { integration: null } },
  };
  for (const [what, scenario] of Object.entries(cases)) {
    const c = await run({ probe: fakeProbe(scenario) });
    assert.equal(c.verdict, "wait", `${what}: ${JSON.stringify(c.findings)}`);
    assert.ok(codes(c).includes("W_PROBE_UNAVAILABLE"), what);
    assert.ok(!codes(c).includes("E_PROBE"), what);
    assert.equal(c.entry, undefined, what);
  }
});

test("the entry's game files, Link summary and schema digests come from the catalogue's own reading of the zip", async () => {
  const proxy = "MZ a Doorstop build, off by default";
  const text = fixtureText("astra-gi.toml") + [
    "",
    "[integration.loader]",
    'proxies = ["winhttp.dll"]',
    "",
    "[[game_files]]",
    'from = "game/winhttp.dll"',
    'to = "${game}/winhttp.dll"',
    "",
  ].join("\n");
  const zip = makeZip({ "astra-gi.toml": text, "BepInEx/plugins/Staging.dll": "not really a dll", "game/winhttp.dll": proxy });
  const c = await run({ zip });
  assert.equal(c.verdict, "accept", JSON.stringify(c.findings));
  assert.deepEqual(c.entry.changes.game_files, [{ path: "winhttp.dll", sha256: sha256(Buffer.from(proxy)), loader: "other" }]);
  assert.ok(codes(c).includes("F_LOADER_OTHER"));
  assert.equal(c.meta.files["game/winhttp.dll"], sha256(Buffer.from(proxy)));
  assert.equal(c.meta.files["astra-gi.toml"], sha256(Buffer.from(text)));
  assert.deepEqual(c.meta.probe.ran, ["check"]);
  assert.ok(c.meta.probe.notices.includes("check:loader-other"));
  // gi-probe classing another file than the manifest places refuses
  const other = await run({ zip, probe: fakeProbe({ check: { loaders_files: [{ dest: "${game}/winhttp.dll", sha256: "b".repeat(64), class: "allowlisted", allowlisted_as: "doorstop-winhttp" }] } }) });
  assert.ok(codes(other).includes("E_PROBE_DISAGREES"), JSON.stringify(other.findings));
});

test("[integration.link] gets a digest (manifest.md §2.6.1), and gi-probe check's own link.digest (0.5.1+) must agree with it", async () => {
  const text = fixtureText("astra-gi.toml") + ["", "[integration.link]", "context = true", "shares_other_players = false", ""].join("\n");
  const zip = stagingZip(text);
  // the default fake gi-probe 0.5.1 now computes link.digest itself
  // (fixtures/gi-probe/fake-gi-probe.mjs), the same way lib/model.mjs's linkOf
  // does: this run already proves the two agree (verdict is accept, not a
  // refusal), with no scenario patch needed.
  const c = await run({ zip });
  assert.equal(c.verdict, "accept", JSON.stringify(c.findings));
  assert.equal(typeof c.entry.link.digest, "string");
  assert.match(c.entry.link.digest, /^[0-9a-f]{64}$/);
  // a disagreeing link.digest (a build with a bug, or another parser) refuses E_PROBE_DISAGREES
  const disagreeing = await run({ zip, probe: fakeProbe({ check: { patch: { link: { digest: "f".repeat(64) } } } }) });
  assert.ok(codes(disagreeing).includes("E_PROBE_DISAGREES"), JSON.stringify(disagreeing.findings));
  // a probe reporting no digest at all (0.5.0's shape) is read as before: no comparison, still accept
  const noDigest = await run({ zip, probe: fakeProbe({ check: { patch: { link: { digest: undefined } } } }) });
  assert.equal(noDigest.verdict, "accept", JSON.stringify(noDigest.findings));
});

test("a VAC game and a game a moderator refused are refused; an online game is only flagged", async () => {
  const vac = fixtureText("astra-gi.toml").replace("steam_appid = 4000001", "steam_appid = 4000002");
  const a = await run({ zip: stagingZip(vac) });
  assert.ok(codes(a).includes("E_GAME_VAC"));
  const online = fixtureText("astra-gi.toml").replace("steam_appid = 4000001", "steam_appid = 4000003");
  const b = await run({ zip: stagingZip(online) });
  assert.equal(b.verdict, "accept", JSON.stringify(b.findings));
  assert.ok(b.flags.includes("F_ONLINE_GAME"));
  const moderation = { ...emptyModeration(), games: [{ store: "steam", id: 4000001, refuse: { reason: "the developer asked" } }] };
  const c = await run({ state: emptyState({ moderation }) });
  assert.ok(codes(c).includes("E_GAME_REFUSED"));
});

test("anti-cheat in the manifest is refused", async () => {
  const m = fixtureText("astra-gi.toml").replace('anti_cheat = "none"', 'anti_cheat = "easyanticheat"');
  const c = await run({ zip: stagingZip(m) });
  assert.ok(codes(c).includes("E_ANTI_CHEAT"));
});

test("a manifest that breaks the S schema is refused", async () => {
  const m = fixtureText("astra-gi.toml") + '\n[surprise]\nkey = "value"\n';
  const c = await run({ zip: stagingZip(m) });
  assert.ok(codes(c).includes("E_MANIFEST_INVALID"), JSON.stringify(c.findings));
});

test("the version must be the tag's", async () => {
  const m = fixtureText("astra-gi.toml").replace('version = "1.0.0"', 'version = "1.0.1"');
  const c = await run({ zip: stagingZip(m), version: "1.0.1" });
  assert.ok(codes(c).includes("E_VERSION_TAG_MISMATCH"));
});

// ── content parts (manifest.md §2.7, merged plan §5.4) ──────────────────

const CONTENT_PNG = Buffer.from("89504e470d0a1a0a0000000000000000", "hex");

function withCoverArt() {
  return fixtureText("astra-gi.toml") + `
[[integration.content]]
path = "art/cover.png"
kind = "art"
title = "Cover art"
credit = "astra-staging-author"
licence = "CC0-1.0"
`;
}

test("a release with its content part present and declared carries content[] end to end", async () => {
  const zip = makeZipBytes({
    "astra-gi.toml": withCoverArt(),
    "BepInEx/plugins/Staging.dll": Buffer.from("not really a dll"),
    "art/cover.png": CONTENT_PNG,
  });
  const c = await run({ zip, request: { ...REQUEST, confirmed: [{ path: "art/cover.png", sha256: sha256(CONTENT_PNG), text_id: "market.rights.art", text_version: 1 }] } });
  assert.equal(c.verdict, "accept", JSON.stringify(c.findings));
  assert.equal(c.entry.content.length, 1);
  assert.equal(c.entry.content[0].path, "art/cover.png");
  assert.equal(c.entry.content[0].kind, "art");
  assert.equal(c.entry.content[0].sha256.length, 64);
});

test("content: an undeclared file refuses the whole release (E_CONTENT_UNDECLARED)", async () => {
  const zip = makeZipBytes({
    "astra-gi.toml": fixtureText("astra-gi.toml"), // no [[integration.content]] at all
    "BepInEx/plugins/Staging.dll": Buffer.from("not really a dll"),
    "art/cover.png": CONTENT_PNG,
  });
  const c = await run({ zip });
  assert.equal(c.verdict, "refuse");
  assert.ok(codes(c).includes("E_CONTENT_UNDECLARED"), JSON.stringify(c.findings));
});

test("content: a declared path with no file refuses the whole release (E_CONTENT_MISSING)", async () => {
  const zip = makeZipBytes({
    "astra-gi.toml": withCoverArt(), // declares art/cover.png; the zip has no such file
    "BepInEx/plugins/Staging.dll": Buffer.from("not really a dll"),
  });
  const c = await run({ zip });
  assert.equal(c.verdict, "refuse");
  assert.ok(codes(c).includes("E_CONTENT_MISSING"), JSON.stringify(c.findings));
});

// ── contract 6.13.0 §4.6: a candidate carries at most 1024 parts[] ──────

function manifestWithParts(n) {
  let m = fixtureText("astra-gi.toml");
  for (let i = 0; i < n; i++) m += `\n[[integration.content]]\npath = "art/p${i}.png"\nkind = "art"\ntitle = "p${i}"\ncredit = "astra-staging-author"\nlicence = "CC0-1.0"\n`;
  return m;
}

function releaseWithParts(n) {
  const files = { "astra-gi.toml": manifestWithParts(n), "BepInEx/plugins/Staging.dll": Buffer.from("not really a dll") };
  for (let i = 0; i < n; i++) files[`art/p${i}.png`] = CONTENT_PNG;
  const confirmed = Array.from({ length: n }, (_, i) => ({ path: `art/p${i}.png`, sha256: sha256(CONTENT_PNG), text_id: "market.rights.art", text_version: 1 }));
  return { zip: makeZipBytes(files), confirmed };
}

test("content: exactly 1024 declared parts (the manifest schema's maxItems bound) is accepted and carries content[1024]", async () => {
  const { zip, confirmed } = releaseWithParts(MAX_PARTS);
  const c = await run({ zip, request: { ...REQUEST, confirmed } });
  assert.equal(c.verdict, "accept", JSON.stringify(c.findings));
  assert.equal(c.entry.content.length, MAX_PARTS);
});

test("content: 1025 declared parts is refused E_MANIFEST_INVALID before any service call, and the games catalogue's own candidate projection still never carries more than MAX_PARTS", async () => {
  const { zip, confirmed } = releaseWithParts(MAX_PARTS + 1);
  const c = await run({ zip, request: { ...REQUEST, confirmed } });
  // The manifest schema (vendored from AstraPlugins, maxItems 1024 on
  // [[integration.content]]) refuses it: the candidate never reaches
  // "accept", never gets an entry, and nothing posts it to the service as
  // a listed release -- this IS the ingest-time refusal, decided locally,
  // before bin/service.mjs ever calls bot/games/ingest-results for it.
  assert.equal(c.verdict, "refuse", JSON.stringify(c.findings));
  assert.ok(codes(c).includes("E_MANIFEST_INVALID"), JSON.stringify(c.findings));
  assert.equal(c.entry, undefined);
  // checkContent still runs on a schema-invalid manifest (it is not gated
  // on the schema check), so the refused candidate's OWN parts[] is not
  // bounded by the schema at all: measured here at MAX_PARTS + 1.
  assert.equal(c.parts.length, MAX_PARTS + 1, "ingest's own candidate is not yet cut -- projectCandidate is what cuts it");
  // What bin/service.mjs's ingest-report job would actually post for this
  // refused release IS cut, by lib/service.mjs's independent MAX_PARTS cut
  // (see test/service.test.mjs): the wire body is never over the bound,
  // whatever ingest's own candidate carries.
  assert.equal(projectCandidate(c).parts.length, MAX_PARTS, "the posted body is cut at the bound rather than sent one past it");
});

// ── engine codes (merged §2.1) ──────────────────────────────────────────

function fooEngine() {
  const text = fixtureText("foo-engine.toml");
  const zip = makeZip({ "astra-gi.toml": text, "foo/runtime.dll": "x" });
  const file = path.join(tmpdir(), "foo.toml");
  fs.writeFileSync(file, text);
  const descriptor = readTomlFile(file).manifest.integration.engine;
  return { zip, descriptorSha: descriptorDigest(descriptor) };
}

test("a foundation that owns a new engine code passes, with its descriptor and digest", async () => {
  const { zip, descriptorSha } = fooEngine();
  const c = await run({ zip, manifestId: "astra-staging-author.foo-engine", version: "0.1.0", descriptorSha, github: fakeGithub({ zip, release: { ...fixture("release.json"), tag_name: "v0.1.0" } }), request: { ...REQUEST, tag: "v0.1.0" }, certificate: { sourceRepositoryRef: "refs/tags/v0.1.0" } });
  assert.equal(c.verdict, "accept", JSON.stringify(c.findings));
  assert.equal(c.entry.kind, "foundation");
  assert.equal(c.entry.descriptor_sha256, descriptorSha);
  assert.deepEqual(c.entry.target, { exe: "*", engine: "foo-engine" });
});

test("engine-code-taken: another publisher's foundation may not claim an owned code", async () => {
  const { zip, descriptorSha } = fooEngine();
  const state = emptyState({ engineCodes: { "foo-engine": { account: "first-owner", repo_id: 900000077, repo_owner_id: 800000077 } } });
  const c = await run({ zip, state, manifestId: "astra-staging-author.foo-engine", version: "0.1.0", descriptorSha, github: fakeGithub({ zip, release: { ...fixture("release.json"), tag_name: "v0.1.0" } }), request: { ...REQUEST, tag: "v0.1.0" }, certificate: { sourceRepositoryRef: "refs/tags/v0.1.0" } });
  assert.equal(c.verdict, "refuse");
  assert.ok(codes(c).includes("E_ENGINE_CODE_TAKEN"), JSON.stringify(c.findings));
});

test("engine-code-taken folds look-alikes: fo0-engine cannot take foo-engine", async () => {
  const t2 = fixtureText("foo-engine.toml").replaceAll("foo-engine", "fo0-engine");
  const zip = makeZip({ "astra-gi.toml": t2, "foo/runtime.dll": "x" });
  const file = path.join(tmpdir(), "foo.toml");
  fs.writeFileSync(file, t2);
  const descriptorSha = descriptorDigest(readTomlFile(file).manifest.integration.engine);
  const state = emptyState({ engineCodes: { "foo-engine": { account: "first-owner", repo_id: 900000077, repo_owner_id: 800000077 } } });
  const c = await run({ zip, state, manifestId: "astra-staging-author.foo-engine", version: "0.1.0", descriptorSha, github: fakeGithub({ zip, release: { ...fixture("release.json"), tag_name: "v0.1.0" } }), request: { ...REQUEST, tag: "v0.1.0" }, certificate: { sourceRepositoryRef: "refs/tags/v0.1.0" } });
  assert.ok(codes(c).includes("E_ENGINE_CODE_TAKEN"), JSON.stringify(c.findings));
});

test("engine-code-reserved: a built-in code is refused", async () => {
  const t = fixtureText("foo-engine.toml").replaceAll("foo-engine", "unity-mono");
  const zip = makeZip({ "astra-gi.toml": t, "foo/runtime.dll": "x" });
  const c = await run({ zip, manifestId: "astra-staging-author.foo-engine", version: "0.1.0", github: fakeGithub({ zip, release: { ...fixture("release.json"), tag_name: "v0.1.0" } }), request: { ...REQUEST, tag: "v0.1.0" }, certificate: { sourceRepositoryRef: "refs/tags/v0.1.0" } });
  assert.ok(codes(c).includes("E_ENGINE_CODE_RESERVED"), JSON.stringify(c.findings));
});

// ── first-party by digest pin (merged §5.1) ─────────────────────────────

function firstPartyRun({ pins = [], zip = stagingZip(fixtureText("astra-gi.toml").replace("astra-staging-author.staging-csharp-gi", "astra.peak").replace("Staging C# test integration", "Astra in PEAK")), prerelease = false, probe = fakeProbe() } = {}) {
  const repo = { id: 1409552680, full_name: "mihailinl/astra-peak", owner: { id: 193032699 }, private: false, visibility: "public", default_branch: "main" };
  const policy = { firstParty: { ...firstParty, pins }, loaders };
  const gh = fakeGh({ sha: sha256(zip) });
  return ingestRelease({
    request: { repo_id: 1409552680, tag: "v1.0.0" },
    policy,
    state: emptyState(),
    reserved,
    deps: {
      github: fakeGithub({ zip, repo, release: { ...fixture("release.json"), prerelease } }),
      gh,
      probe,
      steam: fakeSteam(),
      workdir: tmpdir(),
      now: () => 1793448000,
    },
  }).then((c) => ({ c, gh, zip, probe }));
}

test("first-party: admitted by digest pin, with no attestation asked for", async () => {
  const zip0 = (await firstPartyRun()).zip;
  const { c, gh } = await firstPartyRun({ pins: [{ repository_id: 1409552680, tag: "v1.0.0", asset: "astra-gi.zip", sha256: sha256(zip0) }] });
  assert.equal(c.verdict, "accept", JSON.stringify(c.findings));
  assert.equal(gh.calls.length, 0, "a first-party release never runs gh attestation verify");
  assert.equal(c.entry.id, "mihailinl/astra-peak");
  assert.equal(c.meta.first_party, true);
  assert.ok(!c.findings.some((f) => f.code === "E_RESERVED_ID"), "astra. ids are reserved FOR first-party");
});

test("first-party: no pin holds, a wrong pin refuses, and a prerelease waits for promotion", async () => {
  const none = (await firstPartyRun()).c;
  assert.equal(none.verdict, "hold");
  assert.ok(codes(none).includes("H_FIRST_PARTY_UNPINNED"));
  const wrong = (await firstPartyRun({ pins: [{ repository_id: 1409552680, tag: "v1.0.0", asset: "astra-gi.zip", sha256: "0".repeat(64) }] })).c;
  assert.ok(codes(wrong).includes("E_PIN_MISMATCH"));
  const zip0 = (await firstPartyRun()).zip;
  const pre = (await firstPartyRun({ prerelease: true, pins: [{ repository_id: 1409552680, tag: "v1.0.0", asset: "astra-gi.zip", sha256: sha256(zip0) }] })).c;
  assert.equal(pre.verdict, "accept");
  assert.equal(pre.meta.status, "prerelease");
});

test("a community id with the first-party prefix is reserved", async () => {
  const m = fixtureText("astra-gi.toml").replace("astra-staging-author.staging-csharp-gi", "astra.staging");
  const c = await run({ zip: stagingZip(m), manifestId: "astra.staging" });
  assert.ok(codes(c).includes("E_RESERVED_ID"));
});

test("an id another publisher lists is taken, and a look-alike is confusable", async () => {
  const other = { entry: { id: "astra-staging-author/staging-csharp-gi", publisher: { account: "squatter", repo_id: 1, repo_owner_id: 2 } }, meta: {} };
  const a = await run({ state: emptyState({ entries: [other] }) });
  assert.ok(codes(a).includes("E_ID_TAKEN"));
  const look = { entry: { id: "astra-staging-author/staging-csharp-g1", publisher: { account: "squatter", repo_id: 1, repo_owner_id: 2 } }, meta: {} };
  const b = await run({ state: emptyState({ entries: [look] }) });
  assert.ok(codes(b).includes("E_ID_CONFUSABLE"));
});

// ── the lease: the pull model (lane C design §0 findings 1-3, §1.3, §1.6) ──

const coverZip = () => makeZipBytes({
  "astra-gi.toml": withCoverArt(),
  "BepInEx/plugins/Staging.dll": Buffer.from("not really a dll"),
  "art/cover.png": CONTENT_PNG,
});
const COVER = { path: "art/cover.png", sha256: sha256(CONTENT_PNG), text_id: "market.rights.art", text_version: 3 };

test("rights gate: a part the author has not confirmed waits (W_CONTENT_UNCONFIRMED), is never listed, and is reported with its parts", async () => {
  const c = await run({ zip: coverZip() });
  assert.equal(c.verdict, "wait", JSON.stringify(c.findings));
  assert.ok(codes(c).includes("W_CONTENT_UNCONFIRMED"));
  assert.equal(c.entry, undefined, "a wait carries no entry");
  assert.deepEqual(c.parts.map((p) => [p.path, p.kind, p.sha256]), [["art/cover.png", "art", sha256(CONTENT_PNG)]], "the result door needs the parts to ask about");
});

test("rights gate: a confirmation covers a part only at the SAME path and the SAME sha256", async () => {
  const otherSha = await run({ zip: coverZip(), request: { ...REQUEST, confirmed: [{ ...COVER, sha256: "a".repeat(64) }] } });
  assert.equal(otherSha.verdict, "wait", "a changed file is asked about again");
  assert.ok(codes(otherSha).includes("W_CONTENT_UNCONFIRMED"));
  const otherPath = await run({ zip: coverZip(), request: { ...REQUEST, confirmed: [{ ...COVER, path: "art/other.png" }] } });
  assert.equal(otherPath.verdict, "wait");
});

test("rights gate: full coverage lists the release with content_confirmed {text_id: text_version}, and no account", async () => {
  const c = await run({ zip: coverZip(), request: { ...REQUEST, confirmed: [COVER, { path: "art/gone.png", sha256: "b".repeat(64), text_id: "market.rights.audio", text_version: 2 }] } });
  assert.equal(c.verdict, "accept", JSON.stringify(c.findings));
  assert.deepEqual(c.entry.content_confirmed, { "market.rights.art": 3 }, "the text version the part was confirmed under, and only the texts a present part used");
});

test("rights gate: a release with no content parts needs no confirmation and says none", async () => {
  const c = await run();
  assert.equal(c.verdict, "accept");
  assert.equal(c.entry.content_confirmed, undefined);
});

test("binding: the owner-file line's SHA-256 must be the lease's binding_token_sha256", async () => {
  const zip = stagingZip();
  const good = await run({ zip });
  assert.equal(good.verdict, "accept", JSON.stringify(good.findings));
  const bad = await run({ zip, request: { ...REQUEST, binding_token_sha256: bindingTokenSha256("someoneElsesToken_0123456789") } });
  assert.equal(bad.verdict, "refuse");
  assert.ok(codes(bad).includes("E_UNBOUND"));
  // bound, and the tag's line is the listed one but not the service's current binding
  const stale = await run({ zip, state: emptyState({ bindings: { 900000001: BINDING } }), request: { ...REQUEST, binding_token_sha256: bindingTokenSha256("aNewlyMintedToken_0123456789") } });
  assert.ok(codes(stale).includes("E_UNBOUND"), JSON.stringify(stale.findings));
  // bound, the line is the listed one, and the lease names no binding (nothing to compare)
  const same = await run({ zip, state: emptyState({ bindings: { 900000001: BINDING } }), request: { ...REQUEST, binding_token_sha256: null } });
  assert.equal(same.verdict, "accept", JSON.stringify(same.findings));
});

test("account: a first binding names the repository owner's GitHub login, never an account the request carries (ID-1, BOT-10)", async () => {
  const c = await run({ request: { ...REQUEST, account: "minice-subject-0042" } });
  assert.equal(c.verdict, "accept", JSON.stringify(c.findings));
  assert.equal(c.entry.publisher.account, "astra-staging-author");
  assert.equal(c.meta.binding.account, "astra-staging-author");
  assert.ok(!JSON.stringify(c).includes("minice-subject-0042"), "no request account reaches the candidate");
  // a renamed owner keeps the login it was first bound under
  const zip = stagingZip();
  const renamed = { ...fixture("repo.json"), owner: { id: 800000001, login: "renamed-author" } };
  const later = await run({ zip, github: fakeGithub({ zip, repo: renamed }), state: emptyState({ bindings: { 900000001: BINDING } }) });
  assert.equal(later.entry.publisher.account, "astra-staging-author");
});

test("parseRequest: a lease item, strictly; no account, token or subject member is accepted", () => {
  const ok = parseRequest({ lease_id: "L-1", repo_id: 900000001, tag: null, binding_token_sha256: "c".repeat(64), confirmed: [COVER], extra: 1 });
  assert.deepEqual(ok, { lease_id: "L-1", repo_id: 900000001, tag: null, binding_token_sha256: "c".repeat(64), confirmed: [COVER] });
  const bad = (doc, re) => assert.throws(() => parseRequest(doc), re);
  bad({ ...ok, lease_id: "../x" }, /lease_id/);
  bad({ ...ok, binding_token_sha256: "C".repeat(64) }, /binding_token_sha256/);
  bad({ ...ok, binding_token_sha256: "c".repeat(63) }, /binding_token_sha256/);
  bad({ ...ok, confirmed: [{ ...COVER, text_version: 0 }] }, /confirmed\[0\]/);
  // a text id is dot-separated segments, each [a-z][a-z0-9_-]* (games-index-v1 content_confirmed)
  for (const id of ["market..rights", "market.rights.", ".market", "Market.rights", "market.9rights"]) {
    bad({ ...ok, confirmed: [{ ...COVER, text_id: id }] }, /confirmed\[0\]/);
  }
  bad({ ...ok, confirmed: [COVER, { ...COVER, path: "b.png", text_version: 4 }] }, /CURRENT version/);
  for (const k of ["account", "binding_token", "subject"]) bad({ ...ok, [k]: "x" }, new RegExp(k));
});

test("Check now: a lease with no tag ingests the latest stable release, and a repository with none is refused", async () => {
  const zip = stagingZip();
  const c = await run({ zip, request: { ...REQUEST, tag: null } });
  assert.equal(c.verdict, "accept", JSON.stringify(c.findings));
  assert.equal(c.request.tag, "v1.0.0");
  assert.equal(c.request.lease_id, "lease-1");
  const none = await run({ zip, request: { ...REQUEST, tag: null }, github: fakeGithub({ zip, latest: null }) });
  assert.ok(codes(none).includes("E_RELEASE_NOT_FOUND"));
  assert.equal(none.request.tag, null);
});

// ── gi-probe 0.5.1's subcommands, by release (lib/probe.mjs's table) ─────

function fooFoundation(probe) {
  const zip = makeZip({ "astra-gi.toml": fixtureText("foo-engine.toml"), "foo/runtime.dll": "x" });
  return run({ zip, probe, github: fakeGithub({ zip, release: { ...fixture("release.json"), tag_name: "v0.1.0" } }), request: { ...REQUEST, tag: "v0.1.0" }, certificate: { sourceRepositoryRef: "refs/tags/v0.1.0" } });
}

test("a community integration runs check alone, --provenance community, with loaders[] as the bare array check.rs reads", async () => {
  const probe = fakeProbe();
  const c = await run({ probe });
  assert.equal(c.verdict, "accept", JSON.stringify(c.findings));
  assert.deepEqual(probe.calls.map((a) => a[0]), ["check"]);
  const [argv] = probe.calls;
  assert.equal(argv[argv.indexOf("--provenance") + 1], "community");
  const list = JSON.parse(fs.readFileSync(argv[argv.indexOf("--loaders") + 1], "utf8"));
  assert.ok(Array.isArray(list) && list.length > 0);
  for (const l of list) assert.deepEqual(Object.keys(l).sort(), ["default_enabled", "name", "sha256"]);
  assert.deepEqual(c.meta.probe, { name: "gi-probe", version: "0.5.1", source_tree_sha256: PIN_051.source_tree_sha256, ran: ["check"], notices: [] });
});

test("a foundation that owns a code runs validate-descriptor on its astra-gi.toml as shipped; a digest it disagrees on refuses", async () => {
  const probe = fakeProbe();
  const c = await fooFoundation(probe);
  assert.ok(!codes(c).some((x) => /PROBE/.test(x)), JSON.stringify(c.findings));
  assert.deepEqual(probe.calls.map((a) => a[0]), ["check", "validate-descriptor"]);
  const shipped = probe.calls[1][1];
  assert.equal(fs.readFileSync(shipped, "utf8"), fixtureText("foo-engine.toml"));
  const d = await fooFoundation(fakeProbe({ "validate-descriptor": { descriptor_sha256: "c".repeat(64) } }));
  assert.ok(codes(d).includes("E_PROBE_DISAGREES"), JSON.stringify(d.findings));
  // validate-descriptor's refusal is gi-probe's, said once even when check says it too
  const lint = { code: "descriptor-too-broad", step: 2, field: "engine.rules", detail: "anchored on a generic name", params: { reason: "generic-name" } };
  const e = await fooFoundation(fakeProbe({ check: { findings: [lint] }, "validate-descriptor": { findings: [lint] } }));
  assert.equal(e.findings.filter((f) => f.probe_code === "descriptor-too-broad").length, 1);
});

test("first-party: a 0.2.7 source of its own repository runs compat (R30); compat's refusal refuses, and other releases never run it", async () => {
  const zip0 = (await firstPartyRun()).zip;
  const pins = [{ repository_id: 1409552680, tag: "v1.0.0", asset: "astra-gi.zip", sha256: sha256(zip0) }];
  const { c, probe } = await firstPartyRun({ pins });
  assert.equal(c.verdict, "accept", JSON.stringify(c.findings));
  assert.deepEqual(probe.calls.map((a) => a[0]), ["check", "compat"]);
  const [check, compat] = probe.calls;
  assert.equal(check[check.indexOf("--provenance") + 1], "first-party");
  assert.equal(compat[compat.indexOf("--source") + 1], "astra.peak");
  assert.equal(compat[compat.indexOf("--tag") + 1], "v1.0.0");
  assert.equal(compat[compat.indexOf("--asset") + 1], "astra-gi.zip");
  assert.equal(compat[compat.indexOf("--sha256") + 1], sha256(zip0));
  assert.ok(!compat.includes("--prerelease"));
  assert.deepEqual(c.meta.probe.ran, ["check", "compat"]);
  // compat.rs's own refusal (tests/gi_probe.rs l.1297-1300: verdict fail, findings)
  const refused = (await firstPartyRun({ pins, probe: fakeProbe({ compat: { findings: [{ code: "needs-newer-astra", step: 1, detail: "uses ${astra_pack_inbox}", params: { min_astra: "0.2.8", placeholder: "astra_pack_inbox" } }] } }) })).c;
  assert.ok(refused.findings.some((f) => f.code === "E_PROBE" && f.probe_code === "needs-newer-astra"), JSON.stringify(refused.findings));
  // a prerelease is judged as one
  const pre = await firstPartyRun({ pins, prerelease: true });
  assert.ok(pre.probe.calls[1].includes("--prerelease"));
  // a first-party id 0.2.7 never installed: no compat (compat.rs l.142-150 would exit 2)
  const fresh = stagingZip(fixtureText("astra-gi.toml").replace("astra-staging-author.staging-csharp-gi", "astra.new-game").replace("Staging C# test integration", "Astra in a new game"));
  const n = await firstPartyRun({ zip: fresh });
  assert.deepEqual(n.probe.calls.map((a) => a[0]), ["check"]);
  // a community release: never
  const probe2 = fakeProbe();
  await run({ probe: probe2 });
  assert.ok(!probe2.calls.some((a) => a[0] === "compat"));
});
