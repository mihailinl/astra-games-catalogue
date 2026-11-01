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

import { ingestRelease } from "../lib/ingest.mjs";
import { descriptorDigest } from "../lib/model.mjs";
import { binaryProbe } from "../lib/probe.mjs";
import { loadReserved, readTomlFile } from "../lib/schemas.mjs";
import { emptyModeration } from "../lib/state.mjs";
import { ROOT, fakeGh, fakeGithub, fakeSteam, fixture, fixtureText, makeZip, makeZipBytes, sha256, stubProbe, tmpdir } from "./helpers.mjs";

const reserved = loadReserved();
const firstParty = JSON.parse(fs.readFileSync(path.join(ROOT, "first-party.json"), "utf8"));
const loadersFile = path.join(ROOT, "loaders.json");
const BINDING = { account: "astra-staging-author", repo_id: 900000001, repo_owner_id: 800000001, binding_token: "stagingBindingToken_0123456789abcdef" };
const REQUEST = { repo_id: 900000001, tag: "v1.0.0", account: "astra-staging-author", binding_token: "stagingBindingToken_0123456789abcdef" };

function emptyState(extra = {}) {
  return { entries: [], bindings: {}, engineCodes: {}, moderation: emptyModeration(), withdrawn: { rows: [], held: [] }, holds: [], health: {}, floors: {}, ...extra };
}

function stagingZip(manifestText = fixtureText("astra-gi.toml")) {
  return makeZip({ "astra-gi.toml": manifestText, "BepInEx/plugins/Staging.dll": "not really a dll" });
}

async function run({ zip = stagingZip(), state = emptyState(), certificate = {}, gh = null, probe = null, github = null, request = REQUEST, manifestId = "astra-staging-author.staging-csharp-gi", version = "1.0.0", descriptorSha = null } = {}) {
  return ingestRelease({
    request,
    policy: { firstParty, loadersFile },
    state,
    reserved,
    deps: {
      github: github ?? fakeGithub({ zip }),
      gh: gh ?? fakeGh({ sha: sha256(zip), certificate }),
      probe: probe ?? stubProbe({ manifestId, version, descriptorSha }),
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
  const c = await run({
    zip,
    state: emptyState({ bindings: { 900000001: BINDING } }),
    github: fakeGithub({ zip, ownerFile: "astra-binding: anotherAccountsToken_abcdef0123\n" }),
  });
  assert.equal(c.verdict, "hold");
  assert.ok(codes(c).includes("R_BINDING_CHANGED"));
});

test("an unbound repository is refused, and a first release needs the site's account", async () => {
  const zip = stagingZip();
  const a = await run({ zip, github: fakeGithub({ zip, ownerFile: null }) });
  assert.ok(codes(a).includes("E_UNBOUND"));
  const b = await run({ zip, request: { repo_id: 900000001, tag: "v1.0.0" } });
  assert.ok(codes(b).includes("E_UNBOUND"));
});

test("a community prerelease is refused (stable releases only)", async () => {
  const zip = stagingZip();
  const release = { ...fixture("release.json"), prerelease: true };
  const c = await run({ zip, github: fakeGithub({ zip, release }) });
  assert.ok(codes(c).includes("E_PRERELEASE"));
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
  const c = await run({ probe: binaryProbe({ env: { PATH: "", GI_PROBE: "" } }) });
  assert.equal(c.verdict, "wait");
  assert.ok(codes(c).includes("W_PROBE_UNAVAILABLE"));
  assert.equal(c.entry, undefined);
});

test("a gi-probe error refuses; a gi-probe that disagrees with tomllib refuses", async () => {
  const a = await run({ probe: stubProbe({ manifestId: "astra-staging-author.staging-csharp-gi", version: "1.0.0", findings: [{ code: "zip-traversal", level: "error", message: "../evil" }] }) });
  assert.ok(codes(a).includes("E_PROBE"));
  const b = await run({ probe: stubProbe({ manifestId: "someone.else", version: "1.0.0" }) });
  assert.ok(codes(b).includes("E_PROBE_DISAGREES"));
  const c = await run({ probe: { async ingest() { return { nonsense: true }; } } });
  assert.ok(codes(c).includes("E_PROBE"));
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
  const c = await run({ zip });
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

function firstPartyRun({ pins = [], zip = stagingZip(fixtureText("astra-gi.toml").replace("astra-staging-author.staging-csharp-gi", "astra.peak").replace("Staging C# test integration", "Astra in PEAK")), prerelease = false } = {}) {
  const repo = { id: 1409552680, full_name: "mihailinl/astra-peak", owner: { id: 193032699 }, private: false, visibility: "public", default_branch: "main" };
  const policy = { firstParty: { ...firstParty, pins }, loadersFile };
  const gh = fakeGh({ sha: sha256(zip) });
  return ingestRelease({
    request: { repo_id: 1409552680, tag: "v1.0.0" },
    policy,
    state: emptyState(),
    reserved,
    deps: {
      github: fakeGithub({ zip, repo, release: { ...fixture("release.json"), prerelease } }),
      gh,
      probe: stubProbe({ manifestId: "astra.peak", version: "1.0.0" }),
      steam: fakeSteam(),
      workdir: tmpdir(),
      now: () => 1793448000,
    },
  }).then((c) => ({ c, gh, zip }));
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
