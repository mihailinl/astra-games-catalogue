// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// lib/probe.mjs against gi-probe 0.5.0's REAL interface: every command line
// it builds is one main.rs at v0.5.0 accepts (test/gi-probe-v050.mjs, frozen
// from `git show v0.5.0:src/bin/gi-probe/main.rs`), and anything that is not
// the pinned build's report of the input is ProbeUnavailable. No real
// gi-probe runs here: fixtures/gi-probe/fake-gi-probe.mjs answers in its place.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import {
  ASTRA_027_SOURCES, ProbeUnavailable, binaryProbe, checkArgv, compatArgv, compatSourceFor, readPin, readReport, validateDescriptorArgv,
} from "../lib/probe.mjs";
import { gameFilesOf, linkOf } from "../lib/model.mjs";
import { readTomlFile } from "../lib/schemas.mjs";
import { ACCEPTS, COMPAT_027, TAG, TOOL, parseLikeMain } from "./gi-probe-v050.mjs";
import { FAKE_GI_PROBE, PIN_050, ROOT, fakeProbe, makeZip, tmpdir } from "./helpers.mjs";

/** Every command line lib/probe.mjs can build, one per shape. */
function everyArgv() {
  const zip = "/w/astra-gi.zip";
  return [
    checkArgv({ zip, firstParty: false, loaders: "/w/gi-probe-loaders.json" }),
    checkArgv({ zip, firstParty: true, loaders: "/w/gi-probe-loaders.json" }),
    validateDescriptorArgv({ file: "/w/astra-gi.toml", firstParty: false }),
    validateDescriptorArgv({ file: "/w/astra-gi.toml", firstParty: true }),
    compatArgv({ zip, source: "astra.peak", tag: "v1.0.0", asset: "astra-gi.zip", sha256: "a".repeat(64), prerelease: false }),
    compatArgv({ zip, source: "astra.peak", tag: "v1.0.0", asset: "astra-gi.zip", sha256: "a".repeat(64), prerelease: true }),
  ];
}

test(`every command line lib/probe.mjs builds is one gi-probe ${TAG}'s main.rs accepts`, () => {
  const used = new Set();
  for (const argv of everyArgv()) {
    const p = parseLikeMain(argv);
    assert.ok(p.ok, `gi-probe ${TAG} refuses \`gi-probe ${argv.join(" ")}\`: ${p.detail}`);
    used.add(p.sub);
  }
  // capture and pick are never ingest's
  assert.deepEqual([...used].sort(), ["check", "compat", "validate-descriptor"]);
  // and the frozen reading refuses what 0.5.0 refuses (main.rs l.416, l.538)
  assert.equal(parseLikeMain(["ingest", "--zip", "z", "--loaders", "l", "--json"]).ok, false);
  assert.equal(parseLikeMain(["check", "z", "--json"]).ok, false);
  assert.equal(parseLikeMain(["check", "--zip", "z"]).ok, false);
  assert.equal(parseLikeMain(["check", "z", "--provenance", "astra"]).ok, false);
  assert.equal(parseLikeMain(["compat", "--zip", "z", "--source", "astra.peak"]).ok, false, "compat needs --tag");
});

test("lib/probe.mjs's Astra 0.2.7 sources are compat-0.2.7.json's, and compat runs for a first-party 0.2.7 source of its own repository only", () => {
  assert.deepEqual(ASTRA_027_SOURCES.map((s) => ({ ...s })), COMPAT_027.sources.map(({ id, repo_id, asset }) => ({ id, repo_id, asset })));
  assert.equal(compatSourceFor({ firstParty: true, manifestId: "astra.peak", repoId: 1409552680, asset: "astra-gi.zip" }), "astra.peak");
  assert.equal(compatSourceFor({ firstParty: false, manifestId: "astra.peak", repoId: 1409552680, asset: "astra-gi.zip" }), null);
  assert.equal(compatSourceFor({ firstParty: true, manifestId: "astra.peak", repoId: 1409552749, asset: "astra-gi.zip" }), null, "another repository");
  assert.equal(compatSourceFor({ firstParty: true, manifestId: "astra.unity-il2cpp", repoId: 1408152993, asset: "astra-gi.zip" }), null, "another asset");
  assert.equal(compatSourceFor({ firstParty: true, manifestId: "astra.new-game", repoId: 1409552680, asset: "astra-gi.zip" }), null);
});

test("gi-probe.json pins the build the tests hold the fake to, and fetch-gi-probe reads its source tree", () => {
  const pin = readPin();
  assert.equal(pin.schema, "astra.games.gi-probe/1");
  assert.equal(pin.source_tree_sha256, TOOL.source_tree_sha256);
  assert.ok(pin.version === null || pin.version === TOOL.version, "a re-pin re-reads the tag and re-freezes test/gi-probe-v050.mjs");
  assert.deepEqual(PIN_050, TOOL);
});

test("an unknown subcommand, as 0.5.0 answers it (exit 2, error.usage), is ProbeUnavailable", async () => {
  const probe = fakeProbe();
  const zip = path.join(tmpdir(), "astra-gi.zip");
  fs.writeFileSync(zip, makeZip({ "astra-gi.toml": "schema = 1\n" }));
  await assert.rejects(probe.run("ingest", ["ingest", "--zip", zip, "--loaders", "l.json", "--json"]), (e) => e instanceof ProbeUnavailable && /exit 2, usage: unknown subcommand "ingest"/.test(e.message));
  // an option 0.5.0 does not know is the same (main.rs l.416)
  await assert.rejects(probe.run("check", ["check", zip, "--json"]), (e) => e instanceof ProbeUnavailable && /unknown option --json/.test(e.message));
  // --loaders that is not a bare array: exit 2, io (check.rs l.120-135)
  const obj = path.join(tmpdir(), "loaders.json");
  fs.copyFileSync(path.join(ROOT, "loaders.json"), obj);
  await assert.rejects(probe.run("check", checkArgv({ zip, firstParty: false, loaders: obj })), (e) => e instanceof ProbeUnavailable && /exit 2, io: .*loaders\[\]/.test(e.message));
});

test("readReport: only the pinned build's report of the subcommand asked is read", () => {
  const ok = { schema: "astra.gi-probe/1", tool: { ...TOOL }, subcommand: "validate-descriptor", verdict: "pass", input: {}, spec: {}, descriptor: { sha256: "a".repeat(64), codes: {} }, negative_folders: [], notices: [], findings: [] };
  const read = (r, code = 0, pin = PIN_050) => readReport("validate-descriptor", { stdout: typeof r === "string" ? r : JSON.stringify(r), code }, pin);
  assert.equal(read(ok).descriptor.sha256, "a".repeat(64));
  const unavailable = (r, code, pin, why) => assert.throws(() => read(r, code, pin), (e) => e instanceof ProbeUnavailable, why);
  unavailable("", 0, PIN_050, "empty stdout");
  unavailable("not json", 1, PIN_050, "not JSON");
  unavailable({ ...ok, schema: "astra.gi-probe/0" }, 0, PIN_050, "schema");
  unavailable({ schema: "astra.gi-probe/1", tool: { ...TOOL }, subcommand: "validate-descriptor", error: { code: "usage", detail: "validate-descriptor takes one file" } }, 2, PIN_050, "exit 2");
  unavailable(ok, 2, PIN_050, "exit 2 with a report");
  unavailable(ok, 101, PIN_050, "a panic's exit");
  unavailable({ ...ok, tool: { ...TOOL, version: "0.4.9" } }, 0, PIN_050, "version");
  unavailable({ ...ok, tool: { version: "0.5.0" } }, 0, PIN_050, "no source tree");
  unavailable(ok, 0, { version: "0.5.1" }, "the pin moved");
  unavailable({ ...ok, subcommand: "check" }, 0, PIN_050, "another subcommand");
  unavailable(ok, 1, PIN_050, "exit 1 with a pass");
  unavailable({ ...ok, verdict: "fail" }, 1, PIN_050, "fail without findings");
  unavailable({ ...ok, findings: [{ code: "x", level: "error", message: "m" }], verdict: "fail" }, 1, PIN_050, "the old contract's finding");
  unavailable({ ...ok, descriptor: null }, 0, PIN_050, "a pass without a descriptor");
  // a pin without source_tree_sha256 asks only the version
  assert.equal(read({ ...ok, tool: { version: "0.5.0", source_tree_sha256: "0".repeat(64) } }, 0, { version: "0.5.0" }).verdict, "pass");
});

test("binaryProbe fails closed before it runs anything: no pin, no binary", async () => {
  await assert.rejects(binaryProbe({ env: { GI_PROBE: FAKE_GI_PROBE }, pin: { version: null } }).run("check", ["check", "z"]), ProbeUnavailable);
  await assert.rejects(binaryProbe({ env: { PATH: "", GI_PROBE: "" }, pin: PIN_050 }).run("check", ["check", "z"]), ProbeUnavailable);
  await assert.rejects(binaryProbe({ env: { GI_PROBE: path.join(tmpdir(), "nothing-here") }, pin: PIN_050 }).run("check", ["check", "z"]), ProbeUnavailable);
});

test("what gi-probe 0.5.0 does not report comes from the catalogue's own reading: the Link summary, schema_digests, game files", () => {
  const golden = path.join(ROOT, "lib/vendor/astraplugins/testdata/games/manifests/valid/game-specific-link.toml");
  const { manifest } = readTomlFile(golden);
  const files = {
    "astra/SKILL.md": "1".repeat(64), "astra/tools/drop_item.json": "2".repeat(64),
    "astra/triggers/boss_spawned.json": "3".repeat(64), "astra/events/player_died.json": "4".repeat(64), "winhttp.dll": "5".repeat(64),
  };
  const l = linkOf(manifest, files);
  assert.deepEqual(l.problems, []);
  // manifest.md §2.6.1: digest is SHA-256(JCS([integration.link] as parsed)); vectors.json's "game-specific-link" vector pins this exact value
  assert.deepEqual(l.link, { context: true, shares_other_players: false, skill_digest: "1".repeat(64), digest: "e26a440ebf1c3cacc9891fc8b031d9c0d8cbde9276ceeba68d1866a972a35ea2" });
  assert.deepEqual(l.schemaDigests, { "astra/tools/drop_item.json": "2".repeat(64), "astra/triggers/boss_spawned.json": "3".repeat(64), "astra/events/player_died.json": "4".repeat(64) });
  const { "astra/SKILL.md": _, ...noSkill } = files;
  assert.equal(linkOf(manifest, noSkill).problems.length, 1);
  // check.rs l.500-505's row for the golden's one game file, against the catalogue's digest
  const row = { dest: "${game}/winhttp.dll", sha256: "5".repeat(64), class: "allowlisted", allowlisted_as: "doorstop-winhttp" };
  assert.deepEqual(gameFilesOf(manifest, files, [row]), { gameFiles: [{ path: "winhttp.dll", sha256: "5".repeat(64), loader: "allowlisted" }], problems: [] });
  assert.equal(gameFilesOf(manifest, files, []).problems.length, 1, "a game file gi-probe did not class");
  assert.equal(gameFilesOf(manifest, files, [{ ...row, sha256: "6".repeat(64) }]).problems.length, 1, "another digest");
  assert.equal(gameFilesOf(manifest, files, [{ ...row, dest: "${game}/version.dll" }]).problems.length, 1, "another destination");
});

// Re-reads main.rs at the tag the frozen list names, when a launcher checkout
// is at hand (ASTRA_GAME_LAUNCHER_REPO): `git show` only, nothing built or run.
test(`the frozen list is main.rs at ${TAG}`, { skip: process.env.ASTRA_GAME_LAUNCHER_REPO ? false : "set ASTRA_GAME_LAUNCHER_REPO to a clone of astra-game-launcher" }, () => {
  const src = execFileSync("git", ["-C", process.env.ASTRA_GAME_LAUNCHER_REPO, "show", `${TAG}:src/bin/gi-probe/main.rs`]).toString("utf8");
  const body = src.slice(src.indexOf("fn run(argv"), src.indexOf("fn main()"));
  const found = {};
  for (const m of body.matchAll(/"([a-z-]+)" => \{\s*let a = Args::parse\(\s*rest,\s*&\[([^\]]*)\],\s*&\[([^\]]*)\],?\s*\)\?;/g)) {
    const names = (s) => [...s.matchAll(/"([^"]+)"/g)].map((x) => x[1]);
    found[m[1]] = { options: names(m[2]), flags: names(m[3]) };
  }
  assert.deepEqual(found, Object.fromEntries(Object.entries(ACCEPTS).map(([k, v]) => [k, { options: [...v.options], flags: [...v.flags] }])));
});
