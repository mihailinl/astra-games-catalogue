// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The S goldens, through ingest's own checks: every manifest golden gets the
// verdict AstraPlugins' vectors.json records for it, by the rule it names,
// and the two descriptor attacks the catalogue owns (code squatting, taking a
// recognised game) are refused here, where the ownership table is.

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { CODES } from "../lib/codes.mjs";
import { engineCodeFindings, descriptorCodes, manifestFindings, skeleton, entryIdFor, tagNamesVersion } from "../lib/rules.mjs";
import { loadReserved, readTomlFile, validateMany } from "../lib/schemas.mjs";
import { VENDOR } from "../lib/vendored.mjs";

const AP = path.join(VENDOR, "astraplugins");
const vectors = JSON.parse(fs.readFileSync(path.join(AP, "testdata/games/vectors.json"), "utf8"));
const reserved = loadReserved();
const load = (rel) => {
  const r = readTomlFile(path.join(AP, "testdata/games", rel));
  assert.ok(r.ok, r.error);
  return r.manifest;
};

const RULE_CODE = {
  "engine-undeclared": CODES.E_ENGINE_UNDECLARED,
  "engine-code-reserved": CODES.E_ENGINE_CODE_RESERVED,
  "loader-policy-conflict": CODES.E_LOADER_POLICY_CONFLICT,
  "capability-undeclared": CODES.E_CAPABILITY_UNDECLARED,
  "reserved-id": CODES.E_RESERVED_ID,
  "reserved-name": CODES.E_RESERVED_NAME,
};

for (const v of vectors.manifests.valid) {
  test(`manifest golden ${v.name}: accepted by schemalite and every rule`, () => {
    const m = load(v.file);
    const [r] = validateMany([{ schema: "manifest", doc: m }]);
    assert.ok(r.ok, r.error);
    // runner-builtin is first-party (astra.unity); every other golden is a community author's
    const fp = m.integration.id.startsWith("astra.");
    assert.deepEqual(manifestFindings(m, { reserved, firstParty: fp }).map((f) => f.code), []);
  });
}

for (const v of vectors.manifests.invalid) {
  test(`manifest golden ${v.name}: refused by ${v.check === "schema" ? "the schema" : v.rule}`, () => {
    const m = load(v.file);
    const [r] = validateMany([{ schema: "manifest", doc: m }]);
    if (v.check === "schema") {
      assert.equal(r.ok, false, `${v.name} passed the schema`);
    } else {
      const codes = manifestFindings(m, { reserved, firstParty: false }).map((f) => f.code);
      assert.ok(codes.includes(RULE_CODE[v.rule]), `${v.name}: ${RULE_CODE[v.rule]} not in ${codes}`);
    }
  });
}

test("hostile descriptor hijack-updates-code-squatting: engine-code-taken against the golden owner", () => {
  const owner = load("manifests/valid/foundation-owns-engine.toml");
  const squat = load("descriptors/hostile/hijack-updates-code-squatting.toml");
  const someone = { account: "someone", repo_id: 200000001, repo_owner_id: 100000001 };
  const another = { account: "another", repo_id: 200000002, repo_owner_id: 100000002 };
  const engineCodes = Object.fromEntries(descriptorCodes(owner.integration.engine).map((c) => [c, someone]));
  const found = engineCodeFindings({ codes: descriptorCodes(squat), identity: another, engineCodes, reserved });
  assert.deepEqual(found.map((f) => f.code), [CODES.E_ENGINE_CODE_TAKEN]);
  assert.deepEqual(engineCodeFindings({ codes: descriptorCodes(squat), identity: someone, engineCodes, reserved }), [], "the owner's own next release passes");
});

test("hostile descriptor take-recognised-game: engine-code-reserved", () => {
  const d = load("descriptors/hostile/take-recognised-game.toml");
  const codes = manifestFindings({ schema: 1, integration: { id: "x.y", name: "y", engine: d }, target: { engine: descriptorCodes(d)[0] } }, { reserved }).map((f) => f.code);
  assert.ok(codes.includes(CODES.E_ENGINE_CODE_RESERVED), String(codes));
});

test("entry ids: account prefix dropped, dots become dashes, the spec's spellings come out", () => {
  assert.equal(entryIdFor("someone", "someone.peak-astra"), "someone/peak-astra");
  assert.equal(entryIdFor("mihailinl", "astra.unity"), "mihailinl/astra-unity");
  assert.equal(skeleton("staging-csharp-g1"), skeleton("staging-csharp-gi"));
  assert.notEqual(skeleton("peak"), skeleton("lethal"));
});

// ── the release tag names the version (manifest.md §2) ─────────────────────
//
// The first four prefixed tags are the ones first-party.json pins. Until
// 2026-11-09 the check stripped one leading "v" and compared the rest, so
// each of them was refused E_VERSION_TAG_MISMATCH.

const TAG_NAMES = [
  ["0.8.1", "0.8.1"],
  ["v0.8.1", "0.8.1"],
  ["il2cpp-v0.8.1", "0.8.1"],
  ["ds1-v0.1.1", "0.1.1"],
  ["ds2-v0.1.1", "0.1.1"],
  ["gta3-v0.3.1", "0.3.1"],
  ["v0.1.0-discovery", "0.1.0-discovery"],
  ["0.1.0-discovery", "0.1.0-discovery"],
  ["a.b-c-v1.0.0+build.5", "1.0.0+build.5"],
  ["x-v1.0.0", "1.0.0"],
  ["7-v1.0.0", "1.0.0"],
  ["il2cpp-v0.1.0-discovery", "0.1.0-discovery"],
  // a tag may name two versions, and a release carries one manifest, so only one is ever asked about
  ["a-v1.0.0-v2.0.0", "2.0.0"],
  ["a-v1.0.0-v2.0.0", "1.0.0-v2.0.0"],
];

const TAG_DOES_NOT_NAME = [
  ["il2cpp-0.8.1", "0.8.1", "the -v after a prefix is required"],
  ["il2cpp-v0.8.2", "0.8.1", "another version"],
  ["IL2CPP-v0.8.1", "0.8.1", "a prefix is lowercase"],
  ["Il2cpp-v0.8.1", "0.8.1", "a prefix is lowercase"],
  ["-v0.8.1", "0.8.1", "an empty prefix"],
  ["il2cpp--v0.8.1", "0.8.1", "a prefix ends with a letter or a digit"],
  ["il2cpp.-v0.8.1", "0.8.1", "a prefix ends with a letter or a digit"],
  [".il2cpp-v0.8.1", "0.8.1", "a prefix begins with a letter or a digit"],
  ["il2_cpp-v0.8.1", "0.8.1", "an underscore is not in a prefix"],
  ["il2+cpp-v0.8.1", "0.8.1", "a plus is not in a prefix"],
  ["vv0.8.1", "0.8.1", "one v, not two"],
  ["V0.8.1", "0.8.1", "the v is lowercase"],
  ["il2cpp-V0.8.1", "0.8.1", "the v is lowercase"],
  ["il2cpp_v0.8.1", "0.8.1", "the separator is a hyphen"],
  ["il2cppv0.8.1", "0.8.1", "the separator is a hyphen"],
  ["v0.8.1-extra", "0.8.1", "a suffix is another version"],
  ["il2cpp-v0.8.1-extra", "0.8.1", "a suffix is another version"],
  ["v0.1.0-discovery", "0.1.0", "a prerelease is not its release"],
  ["v0.8.1", "0.8.10", "equality, not a prefix match"],
  ["v0.8.10", "0.8.1", "equality, not a prefix match"],
  ["v00.8.1", "0.8.1", "no semver normalisation"],
  ["v0.8.1", "0.8.1+build", "no semver normalisation"],
  ["x-v", "", "an empty version is named by nothing"],
  ["v", "", "an empty version is named by nothing"],
  ["", "", "an empty version is named by nothing"],
  ["x-v", "0.1.0", "no version in the tag"],
  ["release", "0.8.1", "no version in the tag"],
  ["undefined", undefined, "a version that is not a string"],
  ["v1", 1, "a version that is not a string"],
  [null, "0.8.1", "no tag"],
];

for (const [tag, version] of TAG_NAMES) {
  test(`tag ${tag} names version ${version}`, () => {
    assert.equal(tagNamesVersion(tag, version), true);
  });
}

for (const [tag, version, why] of TAG_DOES_NOT_NAME) {
  test(`tag ${JSON.stringify(tag)} does not name version ${JSON.stringify(version)}: ${why}`, () => {
    assert.equal(tagNamesVersion(tag, version), false);
  });
}

test("manifestFindings: a prefixed tag that names the version is no finding, and a mismatch says the three forms", () => {
  const m = load(vectors.manifests.valid[0].file);
  const withVersion = (version) => ({ ...m, integration: { ...m.integration, version } });
  const mismatch = (tag, version) =>
    manifestFindings(withVersion(version), { reserved, firstParty: true, tag }).filter((f) => f.code === CODES.E_VERSION_TAG_MISMATCH);
  for (const [tag, version] of TAG_NAMES) assert.deepEqual(mismatch(tag, version), [], `${tag} names ${version}`);
  for (const [tag, version] of TAG_DOES_NOT_NAME.filter(([t, v]) => typeof t === "string" && typeof v === "string")) {
    assert.equal(mismatch(tag, version).length, 1, `${tag} does not name ${JSON.stringify(version)}`);
  }
  const [f] = mismatch("il2cpp-0.8.1", "0.8.1");
  assert.match(f.message, /version is "0\.8\.1" and the release tag il2cpp-0\.8\.1 does not name it/);
  assert.match(f.message, /as V, vV or <prefix>-vV/);
  assert.deepEqual(mismatch(null, "0.8.1"), [], "no tag, no check (the goldens are checked without a release)");
});
