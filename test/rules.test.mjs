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
import { engineCodeFindings, descriptorCodes, manifestFindings, skeleton, entryIdFor } from "../lib/rules.mjs";
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
