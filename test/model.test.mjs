// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// manifest.md §2.6.1's link digest (lib/model.mjs linkOf): every vendored
// link.digest vector, through the catalogue's own function, plus the
// gi-probe-disagrees wiring (gi-probe 0.5.1+ carries its own link.digest;
// 0.5.0 does not).

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { linkOf } from "../lib/model.mjs";
import { readTomlFile } from "../lib/schemas.mjs";
import { VENDOR } from "../lib/vendored.mjs";

const AP = path.join(VENDOR, "astraplugins");
const VECTORS = JSON.parse(fs.readFileSync(path.join(AP, "testdata/games/vectors.json"), "utf8"));

for (const v of VECTORS.link.digest) {
  test(`link.digest vector ${v.name}: manifest.md §2.6.1 through linkOf`, () => {
    const toml = readTomlFile(path.join(AP, "testdata/games", v.manifest));
    assert.ok(toml.ok, toml.error);
    assert.ok(toml.manifest.integration?.link, `${v.manifest} has no [integration.link]`);
    const r = linkOf(toml.manifest, {});
    assert.equal(r.link.digest, v.digest, v.note);
  });
}

test("crlf and crlf-as-lf are the same table, so they share a digest (CRLF inside a multi-line string is read as LF)", () => {
  const crlf = VECTORS.link.digest.find((v) => v.name === "crlf");
  const asLf = VECTORS.link.digest.find((v) => v.name === "crlf-as-lf");
  assert.equal(crlf.digest, asLf.digest);
});

test("no [integration.link] table: link is null, no digest, no problems", () => {
  assert.deepEqual(linkOf({ integration: {} }, {}), { link: null, schemaDigests: {}, problems: [] });
});

test("gi-probe check's link.digest, when it agrees, raises no problem", () => {
  const toml = readTomlFile(path.join(AP, "testdata/games/manifests/valid/game-specific-link.toml"));
  const files = { "astra/SKILL.md": "a".repeat(64), "astra/tools/drop_item.json": "b".repeat(64), "astra/triggers/boss_spawned.json": "c".repeat(64), "astra/events/player_died.json": "d".repeat(64) };
  const r = linkOf(toml.manifest, files, linkOf(toml.manifest, files).link.digest);
  assert.deepEqual(r.problems, []);
});

test("gi-probe check's link.digest, when it disagrees, is a problem (ingest.mjs turns it into E_PROBE_DISAGREES)", () => {
  const toml = readTomlFile(path.join(AP, "testdata/games/manifests/valid/game-specific-link.toml"));
  const files = { "astra/SKILL.md": "a".repeat(64), "astra/tools/drop_item.json": "b".repeat(64), "astra/triggers/boss_spawned.json": "c".repeat(64), "astra/events/player_died.json": "d".repeat(64) };
  const r = linkOf(toml.manifest, files, "f".repeat(64));
  assert.ok(r.problems.some((p) => p.includes("digest") && p.includes("gi-probe")), JSON.stringify(r.problems));
});

// MUTATION: a default added for an absent key, or the CRLF-to-LF
// normalisation dropped, changes the digest a vendored vector pins —
// proving the test is sensitive to both. (Not run by default: it exercises
// the rule by hand, against jcs() directly, the same function linkOf calls.)
test("mutation sentinel: writing a default out explicitly changes the digest from the vector pinned", async () => {
  const { jcs } = await import("../lib/vendor/astra-registry/tools/lib/canonical.mjs");
  const { sha256Hex } = await import("../lib/model.mjs");
  const edge = VECTORS.link.digest.find((v) => v.name === "edge");
  const toml = readTomlFile(path.join(AP, "testdata/games", edge.manifest));
  const l = toml.manifest.integration.link;
  assert.equal(sha256Hex(Buffer.from(jcs(l), "utf8")), edge.digest);
  // l.triggers is absent in edge.toml; writing the default out (never done by
  // linkOf, which hashes `l` exactly as parsed) must change the digest.
  const withDefault = { ...l, triggers: [] };
  assert.notEqual(sha256Hex(Buffer.from(jcs(withDefault), "utf8")), edge.digest);
});
