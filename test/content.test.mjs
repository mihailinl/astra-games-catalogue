// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// AstraPlugins manifest.md §2.7 / legal DRAFT-v3.md Part 6 G4-G5: the
// content-coverage check and the HARD VRM licence gate, over real zip
// bytes (lib/content.mjs + schemacheck.py's `content` command). Each test
// below takes a release that is otherwise clean and flips the ONE fact the
// refusal cares about, the same shape test/rules.test.mjs uses for the
// manifest goldens.

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { CODES } from "../lib/codes.mjs";
import { checkContent } from "../lib/content.mjs";
import { ROOT, makeGlb, makeZipBytes, tmpdir } from "./helpers.mjs";

const PNG = Buffer.from("89504e470d0a1a0a0000000000000000", "hex");
const OGG = Buffer.from("OggS" + "\x00".repeat(8), "latin1");
const FBX = Buffer.from("Kaydara FBX Binary  \x00\x1a\x00" + "\x00".repeat(8), "latin1");

// Each fixture below isolates ONE condition: the OTHER spec field is set to
// an explicitly-allowed value, because rule_vrm_licence_refused checks
// redistribution before avatar-permission for each spec, and an absent
// field already refuses (G4's corrected defaults). CC_BY (a UniVRM
// LicenseType, O-2c), never "Redistribution_Allowed" -- that token is not
// one of UniVRM's own, so the gate reads it "unknown", not "allowed"
// (AstraPlugins 516ba38, O-2b/O-2c).
const ALLOWED_VRM0 = makeGlb({ extensions: { VRM: { meta: { allowedUserName: "Everyone", licenseName: "CC_BY" } } } });
const ALLOWED_VRM1 = makeGlb({ extensions: { VRMC_vrm: { meta: { avatarPermission: "everyone", allowRedistribution: true } } } });
const ONLY_AUTHOR_VRM0 = makeGlb({ extensions: { VRM: { meta: { licenseName: "CC_BY", allowedUserName: "OnlyAuthor" } } } });
const ONLY_AUTHOR_VRM1 = makeGlb({ extensions: { VRMC_vrm: { meta: { allowRedistribution: true, avatarPermission: "onlyAuthor" } } } });
const NAMED_PEOPLE_VRM0 = makeGlb({ extensions: { VRM: { meta: { licenseName: "CC_BY", allowedUserName: "ExplicitlyLicensedPerson" } } } });
const NAMED_PEOPLE_VRM1 = makeGlb({ extensions: { VRMC_vrm: { meta: { allowRedistribution: true, avatarPermission: "onlySeparatelyLicensedPerson" } } } });
const ABSENT_FIELDS_VRM0 = makeGlb({ extensions: { VRM: { meta: {} } } });
const ABSENT_FIELDS_VRM1 = makeGlb({ extensions: { VRMC_vrm: { meta: {} } } });
const UNKNOWN_NO_META = makeGlb({ asset: { version: "2.0" } });
// O-2b: a licence/permission token the gate does not name is UNKNOWN, never
// allowed -- "Redistribution_Allowed" is exactly the token that used to slip
// through as allowed (AstraPlugins 516ba38's "allowed.vrm" bug).
const UNKNOWN_LICENCE_TOKEN = makeGlb({ extensions: { VRM: { meta: { licenseName: "Other", allowedUserName: "Everyone" } } } });
const STRING_TRUE_REDISTRIBUTION_VRM1 = makeGlb({ extensions: { VRMC_vrm: { meta: { allowRedistribution: "true", avatarPermission: "everyone" } } } });
const UNKNOWN_VS_ALLOWED = makeGlb({ extensions: {
  VRM: { meta: { licenseName: "Other", allowedUserName: "Everyone" } },
  VRMC_vrm: { meta: { allowRedistribution: true, avatarPermission: "everyone" } },
} });
const ANIMATION_ONLY = makeGlb({ extensions: { VRMC_vrm_animation: {} }, extensionsUsed: ["VRMC_vrm_animation"] });

// AstraPlugins 4976d60: a GLB built from LITERAL JSON text (never
// JSON.stringify, which cannot itself name a member twice) or with a lying
// chunk-length field, the same shape as AstraPlugins'
// tools/check-games-goldens.py / testdata/games/content/vrm/gen.py builds
// its hostile E_CONTENT_FORMAT goldens.
function glbFromText(text) {
  const bodyText = Buffer.from(text, "utf8");
  const pad = (4 - (bodyText.length % 4)) % 4;
  const body = Buffer.concat([bodyText, Buffer.alloc(pad, 0x20)]);
  const chunk0 = Buffer.concat([
    Buffer.from(new Uint32Array([body.length]).buffer),
    Buffer.from("JSON", "ascii"),
    body,
  ]);
  const header = Buffer.concat([
    Buffer.from("glTF", "ascii"),
    Buffer.from(new Uint32Array([2, 12 + chunk0.length]).buffer),
  ]);
  return Buffer.concat([header, chunk0]);
}

/** A whole GLB (the file's own total length is correct) whose JSON CHUNK
 * header lies and claims 8 bytes more than the file actually holds after
 * it -- "the GLB's JSON chunk runs past the end of the file". */
function glbChunkPastEof(obj) {
  const bodyText = Buffer.from(JSON.stringify(obj), "utf8");
  const pad = (4 - (bodyText.length % 4)) % 4;
  const chunk = Buffer.concat([bodyText, Buffer.alloc(pad, 0x20)]);
  const chunkHeader = Buffer.concat([
    Buffer.from(new Uint32Array([chunk.length + 8]).buffer),
    Buffer.from("JSON", "ascii"),
  ]);
  const body = Buffer.concat([chunkHeader, chunk]);
  const header = Buffer.concat([
    Buffer.from("glTF", "ascii"),
    Buffer.from(new Uint32Array([2, 12 + body.length]).buffer),
  ]);
  return Buffer.concat([header, body]);
}

function zipPathFor(files) {
  const dir = tmpdir();
  const p = path.join(dir, "astra-gi.zip");
  fs.writeFileSync(p, makeZipBytes(files));
  return p;
}

const codesOf = (r) => r.findings.map((f) => f.code);
const contentEntry = (over = {}) => ({ path: "character/avatar.vrm", kind: "character", title: "t", credit: "c", ...over });

test("E_CONTENT_UNDECLARED: an extra content-typed file with no entry, fixed by declaring it", () => {
  const zipPath = zipPathFor({ "astra-gi.toml": "x", "art/cover.png": PNG, "audio/theme.ogg": OGG });
  const manifest = { integration: { content: [{ path: "art/cover.png", kind: "art", title: "t", credit: "c", licence: "CC0" }] } };
  const r1 = checkContent({ zipPath, manifest });
  assert.ok(codesOf(r1).includes(CODES.E_CONTENT_UNDECLARED), JSON.stringify(r1.findings));

  const fixed = { integration: { content: [...manifest.integration.content, { path: "audio/theme.ogg", kind: "audio", title: "t", credit: "c", licence: "CC0" }] } };
  const r2 = checkContent({ zipPath, manifest: fixed });
  assert.ok(!codesOf(r2).includes(CODES.E_CONTENT_UNDECLARED), JSON.stringify(r2.findings));
});

test("E_CONTENT_MISSING: a declared path with no file, fixed by adding the file", () => {
  const manifest = { integration: { content: [{ path: "animations/climb.fbx", kind: "animations", title: "t", credit: "c", licence: "CC0" }] } };
  const zipMissing = zipPathFor({ "astra-gi.toml": "x" });
  const r1 = checkContent({ zipPath: zipMissing, manifest });
  assert.ok(codesOf(r1).includes(CODES.E_CONTENT_MISSING), JSON.stringify(r1.findings));

  const zipPresent = zipPathFor({ "astra-gi.toml": "x", "animations/climb.fbx": FBX });
  const r2 = checkContent({ zipPath: zipPresent, manifest });
  assert.ok(!codesOf(r2).includes(CODES.E_CONTENT_MISSING), JSON.stringify(r2.findings));
});

test("E_CONTENT_DUPLICATE: two entries covering one file, fixed by removing one", () => {
  const zipPath = zipPathFor({ "astra-gi.toml": "x", "animations/climb.fbx": FBX });
  const entry = { path: "animations/climb.fbx", kind: "animations", title: "t", credit: "c", licence: "CC0" };
  const dup = { integration: { content: [entry, { ...entry, title: "t2" }] } };
  const r1 = checkContent({ zipPath, manifest: dup });
  assert.ok(codesOf(r1).includes(CODES.E_CONTENT_DUPLICATE), JSON.stringify(r1.findings));

  const fixed = { integration: { content: [entry] } };
  const r2 = checkContent({ zipPath, manifest: fixed });
  assert.ok(!codesOf(r2).includes(CODES.E_CONTENT_DUPLICATE), JSON.stringify(r2.findings));
});

test("a renamed loader is not picked up as content by extension alone (magic bytes must also match)", () => {
  const notAPng = Buffer.from("MZ" + "\x00".repeat(30), "latin1"); // a PE header
  const zipPath = zipPathFor({ "astra-gi.toml": "x", "art/evil.png": notAPng });
  const r = checkContent({ zipPath, manifest: { integration: { content: [] } } });
  assert.deepEqual(r.findings, [], "a non-PNG 'evil.png' must never surface as E_CONTENT_UNDECLARED");
  assert.deepEqual(r.content, []);
});

// ── G4: the HARD VRM gate, the corrected defaults, and named-people ──────

for (const [label, bytes, field, value] of [
  ["VRM 0.x only-author", ONLY_AUTHOR_VRM0, "extensions.VRM.meta.allowedUserName", "OnlyAuthor"],
  ["VRM 1.0 only-author", ONLY_AUTHOR_VRM1, "extensions.VRMC_vrm.meta.avatarPermission", "onlyAuthor"],
  ["VRM 0.x named-people", NAMED_PEOPLE_VRM0, "extensions.VRM.meta.allowedUserName", "ExplicitlyLicensedPerson"],
  ["VRM 1.0 named-people", NAMED_PEOPLE_VRM1, "extensions.VRMC_vrm.meta.avatarPermission", "onlySeparatelyLicensedPerson"],
  ["VRM 0.x absent fields default to refused", ABSENT_FIELDS_VRM0, "extensions.VRM.meta.licenseName", null],
  ["VRM 1.0 absent fields default to refused", ABSENT_FIELDS_VRM1, "extensions.VRMC_vrm.meta.allowRedistribution", null],
]) {
  test(`E_CONTENT_LICENCE_REFUSED: ${label}`, () => {
    const manifest = { integration: { content: [contentEntry({ licence: "CC0" })] } };
    const zipPath = zipPathFor({ "astra-gi.toml": "x", "character/avatar.vrm": bytes });
    const r = checkContent({ zipPath, manifest });
    const f = r.findings.find((x) => x.code === CODES.E_CONTENT_LICENCE_REFUSED);
    assert.ok(f, JSON.stringify(r.findings));
    assert.equal(f.field, field);
    assert.deepEqual(r.content, [], "a licence-refused part is never listed");
  });
}

test("the allowed VRM 0.x and 1.0 fixtures pass, and content[] keeps the VRM licence", () => {
  for (const [bytes, version] of [[ALLOWED_VRM0, "0.x"], [ALLOWED_VRM1, "1.0"]]) {
    const manifest = { integration: { content: [contentEntry({ licence: "CC0" })] } };
    const zipPath = zipPathFor({ "astra-gi.toml": "x", "character/avatar.vrm": bytes });
    const r = checkContent({ zipPath, manifest });
    assert.ok(!codesOf(r).includes(CODES.E_CONTENT_LICENCE_REFUSED), JSON.stringify(r.findings));
    assert.equal(r.content.length, 1);
    assert.equal(r.content[0].vrm_licence.vrm_version, version);
    assert.equal(r.content[0].licence_source, "vrm");
    assert.equal(r.content[0].sha256.length, 64);
  }
});

test("G5: the VRM usage flags are kept with the part", () => {
  const vrm0 = makeGlb({ extensions: { VRM: { meta: {
    allowedUserName: "Everyone", licenseName: "CC_BY",
    violentUssageName: "Disallow", sexualUssageName: "Disallow", commercialUssageName: "Allow",
  } } } });
  const r0 = checkContent({
    zipPath: zipPathFor({ "astra-gi.toml": "x", "character/avatar.vrm": vrm0 }),
    manifest: { integration: { content: [contentEntry({ licence: "CC0" })] } },
  });
  const fields0 = r0.content[0].vrm_licence.fields;
  assert.equal(fields0.violentUssageName, "Disallow");
  assert.equal(fields0.sexualUssageName, "Disallow");
  assert.equal(fields0.commercialUssageName, "Allow");

  const vrm1 = makeGlb({ extensions: { VRMC_vrm: { meta: {
    allowRedistribution: true, avatarPermission: "everyone",
    allowExcessivelyViolentUsage: false, allowExcessivelySexualUsage: false,
    allowPoliticalOrReligiousUsage: true, allowAntisocialOrHateUsage: false,
  } } } });
  const r1 = checkContent({
    zipPath: zipPathFor({ "astra-gi.toml": "x", "character/avatar.vrm": vrm1 }),
    manifest: { integration: { content: [contentEntry({ licence: "CC0" })] } },
  });
  const fields1 = r1.content[0].vrm_licence.fields;
  assert.equal(fields1.allowPoliticalOrReligiousUsage, true);
  assert.equal(fields1.allowAntisocialOrHateUsage, false);
});

// ── "unknown" meta: flagged, never refused, and G5's declared fallback ───

test("a VRM with no readable meta at all is flagged F_CONTENT_VRM_META_UNKNOWN, never refused", () => {
  const manifest = { integration: { content: [contentEntry({ licence: "CC0" })] } };
  const zipPath = zipPathFor({ "astra-gi.toml": "x", "character/avatar.vrm": UNKNOWN_NO_META });
  const r = checkContent({ zipPath, manifest });
  assert.ok(!codesOf(r).includes(CODES.E_CONTENT_LICENCE_REFUSED));
  assert.ok(codesOf(r).includes(CODES.F_CONTENT_VRM_META_UNKNOWN), JSON.stringify(r.findings));
  assert.equal(r.content[0].vrm_licence, undefined, "no VRM extension at all means nothing to keep");
  assert.equal(r.content[0].licence_source, "declared", "unknown meta falls back to the manifest's own licence");
});

test("E_CONTENT_LICENCE_UNDECLARED: unknown VRM meta AND no declared licence refuses; declaring one fixes it", () => {
  const zipPath = zipPathFor({ "astra-gi.toml": "x", "character/avatar.vrm": UNKNOWN_NO_META });
  const r1 = checkContent({ zipPath, manifest: { integration: { content: [contentEntry()] } } }); // no licence key
  assert.ok(codesOf(r1).includes(CODES.E_CONTENT_LICENCE_UNDECLARED), JSON.stringify(r1.findings));
  assert.deepEqual(r1.content, []);

  const r2 = checkContent({ zipPath, manifest: { integration: { content: [contentEntry({ licence: "All rights reserved" })] } } });
  assert.ok(!codesOf(r2).includes(CODES.E_CONTENT_LICENCE_UNDECLARED), JSON.stringify(r2.findings));
  assert.equal(r2.content[0].licence_source, "declared");
  assert.equal(r2.content[0].licence, "All rights reserved");
});

test("E_CONTENT_LICENCE_UNDECLARED: a non-VRM part with no declared licence refuses; declaring one fixes it", () => {
  const zipPath = zipPathFor({ "astra-gi.toml": "x", "audio/theme.ogg": OGG });
  const entry = { path: "audio/theme.ogg", kind: "audio", title: "t", credit: "c" }; // no licence
  const r1 = checkContent({ zipPath, manifest: { integration: { content: [entry] } } });
  assert.ok(codesOf(r1).includes(CODES.E_CONTENT_LICENCE_UNDECLARED), JSON.stringify(r1.findings));

  const r2 = checkContent({ zipPath, manifest: { integration: { content: [{ ...entry, licence: "CC0-1.0" }] } } });
  assert.ok(!codesOf(r2).includes(CODES.E_CONTENT_LICENCE_UNDECLARED), JSON.stringify(r2.findings));
  assert.equal(r2.content[0].licence_source, "declared");
});

test("a VRM part's readable licence_source is 'vrm' regardless of a declared licence", () => {
  const zipPath = zipPathFor({ "astra-gi.toml": "x", "character/avatar.vrm": ALLOWED_VRM0 });
  const r = checkContent({ zipPath, manifest: { integration: { content: [contentEntry({ licence: "irrelevant text" })] } } });
  assert.equal(r.content[0].licence_source, "vrm");
});

// ── .astrachar: the nested body is gated the same as a bare .vrm ────────

test(".astrachar: a readable bundle's body is gated the same as a bare .vrm", () => {
  const inner = makeZipBytes({
    "astrachar.json": JSON.stringify({ format: "astra.character", body: { file: "models/Mira.vrm" } }),
    "models/Mira.vrm": ONLY_AUTHOR_VRM0,
  });
  const manifest = { integration: { content: [{ path: "character/Mira.astrachar", kind: "character", title: "t", credit: "c", licence: "CC0" }] } };
  const zipPath = zipPathFor({ "astra-gi.toml": "x", "character/Mira.astrachar": inner });
  const r = checkContent({ zipPath, manifest });
  const f = r.findings.find((f2) => f2.code === CODES.E_CONTENT_LICENCE_REFUSED);
  assert.ok(f, JSON.stringify(r.findings));
  assert.equal(f.path, "character/Mira.astrachar");
  assert.equal(f.field, "extensions.VRM.meta.allowedUserName");
});

test(".astrachar: an unreadable body is a gap (F_CONTENT_ASTRACHAR_UNREADABLE), never a refusal", () => {
  const inner = makeZipBytes({ "astrachar.json": JSON.stringify({ format: "astra.character", body: { ref: "builtin:nayu" } }) });
  const manifest = { integration: { content: [{ path: "character/Mira.astrachar", kind: "character", title: "t", credit: "c", licence: "CC0" }] } };
  const zipPath = zipPathFor({ "astra-gi.toml": "x", "character/Mira.astrachar": inner });
  const r = checkContent({ zipPath, manifest });
  assert.ok(!codesOf(r).includes(CODES.E_CONTENT_LICENCE_REFUSED));
  assert.ok(codesOf(r).includes(CODES.F_CONTENT_ASTRACHAR_UNREADABLE), JSON.stringify(r.findings));
  assert.equal(r.content.length, 1, "a gap still lists the part -- it just has no vrm_licence, and falls back to the declared licence");
  assert.equal(r.content[0].licence_source, "declared");
});

test("a fully covered, all-allowed release has no findings and lists every part", () => {
  const manifest = {
    integration: {
      content: [
        { path: "art/cover.png", kind: "art", title: "Cover", credit: "someone", licence: "CC0-1.0" },
        { path: "character/avatar.vrm", kind: "character", title: "Avatar", credit: "someone", licence: "CC-BY-4.0" },
      ],
    },
  };
  const zipPath = zipPathFor({ "astra-gi.toml": "x", "art/cover.png": PNG, "character/avatar.vrm": ALLOWED_VRM0 });
  const r = checkContent({ zipPath, manifest });
  assert.deepEqual(r.findings, []);
  assert.equal(r.content.length, 2);
  const byPath = Object.fromEntries(r.content.map((c) => [c.path, c]));
  assert.equal(byPath["art/cover.png"].kind, "art");
  assert.equal(byPath["art/cover.png"].licence_source, "declared");
  assert.equal(byPath["character/avatar.vrm"].vrm_licence.vrm_version, "0.x");
  assert.equal(byPath["character/avatar.vrm"].licence_source, "vrm");
});

test("no [[integration.content]] table at all is not itself a problem", () => {
  const zipPath = zipPathFor({ "astra-gi.toml": "x" });
  const r = checkContent({ zipPath, manifest: { integration: {} } });
  assert.deepEqual(r.findings, []);
  assert.deepEqual(r.content, []);
});

// ── O-2: a VRM carrying both metas is judged on both ────────────────────

const VRM_FIXTURES = path.join(ROOT, "fixtures", "vrm-conflict");
const DISAGREE = fs.readFileSync(path.join(VRM_FIXTURES, "vrm-metas-disagree.vrm"));
const AGREE = fs.readFileSync(path.join(VRM_FIXTURES, "vrm-metas-agree.vrm"));

test("E_CONTENT_LICENCE_CONFLICT: a 0.x meta that allows beside a 1.0 meta that prohibits is refused, never read by the first meta", () => {
  const manifest = { integration: { content: [contentEntry({ licence: "CC0" })] } };
  const r = checkContent({ zipPath: zipPathFor({ "astra-gi.toml": "x", "character/avatar.vrm": DISAGREE }), manifest });
  const f = r.findings.find((x) => x.code === CODES.E_CONTENT_LICENCE_CONFLICT);
  assert.ok(f, JSON.stringify(r.findings));
  assert.equal(f.path, "character/avatar.vrm");
  assert.equal(f.field, "gate verdict");
  assert.ok(!codesOf(r).includes(CODES.E_CONTENT_LICENCE_UNDECLARED), "a conflict is refused before licence_source is asked");
  assert.deepEqual(r.content, [], "a conflicting part is never listed");
});

test("both metas present and agreeing pass, shown as the VRM 1.0 side", () => {
  const manifest = { integration: { content: [contentEntry({ licence: "CC0" })] } };
  const r = checkContent({ zipPath: zipPathFor({ "astra-gi.toml": "x", "character/avatar.vrm": AGREE }), manifest });
  assert.deepEqual(codesOf(r).filter((c) => c.startsWith("E_")), [], JSON.stringify(r.findings));
  assert.equal(r.content.length, 1);
  assert.equal(r.content[0].vrm_licence.vrm_version, "1.0");
  assert.equal(r.content[0].licence_source, "vrm");
});

// AstraPlugins 516ba38 dropped the usage-flag comparison this branch had
// added: the content gate never compares usage flags, so a display-only
// difference between the two specs must not refuse a release here either.
test("both metas allow redistribution: a disagreeing usage flag is NOT a conflict (usage flags are display only)", () => {
  const both = (violent0, violent1) => makeGlb({ extensions: {
    VRM: { meta: { licenseName: "CC_BY", allowedUserName: "Everyone", violentUssageName: violent0 } },
    VRMC_vrm: { meta: { allowRedistribution: true, avatarPermission: "everyone", allowExcessivelyViolentUsage: violent1 } },
  } });
  const manifest = { integration: { content: [contentEntry({ licence: "CC0" })] } };
  const r = checkContent({ zipPath: zipPathFor({ "astra-gi.toml": "x", "character/avatar.vrm": both("Allow", false) }), manifest });
  assert.ok(!codesOf(r).includes(CODES.E_CONTENT_LICENCE_CONFLICT), JSON.stringify(r.findings));
  assert.equal(r.content[0].vrm_licence.vrm_version, "1.0");
});

test(".astrachar: a body carrying disagreeing metas is a conflict too", () => {
  const inner = makeZipBytes({
    "astrachar.json": JSON.stringify({ format: "astra.character", body: { file: "models/Mira.vrm" } }),
    "models/Mira.vrm": DISAGREE,
  });
  const manifest = { integration: { content: [{ path: "character/Mira.astrachar", kind: "character", title: "t", credit: "c", licence: "CC0" }] } };
  const r = checkContent({ zipPath: zipPathFor({ "astra-gi.toml": "x", "character/Mira.astrachar": inner }), manifest });
  assert.equal(r.findings.find((x) => x.code === CODES.E_CONTENT_LICENCE_CONFLICT)?.path, "character/Mira.astrachar", JSON.stringify(r.findings));
});

// ── O-2b/O-2c and the extension-based selection rule (AstraPlugins 516ba38) ─

test("F_CONTENT_VRM_META_UNKNOWN: an unrecognised licence token is flagged, never accepted as a VRM licence", () => {
  const manifest = { integration: { content: [contentEntry({ licence: "CC0" })] } };
  const zipPath = zipPathFor({ "astra-gi.toml": "x", "character/avatar.vrm": UNKNOWN_LICENCE_TOKEN });
  const r = checkContent({ zipPath, manifest });
  assert.ok(!codesOf(r).includes(CODES.E_CONTENT_LICENCE_REFUSED), JSON.stringify(r.findings));
  assert.ok(codesOf(r).includes(CODES.F_CONTENT_VRM_META_UNKNOWN), JSON.stringify(r.findings));
  assert.equal(r.content[0].vrm_licence, undefined, "an unrecognised token is never read as an accepted VRM licence");
  assert.equal(r.content[0].licence_source, "declared");
});

test('E_CONTENT_LICENCE_REFUSED: the string "true" redistribution is prohibited, not a bool', () => {
  const manifest = { integration: { content: [contentEntry({ licence: "CC0" })] } };
  const zipPath = zipPathFor({ "astra-gi.toml": "x", "character/avatar.vrm": STRING_TRUE_REDISTRIBUTION_VRM1 });
  const r = checkContent({ zipPath, manifest });
  const f = r.findings.find((x) => x.code === CODES.E_CONTENT_LICENCE_REFUSED);
  assert.ok(f, JSON.stringify(r.findings));
  assert.equal(f.field, "extensions.VRMC_vrm.meta.allowRedistribution");
  assert.deepEqual(r.content, []);
});

test("E_CONTENT_LICENCE_CONFLICT: a 0.x meta that reads unknown beside a 1.0 meta that reads allowed is a conflict too", () => {
  const manifest = { integration: { content: [contentEntry({ licence: "CC0" })] } };
  const zipPath = zipPathFor({ "astra-gi.toml": "x", "character/avatar.vrm": UNKNOWN_VS_ALLOWED });
  const r = checkContent({ zipPath, manifest });
  const f = r.findings.find((x) => x.code === CODES.E_CONTENT_LICENCE_CONFLICT);
  assert.ok(f, JSON.stringify(r.findings));
  assert.equal(f.field, "gate verdict");
  assert.deepEqual(r.content, []);
});

test("an avatar GLB declared in an 'animations' part is still refused by the gate (selection is by extensions, never by kind or name)", () => {
  const manifest = { integration: { content: [{ path: "models/x.glb", kind: "animations", title: "t", credit: "c", licence: "CC0" }] } };
  const zipPath = zipPathFor({ "astra-gi.toml": "x", "models/x.glb": ONLY_AUTHOR_VRM0 });
  const r = checkContent({ zipPath, manifest });
  const f = r.findings.find((x) => x.code === CODES.E_CONTENT_LICENCE_REFUSED);
  assert.ok(f, JSON.stringify(r.findings));
  assert.equal(f.path, "models/x.glb");
  assert.equal(f.field, "extensions.VRM.meta.allowedUserName");
});

test("a VRMC_vrm_animation-only GLB never reaches the VRM gate: no finding at all", () => {
  const manifest = { integration: { content: [{ path: "animations/run.glb", kind: "animations", title: "t", credit: "c", licence: "CC0" }] } };
  const zipPath = zipPathFor({ "astra-gi.toml": "x", "animations/run.glb": ANIMATION_ONLY });
  const r = checkContent({ zipPath, manifest });
  assert.deepEqual(r.findings, [], "an animation is never judged by the VRM gate, not even as 'unknown'");
  assert.equal(r.content.length, 1);
  assert.equal(r.content[0].vrm_licence, undefined);
  assert.equal(r.content[0].licence_source, "declared");
});

// ── E_CONTENT_FORMAT (AstraPlugins 4976d60): held BEFORE classification ──

test("E_CONTENT_FORMAT: an animations-part GLB that names 'extensions' twice is refused, never read as plain", () => {
  // A lenient parser keeps only the LAST "extensions" member ({}), so the
  // file would classify as "plain" -- and a plain glTF in an "animations"
  // part was never judged by the gate at all, publishing the avatar that
  // the FIRST "extensions" member prohibits with no licence verdict.
  const bytes = glbFromText(
    '{"extensions": {"VRM": {"meta": {"licenseName": "Redistribution_Prohibited", "allowedUserName": "OnlyAuthor"}}}, "extensions": {}}',
  );
  const manifest = { integration: { content: [{ path: "animations/wave.glb", kind: "animations", title: "t", credit: "c", licence: "CC0" }] } };
  const zipPath = zipPathFor({ "astra-gi.toml": "x", "animations/wave.glb": bytes });
  const r = checkContent({ zipPath, manifest });
  const f = r.findings.find((x) => x.code === CODES.E_CONTENT_FORMAT);
  assert.ok(f, JSON.stringify(r.findings));
  assert.equal(f.path, "animations/wave.glb");
  assert.deepEqual(r.content, [], "a format-refused part is never listed");
});

test("E_CONTENT_FORMAT: a GLB whose JSON chunk is declared past EOF is refused", () => {
  const bytes = glbChunkPastEof({ asset: { version: "2.0" } });
  const manifest = { integration: { content: [contentEntry({ licence: "CC0" })] } };
  const zipPath = zipPathFor({ "astra-gi.toml": "x", "character/avatar.vrm": bytes });
  const r = checkContent({ zipPath, manifest });
  const f = r.findings.find((x) => x.code === CODES.E_CONTENT_FORMAT);
  assert.ok(f, JSON.stringify(r.findings));
  assert.deepEqual(r.content, []);
});

test("E_CONTENT_FORMAT: a GLB naming an https:// image uri is refused (nothing Astra loads may fetch a URL)", () => {
  const bytes = makeGlb({ asset: { version: "2.0" }, images: [{ uri: "https://example.invalid/t.png" }] });
  const manifest = { integration: { content: [{ path: "art/portrait.glb", kind: "art", title: "t", credit: "c", licence: "CC0" }] } };
  const zipPath = zipPathFor({ "astra-gi.toml": "x", "art/portrait.glb": bytes });
  const r = checkContent({ zipPath, manifest });
  const f = r.findings.find((x) => x.code === CODES.E_CONTENT_FORMAT);
  assert.ok(f, JSON.stringify(r.findings));
  assert.deepEqual(r.content, []);
});

test("E_CONTENT_FORMAT: a .gltf buffer uri that climbs out of the release ('../') is refused", () => {
  const text = JSON.stringify({ asset: { version: "2.0" }, buffers: [{ uri: "../evil.bin" }] });
  const manifest = { integration: { content: [{ path: "models/prop.gltf", kind: "models", title: "t", credit: "c", licence: "CC0" }] } };
  const zipPath = zipPathFor({ "astra-gi.toml": "x", "models/prop.gltf": text });
  const r = checkContent({ zipPath, manifest });
  const f = r.findings.find((x) => x.code === CODES.E_CONTENT_FORMAT);
  assert.ok(f, JSON.stringify(r.findings));
  assert.deepEqual(r.content, []);
});

test("a .gltf naming a sibling .bin the release holds has no format finding", () => {
  const text = JSON.stringify({ asset: { version: "2.0" }, buffers: [{ uri: "prop.bin" }] });
  const manifest = { integration: { content: [{ path: "models/prop.gltf", kind: "models", title: "t", credit: "c", licence: "CC0" }] } };
  const zipPath = zipPathFor({ "astra-gi.toml": "x", "models/prop.gltf": text, "models/prop.bin": Buffer.from([1, 2, 3, 4]) });
  const r = checkContent({ zipPath, manifest });
  assert.ok(!codesOf(r).includes(CODES.E_CONTENT_FORMAT), JSON.stringify(r.findings));
  assert.equal(r.content.length, 1);
  assert.equal(r.content[0].path, "models/prop.gltf");
});
