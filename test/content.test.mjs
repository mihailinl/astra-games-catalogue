// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// AstraPlugins manifest.md §2.7: the content-coverage check and the HARD VRM
// licence gate, over real zip bytes (lib/content.mjs + schemacheck.py's
// `content` command). Each test below takes a release that is otherwise
// clean and flips the ONE fact the refusal cares about, the same shape
// test/rules.test.mjs uses for the manifest goldens.

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { CODES } from "../lib/codes.mjs";
import { checkContent } from "../lib/content.mjs";
import { makeGlb, makeZipBytes, tmpdir } from "./helpers.mjs";

const PNG = Buffer.from("89504e470d0a1a0a0000000000000000", "hex");
const OGG = Buffer.from("OggS" + "\x00".repeat(8), "latin1");
const FBX = Buffer.from("Kaydara FBX Binary  \x00\x1a\x00" + "\x00".repeat(8), "latin1");

const ALLOWED_VRM = makeGlb({ extensions: { VRM: { meta: { allowedUserName: "Everyone", licenseName: "Redistribution_Allowed" } } } });
const REFUSED_VRM0 = makeGlb({ extensions: { VRM: { meta: { allowedUserName: "OnlyAuthor" } } } });
const REFUSED_VRM1 = makeGlb({ extensions: { VRMC_vrm: { meta: { avatarPermission: "onlyAuthor" } } } });

function zipPathFor(files) {
  const dir = tmpdir();
  const p = path.join(dir, "astra-gi.zip");
  fs.writeFileSync(p, makeZipBytes(files));
  return p;
}

const codesOf = (r) => r.findings.map((f) => f.code);

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

test("E_CONTENT_LICENCE_REFUSED: VRM 0.x OnlyAuthor is refused, naming the field; the allowed fixture passes", () => {
  const manifest = { integration: { content: [{ path: "character/avatar.vrm", kind: "character", title: "t", credit: "c", licence: "CC0" }] } };
  const refusedZip = zipPathFor({ "astra-gi.toml": "x", "character/avatar.vrm": REFUSED_VRM0 });
  const r1 = checkContent({ zipPath: refusedZip, manifest });
  const f1 = r1.findings.find((f) => f.code === CODES.E_CONTENT_LICENCE_REFUSED);
  assert.ok(f1, JSON.stringify(r1.findings));
  assert.equal(f1.field, "extensions.VRM.meta.allowedUserName");
  assert.deepEqual(r1.content, [], "a licence-refused part is never listed");

  const allowedZip = zipPathFor({ "astra-gi.toml": "x", "character/avatar.vrm": ALLOWED_VRM });
  const r2 = checkContent({ zipPath: allowedZip, manifest });
  assert.ok(!codesOf(r2).includes(CODES.E_CONTENT_LICENCE_REFUSED), JSON.stringify(r2.findings));
  assert.equal(r2.content.length, 1);
  assert.equal(r2.content[0].vrm_licence.vrm_version, "0.x");
  assert.equal(r2.content[0].sha256.length, 64);
});

test("E_CONTENT_LICENCE_REFUSED: VRM 1.0 onlyAuthor is refused, naming the field", () => {
  const manifest = { integration: { content: [{ path: "character/avatar.vrm", kind: "character", title: "t", credit: "c", licence: "CC0" }] } };
  const zipPath = zipPathFor({ "astra-gi.toml": "x", "character/avatar.vrm": REFUSED_VRM1 });
  const r = checkContent({ zipPath, manifest });
  const f = r.findings.find((f2) => f2.code === CODES.E_CONTENT_LICENCE_REFUSED);
  assert.ok(f, JSON.stringify(r.findings));
  assert.equal(f.field, "extensions.VRMC_vrm.meta.avatarPermission");
});

test("an absent VRM meta field is not itself a refusal", () => {
  const noMeta = makeGlb({ asset: { version: "2.0" } });
  const manifest = { integration: { content: [{ path: "character/avatar.vrm", kind: "character", title: "t", credit: "c", licence: "CC0" }] } };
  const zipPath = zipPathFor({ "astra-gi.toml": "x", "character/avatar.vrm": noMeta });
  const r = checkContent({ zipPath, manifest });
  assert.deepEqual(r.findings, []);
  assert.equal(r.content[0].vrm_licence, undefined, "no VRM extension at all means nothing to keep");
});

test(".astrachar: a readable bundle's body is gated the same as a bare .vrm", () => {
  const inner = makeZipBytes({
    "astrachar.json": JSON.stringify({ format: "astra.character", body: { file: "models/Mira.vrm" } }),
    "models/Mira.vrm": REFUSED_VRM0,
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
  assert.equal(r.content.length, 1, "a gap still lists the part -- it just has no vrm_licence");
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
  const zipPath = zipPathFor({ "astra-gi.toml": "x", "art/cover.png": PNG, "character/avatar.vrm": ALLOWED_VRM });
  const r = checkContent({ zipPath, manifest });
  assert.deepEqual(r.findings, []);
  assert.equal(r.content.length, 2);
  const byPath = Object.fromEntries(r.content.map((c) => [c.path, c]));
  assert.equal(byPath["art/cover.png"].kind, "art");
  assert.equal(byPath["character/avatar.vrm"].vrm_licence.vrm_version, "0.x");
});

test("no [[integration.content]] table at all is not itself a problem", () => {
  const zipPath = zipPathFor({ "astra-gi.toml": "x" });
  const r = checkContent({ zipPath, manifest: { integration: {} } });
  assert.deepEqual(r.findings, []);
  assert.deepEqual(r.content, []);
});
