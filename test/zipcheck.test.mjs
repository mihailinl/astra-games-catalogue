// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Zip Cloaking: a crafted zip whose LOCAL file headers disagree with its
// CENTRAL DIRECTORY lets a validator (which reads the central directory,
// as Python's zipfile and every reader in this repository do) and a naive
// sequential extractor see two different archives. schemacheck.py's
// verify_zip_headers (lib/schemas.mjs's verifyZipHeaders) refuses that
// before anything is classified as content.
//
// Both cloaked fixtures below are built by SURGERY on an otherwise normal
// zip's own bytes -- not by hand-writing a zip format, so the "normal zip
// passes" and "cloaked zip refuses" cases are guaranteed to differ by
// exactly the one fact each test names.

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { CODES } from "../lib/codes.mjs";
import { checkContent } from "../lib/content.mjs";
import { verifyZipHeaders } from "../lib/schemas.mjs";
import { makeZipBytes, tmpdir } from "./helpers.mjs";

function writeZip(buf) {
  const p = path.join(tmpdir(), "astra-gi.zip");
  fs.writeFileSync(p, buf);
  return p;
}

// ── a tiny, from-scratch central-directory parser, so the cloaking
// fixtures below can be built by editing exactly one fact in otherwise
// real zip bytes. This mirrors schemacheck.py's own field offsets; it is
// deliberately NOT the thing under test. ──────────────────────────────

function findEocd(buf) {
  for (let i = buf.length - 22; i >= 0; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) return i;
  }
  throw new Error("no end-of-central-directory record in this test fixture");
}

function readCentralDirectory(buf) {
  const eocd = findEocd(buf);
  const totalEntries = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  const cdOffset = buf.readUInt32LE(eocd + 16);
  const entries = [];
  let pos = cdOffset;
  for (let i = 0; i < totalEntries; i++) {
    const fnLen = buf.readUInt16LE(pos + 28);
    const extraLen = buf.readUInt16LE(pos + 30);
    const cmtLen = buf.readUInt16LE(pos + 32);
    const lho = buf.readUInt32LE(pos + 42);
    const name = buf.toString("utf8", pos + 46, pos + 46 + fnLen);
    const recLen = 46 + fnLen + extraLen + cmtLen;
    entries.push({ name, pos, recLen, lho });
    pos += recLen;
  }
  return { eocd, totalEntries, cdSize, cdOffset, entries };
}

/** Deletes `name`'s record from the central directory, leaving its local
 * header and data physically in the file -- a hidden entry no
 * central-directory reader will ever see, but whose bytes sit, unlisted,
 * in what should be the gap right before the central directory. */
function hideFromCentralDirectory(buf, name) {
  const { eocd, totalEntries, cdSize, entries } = readCentralDirectory(buf);
  const hidden = entries.find((e) => e.name === name);
  assert.ok(hidden, `no such entry ${name} in this test's own fixture`);
  const spliced = Buffer.concat([buf.subarray(0, hidden.pos), buf.subarray(hidden.pos + hidden.recLen)]);
  const newEocd = eocd - hidden.recLen;
  spliced.writeUInt16LE(totalEntries - 1, newEocd + 8);
  spliced.writeUInt16LE(totalEntries - 1, newEocd + 10);
  spliced.writeUInt32LE(cdSize - hidden.recLen, newEocd + 12);
  return spliced;
}

/** Overwrites the LOCAL header's copy of `name` with `newName` (same byte
 * length, so no offset anywhere else in the file moves) -- the central
 * directory still calls it `name`. */
function renameLocalHeaderOnly(buf, name, newName) {
  assert.equal(name.length, newName.length, "a same-length swap keeps every other offset valid");
  const idx = buf.indexOf(Buffer.from(name, "utf8"));
  assert.ok(idx >= 0, `${name} not found in this test's own fixture`);
  const out = Buffer.from(buf);
  out.write(newName, idx, "utf8");
  return out;
}

function normalZip() {
  return makeZipBytes({ "astra-gi.toml": "x", "art/cover.png": Buffer.from("89504e470d0a1a0a0000000000000000", "hex") });
}

test("a normal zip's headers are consistent", () => {
  assert.deepEqual(verifyZipHeaders(writeZip(normalZip())), { ok: true });
});

test("Zip Cloaking: a hidden local entry the central directory does not list is refused", () => {
  const cloaked = hideFromCentralDirectory(normalZip(), "art/cover.png");
  const r = verifyZipHeaders(writeZip(cloaked));
  assert.equal(r.ok, false);
  assert.match(r.error, /E_ZIP_HEADERS_INCONSISTENT/);
  assert.match(r.error, /undeclared byte/);
});

test("Zip Cloaking: a local header naming itself differently than the central directory is refused", () => {
  const cloaked = renameLocalHeaderOnly(normalZip(), "art/cover.png", "art/cover.pnX");
  const r = verifyZipHeaders(writeZip(cloaked));
  assert.equal(r.ok, false);
  assert.match(r.error, /E_ZIP_HEADERS_INCONSISTENT/);
  assert.match(r.error, /calls itself/);
});

test("checkContent refuses a cloaked release with E_ZIP_HEADERS_INCONSISTENT before any content classification", () => {
  const zipPath = writeZip(hideFromCentralDirectory(normalZip(), "art/cover.png"));
  const manifest = { integration: { content: [{ path: "art/cover.png", kind: "art", title: "t", credit: "c", licence: "CC0" }] } };
  const r = checkContent({ zipPath, manifest });
  assert.deepEqual(r.content, []);
  assert.equal(r.findings.length, 1, JSON.stringify(r.findings));
  assert.equal(r.findings[0].code, CODES.E_ZIP_HEADERS_INCONSISTENT);
});
