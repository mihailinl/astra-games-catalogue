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
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { CODES } from "../lib/codes.mjs";
import { checkContent } from "../lib/content.mjs";
import { verifyZipHeaders } from "../lib/schemas.mjs";
import { makeZipBytes, tmpdir } from "./helpers.mjs";

const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "zip-cloaking");

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

// ── astra-ce sec-probe: two more cloaking shapes verify_zip_headers first
// missed, each with its own vector (fixtures/zip-cloaking/) and a mutation
// that fixes the one fact the refusal cares about. ──────────────────────

/** A minimal, hand-built single-entry STORED zip -- the same low-level
 * shape astra-ce's sec-probe gen.py uses, built here (not vendored) so
 * the mutation can flip exactly one fact against an otherwise identical
 * structure. */
function buildStoredZip({ name, data, extra = Buffer.alloc(0) }) {
  const script = `
import base64, json, struct, sys, zlib
req = json.loads(sys.stdin.read())
name = req["name"].encode()
data = base64.b64decode(req["data"])
extra = base64.b64decode(req["extra"])
crc = zlib.crc32(data)
def lfh(name, crc, sz, extra):
    return struct.pack('<IHHHHHIIIHH', 0x04034b50, 20, 0, 0, 0, 0x21, crc, sz, sz, len(name), len(extra)) + name + extra
def cdh(name, crc, sz, off, extra):
    return struct.pack('<IHHHHHHIIIHHHHHII', 0x02014b50, 20, 20, 0, 0, 0, 0x21, crc, sz, sz, len(name), len(extra), 0, 0, 0, 0, off) + name + extra
def eocd(n, cdsz, cdoff):
    return struct.pack('<IHHHHIIH', 0x06054b50, 0, 0, n, n, cdsz, cdoff, 0)
l = lfh(name, crc, len(data), extra) + data
cd = cdh(name, crc, len(data), 0, extra)
sys.stdout.buffer.write(l + cd + eocd(1, len(cd), len(l)))
`;
  return execFileSync("python3", ["-c", script], {
    input: JSON.stringify({ name, data: data.toString("base64"), extra: extra.toString("base64") }),
  });
}

/** A minimal, hand-built single-entry Deflated zip using general-purpose
 * flag bit 3 (data descriptor), with NO slack: the central directory's
 * compressed_size is exactly the real deflate stream's own length. The
 * legitimate counterpart to fixtures/zip-cloaking/slack.zip's attack. */
function buildBit3DeflateZip({ name, data }) {
  const script = `
import base64, json, struct, sys, zlib
req = json.loads(sys.stdin.read())
name = req["name"].encode()
raw = base64.b64decode(req["data"])
co = zlib.compressobj(9, zlib.DEFLATED, -15)
comp = co.compress(raw) + co.flush()
crc = zlib.crc32(raw)
def lfh(name, flags, csz, usz):
    return struct.pack('<IHHHHHIIIHH', 0x04034b50, 20, flags, 8, 0, 0x21, 0, csz, usz, len(name), 0) + name
def cdh(name, flags, crc, csz, usz, off):
    return struct.pack('<IHHHHHHIIIHHHHHII', 0x02014b50, 20, 20, flags, 8, 0, 0x21, crc, csz, usz, len(name), 0, 0, 0, 0, 0, off) + name
def eocd(n, cdsz, cdoff):
    return struct.pack('<IHHHHIIH', 0x06054b50, 0, 0, n, n, cdsz, cdoff, 0)
dd = struct.pack('<IIII', 0x08074b50, crc, len(comp), len(raw))  # right after comp -- the entry's own recorded end
l = lfh(name, 0x08, 0, 0) + comp + dd
cd = cdh(name, 0x08, crc, len(comp), len(raw), 0)
sys.stdout.buffer.write(l + cd + eocd(1, len(cd), len(l)))
`;
  return execFileSync("python3", ["-c", script], { input: JSON.stringify({ name, data: data.toString("base64") }) });
}

test("Zip Cloaking vector (slack.zip): deflate slack behind a data-descriptor entry hides a second local header", () => {
  const r = verifyZipHeaders(path.join(FIXTURES, "slack.zip"));
  assert.equal(r.ok, false);
  assert.match(r.error, /E_ZIP_HEADERS_INCONSISTENT/);
  assert.match(r.error, /deflate slack/);
  // Confirm the shape really does fool a central-directory-only reader --
  // the hidden "readme.txt" local header, physically inside a.txt's
  // declared range, is never in zipfile's own namelist().
  const names = JSON.parse(
    execFileSync("python3", ["-c", "import zipfile,sys,json; print(json.dumps(zipfile.ZipFile(sys.argv[1]).namelist()))", path.join(FIXTURES, "slack.zip")]),
  );
  assert.deepEqual(names.sort(), ["a.txt", "launch.sh"]);
});

test("mutation: a bit-3 Deflated entry with no slack (compressed_size matches the real stream) passes", () => {
  // Same shape as the vector -- Deflated, data-descriptor flag set -- with
  // the ONE fact fixed: the central directory's compressed_size is
  // exactly the real deflate stream's length, no slack appended after it.
  const zipPath = writeZip(buildBit3DeflateZip({ name: "a.txt", data: Buffer.from("hello world\n".repeat(20)) }));
  assert.deepEqual(verifyZipHeaders(zipPath), { ok: true });
});

test("Zip Cloaking vector (upath.zip): an Info-ZIP Unicode Path extra field is refused", () => {
  const r = verifyZipHeaders(path.join(FIXTURES, "upath.zip"));
  assert.equal(r.ok, false);
  assert.match(r.error, /E_ZIP_HEADERS_INCONSISTENT/);
  assert.match(r.error, /Unicode Path/);
  // Confirm the shape really does fool a reader that honours the field --
  // Python's own zipfile returns the extra field's path, not the header's.
  const names = JSON.parse(
    execFileSync("python3", ["-c", "import zipfile,sys,json; print(json.dumps(zipfile.ZipFile(sys.argv[1]).namelist()))", path.join(FIXTURES, "upath.zip")]),
  );
  assert.deepEqual(names, ["launch.sh"]);
});

test("mutation: the same entry with no Unicode Path extra field passes", () => {
  // Same name and data as the vector's own header ("notes.txt" / 7 bytes
  // of payload) -- the ONE fact fixed is the absent extra field.
  const zipPath = writeZip(buildStoredZip({ name: "notes.txt", data: Buffer.from("payload") }));
  assert.deepEqual(verifyZipHeaders(zipPath), { ok: true });
});

// ── round 2 (astra-ce sec-probe2): a bit-3 entry's data descriptor must
// sit EXACTLY at its recorded end, the Deflate end-check must drain the
// inflater fully, and it must run on every Deflated entry including a
// ZIP64-sentinel'd one. ───────────────────────────────────────────────

/** A hand-built single-entry Stored zip using bit 3, whose data
 * descriptor sits at `ddOffset` bytes after the entry's own data instead
 * of immediately after it -- 0 is the correct, legitimate placement. */
function buildStoredBit3Zip({ name, data, ddOffset = 0, ddSignature = true }) {
  const script = `
import base64, json, struct, sys, zlib
req = json.loads(sys.stdin.read())
name = req["name"].encode()
data = base64.b64decode(req["data"])
crc = zlib.crc32(data)
def lfh(name, flags):
    return struct.pack('<IHHHHHIIIHH', 0x04034b50, 20, flags, 0, 0, 0x21, 0, 0, 0, len(name), 0) + name
def cdh(name, flags, crc, csz, usz, off):
    return struct.pack('<IHHHHHHIIIHHHHHII', 0x02014b50, 20, 20, flags, 0, 0, 0x21, crc, csz, usz, len(name), 0, 0, 0, 0, 0, off) + name
def eocd(n, cdsz, cdoff):
    return struct.pack('<IHHHHIIH', 0x06054b50, 0, 0, n, n, cdsz, cdoff, 0)
dd = (struct.pack('<I', 0x08074b50) if req["ddSignature"] else b'') + struct.pack('<III', crc, len(data), len(data))
pad = b'\\0' * req["ddOffset"]
l = lfh(name, 0x08) + data + pad + dd
cd = cdh(name, 0x08, crc, len(data), len(data), 0)
sys.stdout.buffer.write(l + cd + eocd(1, len(cd), len(l)))
`;
  return execFileSync("python3", ["-c", script], {
    input: JSON.stringify({ name, data: data.toString("base64"), ddOffset, ddSignature }),
  });
}

test("Zip Cloaking vector (stored-dd.zip): a data descriptor placed past its entry's recorded end is refused", () => {
  const r = verifyZipHeaders(path.join(FIXTURES, "stored-dd.zip"));
  assert.equal(r.ok, false);
  assert.match(r.error, /E_ZIP_HEADERS_INCONSISTENT/);
  assert.match(r.error, /data descriptor/);
  // The real, signed descriptor in this vector describes notes.txt's data
  // PLUS launch.sh's whole header and body -- which is exactly how a
  // streaming reader that trusts it would be fooled into swallowing
  // launch.sh as part of notes.txt instead of reading it separately.
  const names = JSON.parse(
    execFileSync("python3", ["-c", "import zipfile,sys,json; print(json.dumps(zipfile.ZipFile(sys.argv[1]).namelist()))", path.join(FIXTURES, "stored-dd.zip")]),
  );
  assert.deepEqual(names.sort(), ["launch.sh", "notes.txt"]);
});

test("mutation: a data descriptor exactly at the recorded end passes, with or without its optional signature", () => {
  for (const ddSignature of [true, false]) {
    const zipPath = writeZip(buildStoredBit3Zip({ name: "notes.txt", data: Buffer.from("harmless notes\n"), ddOffset: 0, ddSignature }));
    assert.deepEqual(verifyZipHeaders(zipPath), { ok: true }, `ddSignature=${ddSignature}`);
  }
});

test("mutation: a data descriptor even ONE byte past the recorded end is refused", () => {
  const zipPath = writeZip(buildStoredBit3Zip({ name: "notes.txt", data: Buffer.from("harmless notes\n"), ddOffset: 1 }));
  const r = verifyZipHeaders(zipPath);
  assert.equal(r.ok, false);
  assert.match(r.error, /data descriptor/);
});

test("Deflate end-check drains the inflater fully before judging eof (a legitimate ~1 MiB+1 file of zeros passes)", () => {
  const data = Buffer.alloc(1024 * 1024 + 1, 0);
  const zipPath = writeZip(makeZipBytes({ "astra-gi.toml": "x", "zeros.bin": data }));
  assert.deepEqual(verifyZipHeaders(zipPath), { ok: true });
});

/** A hand-built single-entry bit-3 Deflated zip whose CENTRAL DIRECTORY
 * sizes are the ZIP64 sentinel (0xFFFFFFFF), resolved from a ZIP64
 * extended-information extra field (tag 0x0001, uncompressed then
 * compressed size, 8 bytes each) carrying `realUsize`/`realCsize` --
 * which a caller can set wrong, to prove the end-check actually runs on
 * the RESOLVED values rather than skipping the entry. `includeZip64Extra
 * = false` omits the extra field entirely, leaving the sentinel
 * unresolved. */
function buildZip64Bit3DeflateZip({ name, data, realUsize = null, realCsize = null, includeZip64Extra = true }) {
  const script = `
import base64, json, struct, sys, zlib
req = json.loads(sys.stdin.read())
name = req["name"].encode()
raw = base64.b64decode(req["data"])
co = zlib.compressobj(9, zlib.DEFLATED, -15)
comp = co.compress(raw) + co.flush()
crc = zlib.crc32(raw)
real_usize = req["realUsize"] if req["realUsize"] is not None else len(raw)
real_csize = req["realCsize"] if req["realCsize"] is not None else len(comp)
extra = (struct.pack('<HH', 0x0001, 16) + struct.pack('<QQ', real_usize, real_csize)) if req["includeZip64Extra"] else b''
SENTINEL = 0xFFFFFFFF
def lfh(name, flags):
    return struct.pack('<IHHHHHIIIHH', 0x04034b50, 20, flags, 8, 0, 0x21, 0, 0, 0, len(name), 0) + name
def cdh(name, flags, crc, off, extra):
    return struct.pack('<IHHHHHHIIIHHHHHII', 0x02014b50, 20, 20, flags, 8, 0, 0x21, crc, SENTINEL, SENTINEL, len(name), len(extra), 0, 0, 0, 0, off) + name + extra
def eocd(n, cdsz, cdoff):
    return struct.pack('<IHHHHIIH', 0x06054b50, 0, 0, n, n, cdsz, cdoff, 0)
dd = struct.pack('<IIII', 0x08074b50, crc, len(comp), len(raw))  # the DD's own 32-bit fields carry the REAL (small) sizes
l = lfh(name, 0x08) + comp + dd
cd = cdh(name, 0x08, crc, 0, extra)
sys.stdout.buffer.write(l + cd + eocd(1, len(cd), len(l)))
`;
  return execFileSync("python3", ["-c", script], {
    input: JSON.stringify({ name, data: data.toString("base64"), realUsize, realCsize, includeZip64Extra }),
  });
}

test("a ZIP64-sentinel'd entry resolves its real size from the extra field and passes", () => {
  const zipPath = writeZip(buildZip64Bit3DeflateZip({ name: "big.bin", data: Buffer.from("some real content, not actually huge") }));
  assert.deepEqual(verifyZipHeaders(zipPath), { ok: true });
});

test("mutation: a ZIP64 sentinel with no resolving extra field is refused", () => {
  const zipPath = writeZip(buildZip64Bit3DeflateZip({ name: "big.bin", data: Buffer.from("some real content"), includeZip64Extra: false }));
  const r = verifyZipHeaders(zipPath);
  assert.equal(r.ok, false);
  assert.match(r.error, /ZIP64 sentinel/);
});

test("mutation: the end-check still runs on a ZIP64-sentinel'd entry -- a lied-about resolved size is caught", () => {
  // The real deflate stream decodes to the real content's length; the
  // ZIP64 extra claims a different uncompressed size. If ZIP64
  // resolution silently skipped the end-check instead of feeding it the
  // resolved value, this would pass; it must not.
  const data = Buffer.from("some real content");
  const zipPath = writeZip(buildZip64Bit3DeflateZip({ name: "big.bin", data, realUsize: data.length + 1000 }));
  const r = verifyZipHeaders(zipPath);
  assert.equal(r.ok, false);
  assert.match(r.error, /uncompressed size/);
});
