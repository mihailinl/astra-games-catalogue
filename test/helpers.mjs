// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Test doubles for every dependency ingest reaches outside the process
// through, built from fixtures/staging/. Keys made here are THROWAWAY Ed25519
// pairs generated per test run; nothing reads or writes real key material.

import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const STAGING = path.join(ROOT, "fixtures", "staging");
export const fixture = (f) => JSON.parse(fs.readFileSync(path.join(STAGING, f), "utf8"));
export const fixtureText = (f) => fs.readFileSync(path.join(STAGING, f), "utf8");

export function tmpdir(prefix = "agc-") {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

/** A deterministic zip (fixed timestamps) of {name: text} via Python's zipfile. */
export function makeZip(files) {
  const script = [
    "import sys, json, zipfile, io",
    "files = json.load(sys.stdin)",
    "buf = io.BytesIO()",
    "with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:",
    "    for name in sorted(files):",
    "        zi = zipfile.ZipInfo(name, date_time=(2026, 10, 31, 0, 0, 0))",
    "        zi.compress_type = zipfile.ZIP_DEFLATED",
    "        z.writestr(zi, files[name])",
    "sys.stdout.buffer.write(buf.getvalue())",
  ].join("\n");
  return execFileSync("python3", ["-c", script], { input: JSON.stringify(files) });
}

/**
 * A deterministic zip whose entries may be binary (base64-round-tripped
 * through the same Python zipfile core as `makeZip`, which only takes text).
 * @param {Record<string, Buffer|string>} files
 */
export function makeZipBytes(files) {
  const payload = {};
  for (const [name, data] of Object.entries(files)) {
    payload[name] = (Buffer.isBuffer(data) ? data : Buffer.from(data, "utf8")).toString("base64");
  }
  const script = [
    "import sys, json, zipfile, io, base64",
    "files = json.load(sys.stdin)",
    "buf = io.BytesIO()",
    "with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:",
    "    for name in sorted(files):",
    "        zi = zipfile.ZipInfo(name, date_time=(2026, 10, 31, 0, 0, 0))",
    "        zi.compress_type = zipfile.ZIP_DEFLATED",
    "        z.writestr(zi, base64.b64decode(files[name]))",
    "sys.stdout.buffer.write(buf.getvalue())",
  ].join("\n");
  return execFileSync("python3", ["-c", script], { input: JSON.stringify(payload) });
}

/** A minimal GLB: the 12-byte header plus one JSON-typed chunk, no BIN chunk. */
export function makeGlb(obj) {
  const bodyText = Buffer.from(JSON.stringify(obj), "utf8");
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

export const sha256 = (b) => crypto.createHash("sha256").update(b).digest("hex");

/**
 * A fake GitHub for one staging repository.
 * @param {{zip: Buffer, repo?: object, release?: object, ownerFile?: string|null, licence?: boolean, reachable?: boolean, refs?: object}} o
 */
export function fakeGithub(o) {
  const repo = o.repo ?? fixture("repo.json");
  const digest = sha256(o.zip);
  const release = structuredClone(o.release ?? fixture("release.json"));
  for (const a of release.assets) {
    if (a.digest === "sha256:__SHA256__") a.digest = `sha256:${digest}`;
    if (!a.size) a.size = o.zip.length;
  }
  const refs = o.refs ?? fixture("refs.json");
  const calls = [];
  return {
    calls,
    async repoById(id) {
      calls.push(["repoById", id]);
      if (Number(id) !== repo.id) return { status: "not_found", reason: "HTTP 404" };
      return { status: "found", repo: { id: repo.id, full_name: repo.full_name, owner_id: repo.owner.id, private: repo.private, default_branch: repo.default_branch } };
    },
    async releaseByTag(id, tag) {
      calls.push(["releaseByTag", id, tag]);
      return tag === release.tag_name ? { status: "found", release } : { status: "not_found", reason: "HTTP 404" };
    },
    async tagCommit(id, tag) {
      calls.push(["tagCommit", id, tag]);
      if (tag !== release.tag_name) return { status: "not_found" };
      let obj = refs.ref.object;
      if (obj.type === "tag") obj = refs.tag_object.object;
      return { status: "found", commit: obj.sha };
    },
    async onDefaultBranch() {
      return { status: "found", reachable: o.reachable ?? true };
    },
    async fileAtCommit(id, sha, p) {
      calls.push(["fileAtCommit", id, sha, p]);
      const text = o.ownerFile === undefined ? fixtureText("astra-gi-owner") : o.ownerFile;
      return text === null ? { status: "not_found", reason: "HTTP 404" } : { status: "found", content: text };
    },
    async licenseAt() {
      return o.licence === false ? { status: "not_found", reason: "HTTP 404" } : { status: "found", spdx_id: "MIT" };
    },
    async download(url) {
      calls.push(["download", url]);
      return o.zip;
    },
  };
}

/** A fake `gh attestation verify`: the staging certificate, with overrides. */
export function fakeGh({ sha, certificate = {}, fail = null }) {
  const calls = [];
  const run = async (args) => {
    calls.push(args);
    if (fail) {
      const e = new Error("Command failed: gh attestation verify");
      Object.assign(e, fail);
      throw e;
    }
    const doc = JSON.parse(JSON.stringify(fixture("attestation.json")).replaceAll("__SHA256__", sha));
    Object.assign(doc[0].verificationResult.signature.certificate, certificate);
    return { stdout: JSON.stringify(doc) };
  };
  run.calls = calls;
  return run;
}

export function fakeSteam() {
  const data = fixture("steam-appdetails.json");
  return {
    async appDetails(appid) {
      const row = data[String(appid)];
      if (!row) return null;
      return row.success ? row.data : null;
    },
  };
}

/** A gi-probe stub that agrees with the manifest it is given. */
export function stubProbe({ manifestId, version, descriptorSha = null, files = {}, findings = [], gameFiles = [], extra = {} }) {
  const calls = [];
  return {
    calls,
    async ingest(args) {
      calls.push(args);
      return {
        probe: "gi-probe-stub",
        version: "0.0.0-test",
        findings,
        manifest_id: manifestId,
        manifest_version: version,
        descriptor_sha256: descriptorSha,
        game_files: gameFiles,
        files: { "BepInEx/plugins/Staging.dll": "d".repeat(64), ...files },
        link: null,
        schema_digests: {},
        code_changed: null,
        compat: null,
        ...extra,
      };
    },
  };
}

/** A throwaway Ed25519 pair as the signing environment holds it: base64 of the raw 32-byte seed. */
export function throwawayKey() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
  const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  return { seedB64: seed.toString("base64"), publicB64: pub.toString("base64") };
}
