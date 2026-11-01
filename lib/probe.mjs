// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// `gi-probe`, behind an interface (A§5.2 step 5; merged R28).
//
// gi-probe is the launcher's own binary (astra-game-launcher 0.5.0, lane L):
// it links the launcher's manifest.rs and descriptor.rs, so the catalogue and
// every client parse a manifest with one parser. 0.5.0 is not released yet,
// so this module is the seam: production runs the binary, the tests hand in
// a stub, and **a missing binary is never a pass** — `W_PROBE_UNAVAILABLE`
// keeps the release out of the catalogue until a probe can look at it.
//
// The contract asked of the binary (lane L implements it; this is the shape
// the catalogue reads, and `checkReport` refuses anything else):
//
//   gi-probe ingest --zip <file> --loaders <loaders.json> [--previous <zip>]
//                   [--first-party] [--catalogue <index-body.json>] --json
//
//   {
//     "probe": "gi-probe", "version": "0.5.0",
//     "findings": [ { "code": "zip-traversal", "level": "error"|"warning"|"flag", "message": "…" } ],
//     "manifest_id": "someone.peak-astra", "manifest_version": "1.2.0",
//     "descriptor_sha256": "<hex>"|null,           // sha256(JCS(parsed)), engine-descriptor-v1.md §1
//     "game_files": [ { "path", "sha256", "loader": "none"|"allowlisted"|"other" } ],
//     "files": { "<path in zip>": "<sha256>" },      // every file, for built_on and code_changed
//     "link": { context, shares_other_players, skill_digest, digest } | null,
//     "schema_digests": { "<path>": "<sha256>" },
//     "code_changed": true|false|null,               // null when no --previous
//     "compat": { "ok": true, "findings": [] } | null // --first-party: B C2's six steps + pick (R30)
//   }
//
// An `error` finding refuses (E_PROBE). A `flag` is shown to moderators. A
// report the catalogue cannot read is a refusal too, never a pass.

import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const HEX64 = /^[0-9a-f]{64}$/;

export class ProbeUnavailable extends Error {
  constructor(message) {
    super(message);
    this.name = "ProbeUnavailable";
  }
}

/** Where the binary is: $GI_PROBE, else `gi-probe` on PATH. Null when neither exists. */
export function locateProbe(env = process.env) {
  if (env.GI_PROBE) return fs.existsSync(env.GI_PROBE) ? env.GI_PROBE : null;
  for (const dir of String(env.PATH ?? "").split(path.delimiter)) {
    if (!dir) continue;
    const p = path.join(dir, process.platform === "win32" ? "gi-probe.exe" : "gi-probe");
    if (fs.existsSync(p)) return p;
  }
  return null;
}

/** The production probe. Throws ProbeUnavailable when there is no binary to run. */
export function binaryProbe({ env = process.env } = {}) {
  return {
    name: "gi-probe",
    async ingest({ zip, loaders, previous = null, firstParty = false, catalogue = null }) {
      const bin = locateProbe(env);
      if (!bin) {
        throw new ProbeUnavailable("gi-probe is not installed (astra-game-launcher 0.5.0); nothing is listed without it");
      }
      const args = ["ingest", "--zip", zip, "--loaders", loaders, "--json"];
      if (previous) args.push("--previous", previous);
      if (firstParty) args.push("--first-party");
      if (catalogue) args.push("--catalogue", catalogue);
      let stdout;
      try {
        ({ stdout } = await execFileAsync(bin, args, { maxBuffer: 64 * 1024 * 1024, timeout: 300_000 }));
      } catch (e) {
        // gi-probe exits non-zero with a report when it refuses; anything
        // without a parseable report is the probe not running.
        if (e.stdout) stdout = e.stdout;
        else throw new ProbeUnavailable(`gi-probe did not run: ${String(e.message).split("\n")[0]}`);
      }
      try {
        return JSON.parse(stdout);
      } catch {
        throw new ProbeUnavailable("gi-probe printed something that is not JSON");
      }
    },
  };
}

/** @returns {string[]} what is wrong with a report's shape; empty when it can be read */
export function checkReport(r) {
  const bad = [];
  if (!r || typeof r !== "object") return ["the report is not an object"];
  if (!Array.isArray(r.findings)) bad.push("findings is not an array");
  else {
    for (const f of r.findings) {
      if (!f || typeof f.code !== "string" || !["error", "warning", "flag"].includes(f.level)) {
        bad.push(`a finding is not {code, level: error|warning|flag}: ${JSON.stringify(f)}`);
      }
    }
  }
  if (typeof r.manifest_id !== "string") bad.push("manifest_id is missing");
  if (typeof r.manifest_version !== "string") bad.push("manifest_version is missing");
  if (r.descriptor_sha256 !== null && !HEX64.test(String(r.descriptor_sha256))) bad.push("descriptor_sha256 is not null or 64 hex");
  if (!Array.isArray(r.game_files)) bad.push("game_files is not an array");
  else {
    for (const g of r.game_files) {
      if (!g || typeof g.path !== "string" || !HEX64.test(String(g.sha256)) || !["none", "allowlisted", "other"].includes(g.loader)) {
        bad.push(`a game_files row is not {path, sha256, loader}: ${JSON.stringify(g)}`);
      }
    }
  }
  if (!r.files || typeof r.files !== "object" || Array.isArray(r.files)) bad.push("files is not an object");
  else if (Object.values(r.files).some((d) => !HEX64.test(String(d)))) bad.push("files holds a digest that is not 64 hex");
  if (r.link !== null && (typeof r.link !== "object" || Array.isArray(r.link))) bad.push("link is not an object or null");
  if (!r.schema_digests || typeof r.schema_digests !== "object") bad.push("schema_digests is not an object");
  if (r.code_changed !== null && typeof r.code_changed !== "boolean") bad.push("code_changed is not a boolean or null");
  if (r.compat !== null && r.compat !== undefined && (typeof r.compat !== "object" || typeof r.compat.ok !== "boolean")) {
    bad.push("compat is not {ok, findings} or null");
  }
  return bad;
}
