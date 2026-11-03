// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// `gi-probe`, behind an interface (A§5.2 step 5; merged R28, R30).
//
// gi-probe is the launcher's own binary (astra-game-launcher, lane L): it
// links the launcher's manifest.rs and descriptor.rs, so the catalogue and
// every client parse a manifest with one parser. The interface is the
// LAUNCHER's — `src/bin/gi-probe/main.rs` at the tag gi-probe.json pins — and
// this module adapts to it. Production runs the binary; the tests run a fake
// binary that emits the same report (fixtures/gi-probe/fake-gi-probe.mjs), and **a probe
// that does not answer is never a pass**: `W_PROBE_UNAVAILABLE` keeps the
// release out of the catalogue until a probe can look at it.
//
// What ingest asks, and which subcommand of gi-probe 0.5.1 answers it
// (main.rs l.449-543; each subcommand's own file holds its arguments and
// report). The command line is byte identical to 0.5.0's (test/gi-probe-v051.mjs's
// module doc, diffed from source): only what check and validate-descriptor
// JUDGE grew — TOML 1.0, a descriptor's mods (spec §7), content round 3, and
// [integration.link]'s consent digest (gi-probe-v051.mjs's module doc):
//
//   | ingest needs                                   | subcommand (0.5.1)                         | when                                  |
//   |------------------------------------------------|--------------------------------------------|---------------------------------------|
//   | the launcher opens the zip, its hygiene, the   | check <zip> --provenance first-party|      | every release                         |
//   | manifest, the [integration.*] lint, Link       |   community --loaders <loaders[] array>    |                                       |
//   | limits, the descriptor's Pass B and negative   |   (check.rs; main.rs l.475-500)            |                                       |
//   | folders, each game file's loader class, the    |                                            |                                       |
//   | release's content; integration{id, version},   |                                            |                                       |
//   | descriptor.sha256, link.digest                 |                                            |                                       |
//   | the descriptor as a file of its own: §5 lint   | validate-descriptor <astra-gi.toml>        | the manifest carries                  |
//   | and descriptor.sha256, a second reading of the |   [--first-party]                          | [integration.engine] (a foundation    |
//   | digest the entry's descriptor_sha256 carries   |   (descriptor.rs; main.rs l.501-511)       | that owns a code)                     |
//   | may the release reach Astra 0.2.7's users      | compat --zip <zip> --source <id> --tag <t> | first-party, and the manifest id is   |
//   | (R30, canary K4)                               |   --asset astra-gi.zip --sha256 <hex>      | the 0.2.7 source of THIS repository   |
//   |                                                |   [--prerelease]                           | and asset (ASTRA_027_SOURCES); 0.2.7  |
//   |                                                |   (compat.rs; main.rs l.454-474)           | never installs any other release      |
//   | —                                              | capture, pick                              | never                                 |
//
// Not passed: check's --previous and --foundation, and compat's --previous
// and --notes. They take the previous release's or the foundation's ZIP, which
// ingest does not download; code_changed and built_on are computed by the
// catalogue from its own reading of the zip (lib/model.mjs), and compat's
// steps 5-6 say they were skipped.
//
// What gi-probe 0.5.1 does NOT report, and the catalogue reads itself
// (lib/schemas.mjs zipFiles, lib/model.mjs): every file's digest (`files`),
// the game files' paths and digests (`changes.game_files`; the loader class
// is check's `loaders.files[].class`), the Link schemas' own validation
// (`schema_digests`; `link.schemas_validated` is false until link-v1 freezes
// — only the consent digest, `link.digest`, is gi-probe's own since 0.5.1),
// `code_changed` and `built_on`.
//
// Every report is `astra.gi-probe/1` (main.rs l.5-14, l.278-291):
//
//   {"schema": "astra.gi-probe/1", "tool": {"version", "source_tree_sha256"},
//    "subcommand": "check", "verdict": "pass"|"fail", …,
//    "findings": [{"code", "step"?, "field"?, "detail", "params"?}], "notices": [same]}
//
// Exit 0 is no findings, 1 findings, 2 nothing concluded (the report then
// carries `error{code, detail}` and no verdict; main.rs l.562-579). A
// finding refuses (E_PROBE); a notice never does — this covers every finding
// code 0.5.1 added (manifest-invalid/descriptor-invalid{reason=toml-1.0},
// mods-invalid, content round 3's codes) automatically: nothing here keys off
// a specific gi-probe code, so none is ever silently dropped. Anything this
// module cannot read as the pinned build's report of THIS input — exit 2, a
// crash, stdout that is not JSON, another `schema`, another `tool.version` or
// `tool.source_tree_sha256` than gi-probe.json pins, another subcommand, a
// verdict its findings or exit code contradict, a report of other bytes — is
// ProbeUnavailable: nothing was concluded, so the release waits.

import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { promisify } from "node:util";

import { ROOT } from "./vendored.mjs";

const execFileAsync = promisify(execFile);
const HEX64 = /^[0-9a-f]{64}$/;

/** The report's `schema` (main.rs l.49). */
export const REPORT_SCHEMA = "astra.gi-probe/1";

/**
 * Astra 0.2.7's compiled game-integration sources, `{id, repo_id, asset}`:
 * what `compat --source` accepts (compat.rs l.142-150 refuses any other id,
 * exit 2). Copied from astra-game-launcher v0.5.0
 * `src/bin/gi-probe/compat-0.2.7.json` (sha256 81edbf0b…159c), itself frozen
 * from Astra v0.2.7's pins.rs; 0.2.7 is released, so this never changes.
 * test/probe.test.mjs holds it equal to the test suite's own copy.
 */
export const ASTRA_027_SOURCES = Object.freeze([
  { id: "astra.unity", repo_id: 1408152993, asset: "astra-gi.zip" },
  { id: "astra.unity-il2cpp", repo_id: 1408152993, asset: "astra-gi-il2cpp.zip" },
  { id: "astra.unreal", repo_id: 1412685270, asset: "astra-gi.zip" },
  { id: "astra.unreal.gta3-definitive-edition", repo_id: 1412685270, asset: "astra-gi-gta3.zip" },
  { id: "astra.lethal-company", repo_id: 1409552539, asset: "astra-gi.zip" },
  { id: "astra.content-warning", repo_id: 1409552609, asset: "astra-gi.zip" },
  { id: "astra.peak", repo_id: 1409552680, asset: "astra-gi.zip" },
  { id: "astra.repo", repo_id: 1409552749, asset: "astra-gi.zip" },
  { id: "astra.death-stranding", repo_id: 1405082830, asset: "astra-gi-ds1.zip" },
  { id: "astra.death-stranding-2", repo_id: 1405082830, asset: "astra-gi-ds2.zip" },
  { id: "astra.gta-trilogy.gta3", repo_id: 1427110216, asset: "astra-gi-gta3.zip" },
  { id: "astra.gta-trilogy.vicecity", repo_id: 1427110216, asset: "astra-gi-vicecity.zip" },
  { id: "astra.gta-trilogy.sanandreas", repo_id: 1427110216, asset: "astra-gi-sanandreas.zip" },
].map((s) => Object.freeze(s)));

export class ProbeUnavailable extends Error {
  constructor(message) {
    super(message);
    this.name = "ProbeUnavailable";
  }
}

/** gi-probe.json: the build ingest runs. */
export function readPin(root = ROOT) {
  return JSON.parse(fs.readFileSync(path.join(root, "gi-probe.json"), "utf8"));
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

// ── the command lines (main.rs l.449-543) ────────────────────────────────

/** `check <zip> --provenance first-party|community --loaders <file>` (main.rs l.475-500). */
export function checkArgv({ zip, firstParty, loaders }) {
  return ["check", zip, "--provenance", firstParty ? "first-party" : "community", "--loaders", loaders];
}

/** `validate-descriptor <file> [--first-party]` (main.rs l.501-511). */
export function validateDescriptorArgv({ file, firstParty }) {
  return ["validate-descriptor", file, ...(firstParty ? ["--first-party"] : [])];
}

/** `compat --zip --source --tag --asset --sha256 [--prerelease]` (main.rs l.454-474). */
export function compatArgv({ zip, source, tag, asset, sha256, prerelease }) {
  return ["compat", "--zip", zip, "--source", source, "--tag", tag, "--asset", asset, "--sha256", sha256, ...(prerelease ? ["--prerelease"] : [])];
}

/**
 * The 0.2.7 source `compat` judges a release as: its manifest id, when that
 * id is a 0.2.7 source of this repository and this asset. Null otherwise —
 * Astra 0.2.7 installs a source's asset from that source's repository only,
 * so no other release can reach its users.
 */
export function compatSourceFor({ firstParty, manifestId, repoId, asset }) {
  if (!firstParty) return null;
  const row = ASTRA_027_SOURCES.find((s) => s.id === manifestId && s.repo_id === Number(repoId) && s.asset === asset);
  return row ? row.id : null;
}

// ── reading a report ─────────────────────────────────────────────────────

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/** What is wrong with one finding or notice (main.rs l.116-126); null when it reads. */
function findingProblem(f) {
  if (!isObj(f)) return "not an object";
  if (typeof f.code !== "string" || !f.code) return "no code";
  if (typeof f.detail !== "string") return "no detail";
  if (f.step !== undefined && !Number.isInteger(f.step)) return "step is not an integer";
  if (f.field !== undefined && typeof f.field !== "string") return "field is not a string";
  if (f.params !== undefined && (!isObj(f.params) || Object.values(f.params).some((v) => typeof v !== "string"))) return "params is not {string: string}";
  return null;
}

// A descriptor's `sha256` is null on a toml-1.0 finding (0.5.1:
// manifest-invalid/descriptor-invalid{reason=toml-1.0} nulls it, since
// ingest's own tomllib never has a descriptor of such a text either) even
// though `descriptor` itself is still an object (its `codes`/`mods_loaders`,
// whatever Pass B still read, are not thrown away). A PASSING report never
// has this: toml-1.0 is always a finding, so verdict is "fail" whenever
// sha256 is null. Rejecting a non-null `descriptor` for a null `sha256`
// would make `readReport` throw ProbeUnavailable on a report that already
// carries the finding that explains why — turning a terminal refusal into a
// retried wait, and the finding it was waiting to show would never surface.
const descriptorOk = (d, verdict) => isObj(d) && (HEX64.test(String(d.sha256)) || (d.sha256 === null && verdict !== "pass"));

/** Each subcommand's own members the catalogue reads; what is wrong with them. */
const SHAPE = {
  check(r, bad) {
    const i = r.input;
    if (!isObj(i) || i.kind !== "zip" || !HEX64.test(String(i.sha256)) || !["first-party", "community"].includes(i.provenance)) {
      bad.push("input is not {kind: zip, sha256, provenance}");
    }
    if (r.integration !== null && !(isObj(r.integration) && typeof r.integration.id === "string" && typeof r.integration.version === "string")) {
      bad.push("integration is not null or {id, version}");
    }
    if (r.descriptor !== null && !descriptorOk(r.descriptor, r.verdict)) bad.push("descriptor is not null or {sha256}");
    if (r.loaders !== null) {
      if (!isObj(r.loaders) || !Array.isArray(r.loaders.files)) bad.push("loaders is not null or {files: []}");
      else if (r.loaders.files.some((row) => !isObj(row) || typeof row.dest !== "string" || !(row.sha256 === null || HEX64.test(String(row.sha256))) || !["none", "allowlisted", "other"].includes(row.class))) {
        bad.push("a loaders.files row is not {dest, sha256, class: none|allowlisted|other}");
      }
    }
    if (r.verdict === "pass" && (r.integration === null || r.loaders === null)) bad.push("a passing check names no integration or no loaders");
  },
  "validate-descriptor"(r, bad) {
    if (r.descriptor !== null && !descriptorOk(r.descriptor, r.verdict)) bad.push("descriptor is not null or {sha256}");
    if (r.verdict === "pass" && r.descriptor === null) bad.push("a passing validate-descriptor has no descriptor");
  },
  compat(r, bad) {
    if (!isObj(r.source) || typeof r.source.id !== "string") bad.push("source is not {id}");
    if (!isObj(r.input) || !HEX64.test(String(r.input.zip_sha256))) bad.push("input is not {zip_sha256}");
    if (r.integration !== null && !(isObj(r.integration) && typeof r.integration.id === "string" && typeof r.integration.version === "string")) {
      bad.push("integration is not null or {id, version}");
    }
  },
};

/**
 * One run's report, if it is the pinned build's verdict on `subcommand`.
 * @param {string} subcommand
 * @param {{stdout: string, code: number}} run the exit code and stdout
 * @param {{version: string|null, source_tree_sha256?: string|null}} pin gi-probe.json
 * @returns {object} the report
 * @throws {ProbeUnavailable} on anything else
 */
export function readReport(subcommand, { stdout, code }, pin) {
  const no = (why) => new ProbeUnavailable(`gi-probe ${subcommand}: ${why}; nothing is listed until it answers`);
  let r;
  try {
    r = JSON.parse(stdout);
  } catch {
    throw no(`exit ${code}, and stdout is not JSON`);
  }
  if (!isObj(r)) throw no("the report is not an object");
  if (r.schema !== REPORT_SCHEMA) throw no(`the report's schema is ${JSON.stringify(r.schema)}, not ${REPORT_SCHEMA}`);
  if (r.error !== undefined || code === 2) {
    const e = isObj(r.error) ? `${r.error.code}: ${r.error.detail}` : "no error said";
    throw no(`concluded nothing (exit ${code}, ${e})`);
  }
  if (code !== 0 && code !== 1) throw no(`exit ${code}`);
  if (!isObj(r.tool) || typeof r.tool.version !== "string") throw no("the report has no tool.version");
  if (r.tool.version !== pin.version) throw no(`the report is gi-probe ${r.tool.version}'s, and gi-probe.json pins ${pin.version}`);
  if (pin.source_tree_sha256 && r.tool.source_tree_sha256 !== pin.source_tree_sha256) {
    throw no(`the build's source tree is ${r.tool.source_tree_sha256}, and gi-probe.json pins ${pin.source_tree_sha256}`);
  }
  if (r.subcommand !== subcommand) throw no(`the report is ${JSON.stringify(r.subcommand)}'s`);
  const bad = [];
  if (!["pass", "fail"].includes(r.verdict)) bad.push("verdict is not pass or fail");
  // validate-descriptor numbers no steps (descriptor.rs l.576-587)
  for (const key of ["findings", "notices", ...(subcommand === "validate-descriptor" ? [] : ["steps"])]) {
    if (!Array.isArray(r[key])) bad.push(`${key} is not an array`);
  }
  for (const key of ["findings", "notices"]) {
    for (const f of Array.isArray(r[key]) ? r[key] : []) {
      const p = findingProblem(f);
      if (p) bad.push(`a ${key.slice(0, -1)} is not {code, detail}: ${p}`);
    }
  }
  if (Array.isArray(r.findings) && (r.verdict === "pass") !== (r.findings.length === 0)) bad.push(`verdict ${r.verdict} with ${r.findings.length} finding(s)`);
  if ((code === 0) !== (r.verdict === "pass")) bad.push(`verdict ${r.verdict} with exit ${code}`);
  SHAPE[subcommand]?.(r, bad);
  if (bad.length) throw no(`the report cannot be read: ${bad.join("; ")}`);
  return r;
}

/**
 * The production probe: runs the binary, returns a report readReport
 * accepted. Throws ProbeUnavailable when there is no pinned binary to run.
 * @param {{env?: object, pin?: {version: string|null, source_tree_sha256?: string|null}}} o
 */
export function binaryProbe({ env = process.env, pin = readPin() } = {}) {
  return {
    name: "gi-probe",
    pin,
    async run(subcommand, argv) {
      if (!pin.version) throw new ProbeUnavailable("gi-probe.json pins no gi-probe build; nothing is listed without it");
      const bin = locateProbe(env);
      if (!bin) throw new ProbeUnavailable(`gi-probe ${pin.version} is not installed; nothing is listed without it`);
      if (argv[0] !== subcommand) throw new Error(`probe.run(${subcommand}) given the command line of ${argv[0]}`);
      let stdout;
      let code = 0;
      try {
        ({ stdout } = await execFileAsync(bin, argv, { env, maxBuffer: 64 * 1024 * 1024, timeout: 300_000 }));
      } catch (e) {
        // exit 1 (findings) and 2 (nothing concluded) both print a report;
        // a signal, a timeout or a binary that never started print none
        if (!Number.isInteger(e.code)) throw new ProbeUnavailable(`gi-probe ${subcommand} did not run: ${String(e.message).split("\n")[0]}`);
        code = e.code;
        stdout = e.stdout ?? "";
      }
      return readReport(subcommand, { stdout, code }, pin);
    },
  };
}

/**
 * Every subcommand a release needs (the table above), each report checked
 * against the input it was asked about.
 * @param {{probe: {run: Function}, zip: string, zipSha256: string, firstParty: boolean, loaders: string,
 *          manifestFile?: string|null, compat?: {source: string, tag: string, asset: string, prerelease: boolean}|null}} o
 *   manifestFile: astra-gi.toml as shipped, when the manifest carries [integration.engine]
 * @returns {Promise<{check: object, "validate-descriptor"?: object, compat?: object}>}
 * @throws {ProbeUnavailable}
 */
export async function probeRelease({ probe, zip, zipSha256, firstParty, loaders, manifestFile = null, compat = null }) {
  const reports = {};
  const check = await probe.run("check", checkArgv({ zip, firstParty, loaders }));
  if (check.input.sha256 !== zipSha256) throw new ProbeUnavailable(`gi-probe check read bytes hashing to ${check.input.sha256}, not the release's ${zipSha256}`);
  if (check.input.provenance !== (firstParty ? "first-party" : "community")) throw new ProbeUnavailable(`gi-probe check judged the release as ${check.input.provenance}`);
  reports.check = check;
  if (manifestFile) {
    reports["validate-descriptor"] = await probe.run("validate-descriptor", validateDescriptorArgv({ file: manifestFile, firstParty }));
  }
  if (compat) {
    const r = await probe.run("compat", compatArgv({ zip, source: compat.source, tag: compat.tag, asset: compat.asset, sha256: zipSha256, prerelease: compat.prerelease }));
    if (r.source.id !== compat.source || r.input.zip_sha256 !== zipSha256) throw new ProbeUnavailable(`gi-probe compat judged ${r.source.id} over ${r.input.zip_sha256}, not ${compat.source} over the release`);
    reports.compat = r;
  }
  return reports;
}
