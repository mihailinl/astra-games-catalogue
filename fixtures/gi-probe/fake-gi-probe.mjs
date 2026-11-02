#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// A FAKE gi-probe 0.5.0, for the tests: what lib/probe.mjs runs in place of
// the real binary, which no test and no part of this work ever executes.
//
// It reads its command line as main.rs does (test/gi-probe-v050.mjs
// parseLikeMain, from main.rs l.397-540) and answers a wrong one as main.rs
// does — exit 2, `{schema, tool, subcommand, error{code: "usage", detail}}`
// on stdout (main.rs l.559-576). A right one gets a report of exactly the
// keys 0.5.0 writes, in its order (main.rs l.275-340):
//
//   check (check.rs l.553-590; keys as the launcher's author read them off
//   the released musl build): schema, tool{version, source_tree_sha256},
//   subcommand, verdict, input{file, kind, sha256, provenance, foundation,
//   previous, loaders}, spec{repo, sha, section}, integration{id, name,
//   version, repo, engine, sdk}, descriptor{sha256, codes}, negative_folders,
//   link{files, schemas_validated, why}, built_on, code_changed, steps,
//   notices, content{content_files, parts, classes}, loaders{allowlist,
//   allowlist_entries, hijack_names, files[{dest, sha256, class,
//   allowlisted_as}]}, findings[{code, step, field?, detail, params?}];
//   validate-descriptor (descriptor.rs l.546-562): schema, tool, subcommand,
//   verdict, input{file, kind, first_party}, spec, descriptor, negative_folders,
//   notices, findings;
//   compat (compat.rs l.307-334): schema, tool, subcommand, verdict,
//   input{zip, zip_sha256, digest_checked, tag, asset, prerelease, previous,
//   notes}, source{id, repo, repo_id, tag_prefix, asset, target},
//   against{astra, launcher}, integration{id, version, repo}, steps, notices,
//   findings.
//
// By default it agrees with the release: it reads the zip itself (Python's
// zipfile and tomllib, not the catalogue's code) and classifies each
// [[game_files]] entry as check.rs l.469-505 does. A test makes it disagree,
// refuse or misbehave through a scenario file ($FAKE_GI_PROBE_SCENARIO):
//
//   { "tool": {…},                                 // every report's tool
//     "<subcommand>": {
//       "findings": [{code, step, field?, detail, params?}],   // → verdict fail, exit 1
//       "notices": [...],
//       "integration": {…}|null, "descriptor_sha256": "<hex>"|null, "loaders_files": [...],
//       "patch": {…},                              // merged over the finished report
//       "exit": N, "stdout": "<raw>" } }          // exit code; raw stdout instead of a report
//
// Every command line is appended to $FAKE_GI_PROBE_LOG, one JSON array a line.

import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { jcs } from "../../lib/vendor/astra-registry/tools/lib/canonical.mjs";
import {
  CHECK_STEPS, COMPAT_027, COMPAT_STEPS, HIJACK_NAMES, KEY_ORDER, NEGATIVE_FOLDERS, REPORT_SCHEMA, SPEC_SHA, TOOL, parseLikeMain,
} from "../../test/gi-probe-v050.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
if (process.env.FAKE_GI_PROBE_LOG) fs.appendFileSync(process.env.FAKE_GI_PROBE_LOG, `${JSON.stringify(argv)}\n`);
const scenario = process.env.FAKE_GI_PROBE_SCENARIO ? JSON.parse(fs.readFileSync(process.env.FAKE_GI_PROBE_SCENARIO, "utf8")) : {};
const tool = { ...TOOL, ...(scenario.tool ?? {}) };
const sha256 = (b) => crypto.createHash("sha256").update(b).digest("hex");

/** main.rs l.316-340: KEY_ORDER first, the rest sorted, `findings` last. */
function ordered(r) {
  const rank = (k) => (k === "findings" ? Infinity : KEY_ORDER.includes(k) ? KEY_ORDER.indexOf(k) : KEY_ORDER.length);
  const keys = Object.keys(r).sort((a, b) => rank(a) - rank(b) || (a < b ? -1 : a > b ? 1 : 0));
  return Object.fromEntries(keys.map((k) => [k, r[k]]));
}

function emit(report, code) {
  process.stdout.write(`${JSON.stringify(ordered(report), null, 2)}\n`);
  process.exit(code);
}

/** main.rs l.561-576: nothing concluded. */
function fatal(code, detail) {
  process.stderr.write(`gi-probe: ${code}: ${detail}\n`);
  emit({ schema: REPORT_SCHEMA, tool, subcommand: argv[0] ?? "", error: { code, detail } }, 2);
}

/** main.rs l.275-288, with the scenario's findings, notices, patch and exit. */
function finish(subcommand, rest, findings, sc) {
  const report = { schema: REPORT_SCHEMA, tool: sc.tool ? { ...tool, ...sc.tool } : tool, subcommand, verdict: findings.length ? "fail" : "pass", ...rest, findings };
  Object.assign(report, sc.patch ?? {});
  emit(report, sc.exit ?? (findings.length ? 1 : 0));
}

/** Probe::close / skip (main.rs l.211-241): each step pass, fail, notice or skipped. */
function steps(names, findings, notices, skipped, extra = {}) {
  return names.map((check, i) => {
    const step = i + 1;
    if (skipped[step]) return { step, check, status: "skipped", why: skipped[step] };
    const status = findings.some((f) => f.step === step) ? "fail" : notices.some((n) => n.step === step) ? "notice" : "pass";
    return { step, check, status, ...(extra[step] ?? {}) };
  });
}

/** The zip as Python reads it: every file's digest, and astra-gi.toml parsed. */
function readZip(file) {
  const py = [
    "import hashlib, json, sys, tomllib, zipfile",
    "out = {'digests': {}, 'manifest': None, 'error': None}",
    "try:",
    "    with zipfile.ZipFile(sys.argv[1]) as z:",
    "        text = None",
    "        for i in z.infolist():",
    "            if i.is_dir(): continue",
    "            data = z.read(i)",
    "            out['digests'][i.filename.replace(chr(92), '/')] = hashlib.sha256(data).hexdigest()",
    "            if i.filename == 'astra-gi.toml': text = data.decode('utf-8')",
    "    if text is None: out['error'] = 'the zip holds no astra-gi.toml'",
    "    else: out['manifest'] = tomllib.loads(text)",
    "except Exception as e:",
    "    out['error'] = str(e)",
    "print(json.dumps(out, default=str))",
  ].join("\n");
  return JSON.parse(execFileSync(process.env.PYTHON ?? "python3", ["-c", py, file]).toString("utf8"));
}

function readToml(file) {
  const py = "import json, sys, tomllib\nprint(json.dumps(tomllib.loads(open(sys.argv[1], encoding='utf-8').read()), default=str))";
  return JSON.parse(execFileSync(process.env.PYTHON ?? "python3", ["-c", py, file]).toString("utf8"));
}

function readFile(file) {
  try {
    return fs.readFileSync(file);
  } catch (e) {
    return fatal("io", `${file}: ${e.message}`);
  }
}

/** descriptor.rs l.494-500. */
function descriptorSummary(d, sc) {
  if (Object.hasOwn(sc, "descriptor_sha256")) return sc.descriptor_sha256 === null ? null : { sha256: sc.descriptor_sha256, codes: {} };
  if (!d) return null;
  return { sha256: sha256(Buffer.from(jcs(d), "utf8")), codes: Object.fromEntries(Object.entries(d.engine?.codes ?? {}).map(([c, v]) => [c, v?.name ?? v])) };
}

const negativeFolders = (descriptor) => (descriptor ? NEGATIVE_FOLDERS.map((folder) => ({ folder, claimed: false, engine: null, places: [] })) : []);

/** check.rs l.120-135: a JSON array of {name, sha256, default_enabled}, nothing else. */
function readLoaders(file) {
  let list;
  try {
    list = JSON.parse(readFile(file).toString("utf8"));
  } catch (e) {
    return fatal("io", `${file}: loaders[]: ${e.message}`);
  }
  const keys = ["default_enabled", "name", "sha256"];
  if (!Array.isArray(list)) return fatal("io", `${file}: loaders[]: invalid type: map, expected a sequence`);
  for (const l of list) {
    if (!l || typeof l !== "object" || Object.keys(l).sort().join() !== keys.join() || typeof l.name !== "string" || typeof l.default_enabled !== "boolean" || typeof l.sha256 !== "string") {
      return fatal("io", `${file}: loaders[]: not {name, sha256, default_enabled}`);
    }
    if (!/^[0-9a-fA-F]{64}$/.test(l.sha256)) return fatal("io", `${file}: loaders[] ${JSON.stringify(l.name)}: sha256 is not 64 hex digits`);
  }
  return list;
}

function check(p, sc) {
  const file = p.positional[0];
  const bytes = readFile(file);
  const isZip = bytes.subarray(0, 2).toString("latin1") === "PK";
  const provenance = p.opts.provenance ?? "community";
  const allowlist = p.opts.loaders ? readLoaders(p.opts.loaders) : null;
  const findings = [...(sc.findings ?? [])];
  const notices = [...(sc.notices ?? [])];
  const z = isZip ? readZip(file) : { digests: {}, manifest: readToml(file), error: null };
  if (z.error) findings.push({ code: "zip-invalid", step: 1, detail: z.error });
  const m = z.manifest;
  const integration = Object.hasOwn(sc, "integration") ? sc.integration : m ? {
    id: m.integration?.id ?? null, name: m.integration?.name ?? null, version: m.integration?.version ?? null,
    repo: m.integration?.repo ?? null, engine: m.target?.engine ?? null, sdk: m.integration?.sdk ?? null,
  } : null;
  const d = m?.integration?.engine ?? null;
  const descriptor = descriptorSummary(d, sc);
  const l = m?.integration?.link ?? null;
  const linkFiles = l ? [l.skill, ...(l.tools ?? []).map((t) => t.params), ...(l.triggers ?? []).map((t) => t.data), ...(l.events ?? []).map((e) => e.data)].filter((x) => typeof x === "string") : [];
  if (linkFiles.length) notices.push({ code: "link-schemas-unvalidated", step: 3, detail: "the params/data schemas are not yet held to link-v1.md §6's restricted profile: that waits for link-v1 to freeze" });
  // check.rs l.443-515
  const proxies = (m?.integration?.loader?.proxies ?? []).map((x) => String(x).toLowerCase());
  const rows = Object.hasOwn(sc, "loaders_files") ? sc.loaders_files : (m?.game_files ?? []).map((g) => {
    const dest = String(g.to);
    const digest = z.digests[String(g.from)] ?? null;
    const name = dest.split("/").pop().toLowerCase();
    const listed = (allowlist ?? []).find((a) => digest && a.sha256.toLowerCase() === digest);
    const cls = !HIJACK_NAMES.includes(name) && !proxies.includes(name) ? "none" : listed && !listed.default_enabled ? "allowlisted" : "other";
    if (cls === "other") notices.push({ code: "loader-other", step: 7, field: dest, detail: `${dest} is a name mod loaders hijack-load by, and no loader the allowlist knows as off by default: it runs every time the game starts, even without Astra` });
    return { dest, sha256: digest, class: cls, allowlisted_as: cls === "allowlisted" ? listed.name : null };
  });
  const claim = m?.integration?.foundation ?? null;
  const opened = isZip && !z.error;
  finish("check", {
    input: { file, kind: isZip ? "zip" : "manifest", sha256: sha256(bytes), provenance, foundation: p.opts.foundation ?? null, previous: p.opts.previous ?? null, loaders: p.opts.loaders ?? null },
    spec: { repo: "mihailinl/AstraPlugins", sha: SPEC_SHA, section: "spec/games/manifest.md §4" },
    integration,
    descriptor,
    negative_folders: negativeFolders(descriptor),
    link: l ? { files: linkFiles.length, schemas_validated: false, why: "validating params/data schemas against link-v1.md §6's restricted profile waits for link-v1 to freeze" } : null,
    built_on: claim ? { id: claim.id, version: claim.version, verified: false, claimed: claim } : null,
    code_changed: null,
    loaders: m ? { allowlist: p.opts.loaders ?? null, allowlist_entries: allowlist ? allowlist.length : null, hijack_names: HIJACK_NAMES, files: rows } : null,
    content: opened ? { content_files: [], parts: [], classes: {} } : null,
    steps: steps(CHECK_STEPS, findings, notices, {
      ...(m ? {} : { 2: "the zip holds no readable astra-gi.toml" }),
      ...(linkFiles.length ? {} : { 3: "no [integration.link] files" }),
      ...(descriptor ? {} : { 4: "no [integration.engine] the launcher reads" }),
      ...(p.opts.foundation ? {} : { 5: "no --foundation" }),
      ...(p.opts.previous ? {} : { 6: "no --previous" }),
    }, { 1: { zip: isZip, zip_checks: isZip ? "made" : "not made: a manifest, not a zip" } }),
    notices,
  }, findings, sc);
}

function validateDescriptor(p, sc) {
  const file = p.positional[0];
  const text = readFile(file).toString("utf8");
  const findings = [...(sc.findings ?? [])];
  let kind = "descriptor-toml";
  let d = null;
  if (text.trimStart().startsWith("{")) {
    kind = "descriptor-json";
    d = JSON.parse(text);
  } else {
    const t = readToml(file);
    if (Number.isInteger(t.schema)) {
      kind = "manifest-integration-engine";
      d = t.integration?.engine ?? null;
      if (!d) findings.push({ code: "descriptor-invalid", step: 1, field: "integration.engine", detail: "not an astra.engine/1 descriptor", params: { field: "integration.engine", detail: "a manifest without [integration.engine]" } });
    } else {
      d = t;
    }
  }
  const descriptor = descriptorSummary(d, sc);
  finish("validate-descriptor", {
    input: { file, kind, first_party: p.flags.includes("first-party") },
    spec: { repo: "mihailinl/AstraPlugins", sha: SPEC_SHA, section: "spec/games/engine-descriptor-v1.md §5" },
    descriptor,
    negative_folders: negativeFolders(descriptor),
    notices: sc.notices ?? [],
  }, findings, sc);
}

function compat(p, sc) {
  const source = COMPAT_027.sources.find((s) => s.id === p.opts.source);
  if (!source) fatal("usage", `--source ${JSON.stringify(p.opts.source)} is none of Astra 0.2.7's sources: ${COMPAT_027.sources.map((s) => s.id).join(", ")}`);
  const bytes = readFile(p.opts.zip);
  const z = readZip(p.opts.zip);
  const findings = [...(sc.findings ?? [])];
  if (z.error) findings.push({ code: "zip-invalid", step: 1, detail: z.error });
  const m = z.manifest;
  const integration = Object.hasOwn(sc, "integration") ? sc.integration : m ? { id: m.integration?.id ?? null, version: m.integration?.version ?? null, repo: m.integration?.repo ?? null } : null;
  const notices = sc.notices ?? [];
  finish("compat", {
    input: {
      zip: p.opts.zip, zip_sha256: sha256(bytes), digest_checked: p.opts.sha256 !== undefined, tag: p.opts.tag,
      asset: p.opts.asset ?? path.basename(p.opts.zip), prerelease: p.flags.includes("prerelease"), previous: p.opts.previous ?? null, notes: p.opts.notes ?? null,
    },
    source,
    against: COMPAT_027.against,
    integration,
    steps: steps(COMPAT_STEPS, findings, notices, p.opts.previous ? {} : { 5: "no --previous release", 6: "no --previous release" }),
    notices,
  }, findings, sc);
}

// main.rs l.542-558
if (argv[0] === "--version") {
  process.stdout.write(`gi-probe ${tool.version} (source tree sha256 ${tool.source_tree_sha256})\n`);
  process.exit(0);
}
const parsed = parseLikeMain(argv);
if (!parsed.ok) fatal("usage", parsed.detail);
const sc = scenario[parsed.sub] ?? {};
if (sc.stdout !== undefined) {
  process.stdout.write(sc.stdout);
  process.exit(sc.exit ?? 0);
}
if (parsed.sub === "check") check(parsed, sc);
else if (parsed.sub === "validate-descriptor") validateDescriptor(parsed, sc);
else if (parsed.sub === "compat") compat(parsed, sc);
else fatal("io", `${parsed.sub}: the fake gi-probe answers check, validate-descriptor and compat only (${HERE})`);
