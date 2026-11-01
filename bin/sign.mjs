#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The signing job's entry point (sign.yml; resign.yml runs bin/resign.mjs).
// Runs in the publish-games environment, the only place the signing secrets
// exist; reads them from the environment, never from arguments.
//
//   node bin/sign.mjs --data <data-branch checkout> --trust <trust.json>
//                     [--candidates <dir>] [--acts <acts.json>] [--health <health.json>] [--report <file>]
//
//   --trust        the published, root-signed trust.json (astra-registry
//                  registry/v1/trust.json); its `kind_keys` say which two keys
//                  may sign the games documents (lib/trust.mjs)
//   --candidates   the Ingest run's candidates: <dir>/*.json, or one
//                  <dir>/games-candidate-<lease>/candidate.json per lease
//   --acts         a JSON list of astra.games.act/1, oldest first, as sign.yml's
//                  work job pulled them (GET bot/games/work); absent = none
//   --health       the plugins service's counts, a JSON object or null
//   --report       where to write the run's report for the report job
//
// Nothing a service or a dispatcher wrote is read from an event or
// interpolated into a shell: the work job wrote it to files. Prints a
// one-line JSON report and writes `issued_at`, `key_id` and `refused_acts`
// to $GITHUB_OUTPUT (the report job fails the run on refused acts AFTER the
// rest landed and was reported); exits 1 when the run itself was refused.

import fs from "node:fs";
import path from "node:path";

import { runSign } from "../lib/pipeline.mjs";
import { writeJson } from "../lib/state.mjs";
import { ROOT } from "../lib/vendored.mjs";

const args = process.argv.slice(2);
const opt = (n) => (args.indexOf(n) >= 0 ? args[args.indexOf(n) + 1] : null);

/** Candidate files: <dir>/*.json, and <dir>/<artifact>/candidate.json (download-artifact by pattern). */
export function readCandidates(dir) {
  if (!dir || !fs.existsSync(dir)) return [];
  const files = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    if (e.isFile() && e.name.endsWith(".json")) files.push(path.join(dir, e.name));
    else if (e.isDirectory() && fs.existsSync(path.join(dir, e.name, "candidate.json"))) files.push(path.join(dir, e.name, "candidate.json"));
  }
  return files.map((f) => JSON.parse(fs.readFileSync(f, "utf8")));
}

/** The work job's files: acts a list (absent = none), health an object or null (absent = unchanged). */
export function readWorkFiles({ actsFile, healthFile }) {
  const acts = actsFile && fs.existsSync(actsFile) ? JSON.parse(fs.readFileSync(actsFile, "utf8")) : [];
  if (!Array.isArray(acts)) throw new Error(`${actsFile} is not a list of acts`);
  const health = healthFile && fs.existsSync(healthFile) ? JSON.parse(fs.readFileSync(healthFile, "utf8")) : null;
  return { acts, health: health ?? undefined };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const data = opt("--data");
    if (!data || !opt("--trust")) throw new Error("usage: bin/sign.mjs --data <dir> --trust <trust.json> [--candidates <dir>] [--acts <file>] [--health <file>] [--report <file>]");
    const { acts, health } = readWorkFiles({ actsFile: opt("--acts"), healthFile: opt("--health") });
    const report = runSign({
      dataDir: data,
      root: ROOT,
      trustFile: opt("--trust"),
      env: process.env,
      now: Math.floor(Date.now() / 1000),
      candidates: readCandidates(opt("--candidates")),
      acts,
      health,
    });
    console.log(JSON.stringify({ ...report, acts: report.acts.map((a) => ({ ref: a.confirmation.ref, type: a.type, seq: a.seq })) }));
    if (opt("--report")) writeJson(opt("--report"), report);
    if (process.env.GITHUB_OUTPUT) {
      fs.appendFileSync(process.env.GITHUB_OUTPUT, `issued_at=${report.issuedAt}\nkey_id=${report.keyId}\nrefused_acts=${report.refusedActs.length}\n`);
    }
    for (const d of report.duplicateActs) console.log(`act ${d.ref} (${d.type}) was already applied as seq ${d.seq}; not applied again`);
    for (const r of report.refusedActs) console.error(`act refused: ${r.ref ?? "(no ref)"} ${r.type}: ${r.problems.join("; ")}`);
  } catch (e) {
    console.error(`sign refused: ${e.message}`);
    process.exit(1);
  }
}
