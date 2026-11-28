#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The signing job's entry point (sign.yml; resign.yml runs bin/resign.mjs).
// Runs in the publish-games environment, the only place the signing secrets
// exist; reads them from the environment, never from arguments.
//
//   node bin/sign.mjs --data <data-branch checkout> --trust <trust.json>
//                     [--candidates <dir>] [--signable <signable.json>] [--acts <acts.json>] [--health <health.json>] [--report <file>]
//
//   --trust        the published, root-signed trust.json (astra-registry
//                  registry/v1/trust.json); its `kind_keys` say which two keys
//                  may sign the games documents (lib/trust.mjs)
//   --candidates   the Ingest run's candidates: <dir>/*.json, or one
//                  <dir>/games-candidate-<lease>/candidate.json per lease
//   --signable     the leases the plugins service would settle as signed, as
//                  sign.yml's work job wrote them (GET bot/games/work,
//                  plugins 0144). ONLY those candidates are listed; absent,
//                  null or malformed lists none (acts and health still apply)
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
import { readCandidates } from "../lib/candidates.mjs";
import { checkSignable } from "../lib/service.mjs";
import { writeJson } from "../lib/state.mjs";
import { ROOT } from "../lib/vendored.mjs";

const args = process.argv.slice(2);
const opt = (n) => (args.indexOf(n) >= 0 ? args[args.indexOf(n) + 1] : null);

export { readCandidates } from "../lib/candidates.mjs";

/**
 * The oldest signable list the signer acts on: 20 minutes, under the service's requeue grace (45 min
 * after 0156; 30 before). Past it the list says what the service would have settled THEN; the lease
 * may since have been requeued and re-leased, or its art may no longer be cleared.
 */
export const SIGNABLE_MAX_AGE_MS = 20 * 60 * 1000;
/** A read_at this far in the future is a clock nobody can trust, so it is as good as none. */
export const SIGNABLE_MAX_SKEW_MS = 5 * 60 * 1000;

/**
 * The work job's files: acts a list (absent = none), health an object or null
 * (absent = unchanged), signable a list of lease ids or null. Signable is
 * read again here (it crossed an artifact boundary) and fails CLOSED:
 * absent, unreadable, null, malformed, without its read_at (an artifact from
 * before the stamp), older than SIGNABLE_MAX_AGE_MS or dated in the future is
 * null, which lists no candidate -- never a refused run, so acts and health
 * still land. `signableProblem` says which, for the job's warning.
 */
export function readWorkFiles({ actsFile, healthFile, signableFile = null, now = Date.now() }) {
  const acts = actsFile && fs.existsSync(actsFile) ? JSON.parse(fs.readFileSync(actsFile, "utf8")) : [];
  if (!Array.isArray(acts)) throw new Error(`${actsFile} is not a list of acts`);
  const health = healthFile && fs.existsSync(healthFile) ? JSON.parse(fs.readFileSync(healthFile, "utf8")) : null;
  let signable = null;
  let signableProblem = "no signable.json";
  if (signableFile && fs.existsSync(signableFile)) {
    try {
      const v = JSON.parse(fs.readFileSync(signableFile, "utf8"));
      const readAt = v && typeof v === "object" && !Array.isArray(v) && typeof v.read_at === "string" ? Date.parse(v.read_at) : NaN;
      if (!Number.isFinite(readAt)) signableProblem = "signable.json carries no read_at (an artifact from before the stamp)";
      else if (now - readAt > SIGNABLE_MAX_AGE_MS) signableProblem = `signable.json was read at ${v.read_at}, more than ${SIGNABLE_MAX_AGE_MS / 60000} minutes ago (a re-run of the sign job alone?)`;
      else if (readAt - now > SIGNABLE_MAX_SKEW_MS) signableProblem = `signable.json's read_at ${v.read_at} is in the future`;
      else if (v.leases === null) signableProblem = "the service named no signable list";
      else {
        signable = checkSignable(v.leases).signable;
        signableProblem = signable === null ? "signable.json's list is malformed" : null;
      }
    } catch {
      signable = null;
      signableProblem = "signable.json is unreadable";
    }
  }
  return { acts, health: health ?? undefined, signable, signableProblem };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const data = opt("--data");
    if (!data || !opt("--trust")) throw new Error("usage: bin/sign.mjs --data <dir> --trust <trust.json> [--candidates <dir>] [--signable <file>] [--acts <file>] [--health <file>] [--report <file>]");
    const { acts, health, signable, signableProblem } = readWorkFiles({ actsFile: opt("--acts"), healthFile: opt("--health"), signableFile: opt("--signable") });
    if (signable === null) console.error(`::warning::${signableProblem}; no new candidate is signed this run (acts, health and the re-sign go on)`);
    const report = runSign({
      dataDir: data,
      root: ROOT,
      trustFile: opt("--trust"),
      env: process.env,
      now: Math.floor(Date.now() / 1000),
      candidates: readCandidates(opt("--candidates")),
      signable,
      acts,
      health,
    });
    console.log(JSON.stringify({ ...report, acts: report.acts.map((a) => ({ ref: a.confirmation.ref, type: a.type, seq: a.seq })) }));
    if (opt("--report")) writeJson(opt("--report"), report);
    if (process.env.GITHUB_OUTPUT) {
      fs.appendFileSync(process.env.GITHUB_OUTPUT, `issued_at=${report.issuedAt}\nkey_id=${report.keyId}\nrefused_acts=${report.refusedActs.length}\n`);
    }
    // signed, but a person should know (signing.mjs droppedCoSigners); an annotation in Actions
    for (const w of report.warnings ?? []) console.error(`${process.env.GITHUB_ACTIONS === "true" ? "::warning::" : "warning: "}${w}`);
    if (report.firstPartyBound?.length) console.log(`first-party bindings written for ${report.firstPartyBound.join(", ")}: the plugins service polls these repositories from this commit of data`);
    for (const l of report.leftOut) console.log(`candidate ${l.lease_id ?? "(no lease)"} left out: ${l.reason}; it is not settled, and nothing listed moves`);
    for (const d of report.duplicateActs) console.log(`act ${d.ref} (${d.type}) was already applied as seq ${d.seq}; not applied again`);
    for (const r of report.refusedActs) console.error(`act refused: ${r.ref ?? "(no ref)"} ${r.type}: ${r.problems.join("; ")}`);
  } catch (e) {
    console.error(`sign refused: ${e.message}`);
    process.exit(1);
  }
}
