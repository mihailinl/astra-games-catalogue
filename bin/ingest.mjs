#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The ingest job's entry point (ingest.yml's matrix `ingest` job). Reads ONE
// lease from the request FILE the `work` job wrote (games-request-<lease>.json,
// an astra.games.leases/1 item) — never from a string a workflow
// interpolated — checks its shape, runs one release through lib/ingest.mjs and
// writes the unsigned candidate. It holds no secret: GITHUB_TOKEN is the job's
// read-only token, used for GitHub's API rate limit only.
//
//   node bin/ingest.mjs --data <data-branch checkout> --request <games-request-<lease>.json> --out <candidate.json> [--lease <id>]
//
// Exit 0 whatever the verdict (the verdict is data for the report job and
// sign.yml); non-zero only when the run itself broke.

import fs from "node:fs";
import path from "node:path";

import { githubApi } from "../lib/github.mjs";
import { ingestRelease, parseRequest } from "../lib/ingest.mjs";
import { effectiveLoaders } from "../lib/model.mjs";
import { binaryProbe } from "../lib/probe.mjs";
import { runGh } from "../lib/provenance.mjs";
import { loadReserved } from "../lib/schemas.mjs";
import { loadPolicy, loadState, writeJson } from "../lib/state.mjs";
import { storeApi } from "../lib/steam.mjs";
import { ROOT } from "../lib/vendored.mjs";

const args = process.argv.slice(2);
const opt = (n) => (args.indexOf(n) >= 0 ? args[args.indexOf(n) + 1] : null);

/** The request, from one lease file (lib/ingest.mjs parseRequest). */
export function readRequest(doc) {
  return parseRequest(doc);
}

async function main() {
  const data = opt("--data");
  const outFile = opt("--out");
  const requestFile = opt("--request");
  if (!data || !outFile || !requestFile) throw new Error("usage: bin/ingest.mjs --data <dir> --request <games-request-<lease>.json> --out <candidate.json>");
  const request = readRequest(JSON.parse(fs.readFileSync(requestFile, "utf8")));
  // the matrix names the lease; the file must be that lease's
  if (opt("--lease") && request.lease_id !== opt("--lease")) throw new Error(`${requestFile} is lease ${request.lease_id}, not ${opt("--lease")}`);

  const policy = loadPolicy(ROOT);
  const state = loadState(data);
  const workdir = path.join(path.dirname(path.resolve(outFile)), "work");

  const candidate = await ingestRelease({
    request,
    // ingest hands gi-probe check these rows as the bare array --loaders reads
    policy: { firstParty: policy.firstParty, loaders: effectiveLoaders(policy.loaders, state.moderation) },
    state,
    reserved: loadReserved(),
    deps: { github: githubApi(), gh: runGh, probe: binaryProbe(), steam: storeApi(), workdir },
  });
  writeJson(outFile, candidate);
  console.log(`${candidate.verdict}  lease ${request.lease_id}  repository ${request.repo_id} ${candidate.request.tag ?? "(no release)"}  ${candidate.findings.map((f) => f.code).join(" ") || "no findings"}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error(`ingest broke: ${e.message}`);
    process.exit(1);
  });
}
