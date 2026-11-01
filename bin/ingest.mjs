#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The ingest job's entry point (ingest.yml). Reads the request from the
// event payload FILE ($GITHUB_EVENT_PATH) — never from a string a workflow
// interpolated — checks its shape, runs one release through lib/ingest.mjs
// and writes the unsigned candidate. It holds no secret: GITHUB_TOKEN is the
// job's read-only token, used for GitHub's API rate limit only.
//
//   node bin/ingest.mjs --data <data-branch checkout> --out <candidate.json> [--request <file>]
//
// Exit 0 whatever the verdict (the verdict is data for sign.yml); non-zero
// only when the run itself broke.

import fs from "node:fs";
import path from "node:path";

import { githubApi } from "../lib/github.mjs";
import { ingestRelease } from "../lib/ingest.mjs";
import { effectiveLoaders } from "../lib/model.mjs";
import { binaryProbe } from "../lib/probe.mjs";
import { runGh } from "../lib/provenance.mjs";
import { loadReserved } from "../lib/schemas.mjs";
import { loadPolicy, loadState, writeJson } from "../lib/state.mjs";
import { storeApi } from "../lib/steam.mjs";
import { ROOT } from "../lib/vendored.mjs";

const args = process.argv.slice(2);
const opt = (n) => (args.indexOf(n) >= 0 ? args[args.indexOf(n) + 1] : null);

/** The request, from repository_dispatch's client_payload or workflow_dispatch's inputs. */
export function readRequest(event) {
  const p = event?.client_payload ?? event?.inputs ?? event ?? {};
  const req = {
    repo_id: Number(p.repo_id),
    tag: String(p.tag ?? ""),
    account: p.account ? String(p.account) : undefined,
    binding_token: p.binding_token ? String(p.binding_token) : undefined,
  };
  const bad = [];
  if (!Number.isSafeInteger(req.repo_id) || req.repo_id < 1) bad.push("repo_id is not a positive integer");
  if (!/^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/.test(req.tag)) bad.push("tag is not a plain tag name");
  if (req.account !== undefined && !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(req.account)) bad.push("account is not an account name");
  if (req.binding_token !== undefined && !/^[A-Za-z0-9_-]{16,128}$/.test(req.binding_token)) bad.push("binding_token is not a binding token");
  if (bad.length) throw new Error(`the ingest request is malformed: ${bad.join("; ")}`);
  return req;
}

async function main() {
  const data = opt("--data");
  const outFile = opt("--out");
  if (!data || !outFile) throw new Error("usage: bin/ingest.mjs --data <dir> --out <candidate.json> [--request <file>]");
  const eventFile = opt("--request") ?? process.env.GITHUB_EVENT_PATH;
  const request = readRequest(JSON.parse(fs.readFileSync(eventFile, "utf8")));

  const policy = loadPolicy(ROOT);
  const state = loadState(data);
  const workdir = path.join(path.dirname(path.resolve(outFile)), "work");
  const loadersFile = path.join(workdir, "loaders.json");
  writeJson(loadersFile, { loaders: effectiveLoaders(policy.loaders, state.moderation) });

  const candidate = await ingestRelease({
    request,
    policy: { firstParty: policy.firstParty, loadersFile },
    state,
    reserved: loadReserved(),
    deps: { github: githubApi(), gh: runGh, probe: binaryProbe(), steam: storeApi(), workdir },
  });
  writeJson(outFile, candidate);
  console.log(`${candidate.verdict}  repository ${request.repo_id} ${request.tag}  ${candidate.findings.map((f) => f.code).join(" ") || "no findings"}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error(`ingest broke: ${e.message}`);
    process.exit(1);
  });
}
