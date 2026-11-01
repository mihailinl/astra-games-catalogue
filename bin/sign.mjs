#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The signing job's entry point (sign.yml; resign.yml runs bin/resign.mjs).
// Runs in the games-signing environment, the only place the signing secrets
// exist; reads them from the environment, never from arguments.
//
//   node bin/sign.mjs --data <data-branch checkout> [--candidates <dir>] [--act-event] [--health-event]
//
//   --candidates   a directory of candidate JSON files (ingest's artifact)
//   --act-event    $GITHUB_EVENT_PATH is a repository_dispatch `games-act`:
//                  its client_payload.act is one moderator act
//   --health-event $GITHUB_EVENT_PATH is a repository_dispatch `games-health`:
//                  its client_payload.health holds the plugins service's counts
//
// Payloads are read from the event FILE; nothing a dispatcher wrote is ever
// interpolated into a shell. Prints a one-line JSON report; exits 3 when an
// act was refused (after writing everything else), 1 when the run broke.

import fs from "node:fs";
import path from "node:path";

import { runSign } from "../lib/pipeline.mjs";
import { ROOT } from "../lib/vendored.mjs";

const args = process.argv.slice(2);
const has = (n) => args.includes(n);
const opt = (n) => (args.indexOf(n) >= 0 ? args[args.indexOf(n) + 1] : null);

function readCandidates(dir) {
  if (!dir || !fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((f) => f.endsWith(".json")).sort().map((f) => JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")));
}

function eventPayload() {
  const file = process.env.GITHUB_EVENT_PATH;
  if (!file) throw new Error("GITHUB_EVENT_PATH is not set");
  return JSON.parse(fs.readFileSync(file, "utf8"))?.client_payload ?? {};
}

try {
  const data = opt("--data");
  if (!data) throw new Error("usage: bin/sign.mjs --data <dir> [--candidates <dir>] [--act-event] [--health-event]");
  const acts = has("--act-event") ? [eventPayload().act] : [];
  const health = has("--health-event") ? eventPayload().health : undefined;
  const report = runSign({
    dataDir: data,
    root: ROOT,
    env: process.env,
    now: Math.floor(Date.now() / 1000),
    candidates: readCandidates(opt("--candidates")),
    acts,
    health,
  });
  console.log(JSON.stringify(report));
  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `issued_at=${report.issuedAt}\nkey_id=${report.keyId}\nrefused_acts=${report.refusedActs.length}\n`);
  }
  process.exit(report.refusedActs.length ? 3 : 0);
} catch (e) {
  console.error(`sign refused: ${e.message}`);
  process.exit(1);
}
