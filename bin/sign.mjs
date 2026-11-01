#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The signing job's entry point (sign.yml; resign.yml runs bin/resign.mjs).
// Runs in the games-signing environment, the only place the signing secrets
// exist; reads them from the environment, never from arguments.
//
//   node bin/sign.mjs --data <data-branch checkout> [--candidates <dir>] [--from-event]
//
//   --candidates   a directory of candidate JSON files (ingest's artifact)
//   --from-event   read $GITHUB_EVENT_NAME and $GITHUB_EVENT_PATH: a
//                  repository_dispatch `games-act` carries one moderator act
//                  in client_payload.act; `games-health` carries the plugins
//                  service's counts in client_payload.health
//
// Payloads are read from the event FILE; nothing a dispatcher wrote is ever
// interpolated into a shell. Prints a one-line JSON report and writes
// `refused_acts` to $GITHUB_OUTPUT (sign.yml fails the run on it AFTER the
// rest is committed); exits 1 when the run itself was refused.

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

/** {acts, health} from a repository_dispatch event; nothing for any other event. */
function fromEvent() {
  if (process.env.GITHUB_EVENT_NAME !== "repository_dispatch") return { acts: [], health: undefined };
  const file = process.env.GITHUB_EVENT_PATH;
  if (!file) throw new Error("GITHUB_EVENT_PATH is not set");
  const event = JSON.parse(fs.readFileSync(file, "utf8"));
  if (event.action === "games-act") return { acts: [event.client_payload?.act], health: undefined };
  if (event.action === "games-health") return { acts: [], health: event.client_payload?.health };
  throw new Error(`repository_dispatch ${JSON.stringify(event.action)} is not an event this signer reads`);
}

try {
  const data = opt("--data");
  if (!data) throw new Error("usage: bin/sign.mjs --data <dir> [--candidates <dir>] [--from-event]");
  const { acts, health } = has("--from-event") ? fromEvent() : { acts: [], health: undefined };
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
  for (const r of report.refusedActs) console.error(`act refused: ${r.type}: ${r.problems.join("; ")}`);
} catch (e) {
  console.error(`sign refused: ${e.message}`);
  process.exit(1);
}
