#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The scheduled re-sign (resign.yml, daily). A copy expires 7 days after it
// was issued and clients stop new installs and updates on an expired copy,
// so both documents are re-signed every day whether or not anything changed
// — and held takedowns whose window has freed are admitted on the way.
//
//   node bin/resign.mjs --data <data-branch checkout> --trust <trust.json>

import fs from "node:fs";

import { runSign } from "../lib/pipeline.mjs";
import { ROOT } from "../lib/vendored.mjs";

const args = process.argv.slice(2);
const opt = (n) => (args.indexOf(n) >= 0 ? args[args.indexOf(n) + 1] : null);
const data = opt("--data");
try {
  if (!data || !opt("--trust")) throw new Error("usage: bin/resign.mjs --data <dir> --trust <trust.json>");
  const report = runSign({ dataDir: data, root: ROOT, trustFile: opt("--trust"), env: process.env, now: Math.floor(Date.now() / 1000) });
  console.log(JSON.stringify(report));
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `issued_at=${report.issuedAt}\nkey_id=${report.keyId}\n`);
  // signed, but a person should know (signing.mjs droppedCoSigners); an annotation in Actions
  for (const w of report.warnings ?? []) console.error(`${process.env.GITHUB_ACTIONS === "true" ? "::warning::" : "warning: "}${w}`);
} catch (e) {
  console.error(`resign refused: ${e.message}`);
  process.exit(1);
}
