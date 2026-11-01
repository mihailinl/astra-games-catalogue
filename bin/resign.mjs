#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The scheduled re-sign (resign.yml, daily). A copy expires 7 days after it
// was issued and clients stop new installs and updates on an expired copy,
// so both documents are re-signed every day whether or not anything changed
// — and held takedowns whose window has freed are admitted on the way.
//
//   node bin/resign.mjs --data <data-branch checkout>

import fs from "node:fs";

import { runSign } from "../lib/pipeline.mjs";
import { ROOT } from "../lib/vendored.mjs";

const args = process.argv.slice(2);
const data = args.indexOf("--data") >= 0 ? args[args.indexOf("--data") + 1] : null;
try {
  if (!data) throw new Error("usage: bin/resign.mjs --data <dir>");
  const report = runSign({ dataDir: data, root: ROOT, env: process.env, now: Math.floor(Date.now() / 1000) });
  console.log(JSON.stringify(report));
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `issued_at=${report.issuedAt}\nkey_id=${report.keyId}\n`);
} catch (e) {
  console.error(`resign refused: ${e.message}`);
  process.exit(1);
}
