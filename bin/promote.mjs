#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// promote.yml's entry point: make the first-party repositories' GitHub
// releases agree with the SIGNED documents (lib/promote.mjs).
//
//   node bin/promote.mjs --data <data-branch checkout> [--apply]
//
// Without --apply it prints the plan. With --apply it needs GH_APP_TOKEN (the
// first-party-promote environment's App token) and verifies both documents'
// signatures against keys.json before acting on them.

import fs from "node:fs";
import path from "node:path";

import { INDEX_SCHEMA, verifyDocuments, WITHDRAWN_SCHEMA } from "../lib/documents.mjs";
import { applyPlan, planReleases, releasesApi } from "../lib/promote.mjs";
import { loadPolicy } from "../lib/state.mjs";
import { ROOT } from "../lib/vendored.mjs";

const args = process.argv.slice(2);
const data = args.indexOf("--data") >= 0 ? args[args.indexOf("--data") + 1] : null;
try {
  if (!data) throw new Error("usage: bin/promote.mjs --data <dir> [--apply]");
  const policy = loadPolicy(ROOT);
  const read = (f) => JSON.parse(fs.readFileSync(path.join(data, "dist", f), "utf8"));
  const index = read("games-index.json");
  const withdrawn = read("games-withdrawn.json");
  const now = Math.floor(Date.now() / 1000);
  const keys = policy.keys?.keys ?? [];
  const problems = verifyDocuments([
    { envelope: index, domain: INDEX_SCHEMA },
    { envelope: withdrawn, domain: WITHDRAWN_SCHEMA, indexBody: index.signed },
  ], { keys, now }).flat();
  if (problems.length) throw new Error(`the signed documents do not verify, so nothing is promoted: ${problems.join("; ")}`);
  const plan = planReleases({ index: index.signed, withdrawn: withdrawn.signed, firstParty: policy.firstParty });
  if (!args.includes("--apply")) {
    console.log(JSON.stringify(plan, null, 2));
    process.exit(0);
  }
  if (!process.env.GH_APP_TOKEN) throw new Error("GH_APP_TOKEN is not set (the first-party-promote environment's App token)");
  const result = await applyPlan(plan, releasesApi({ token: process.env.GH_APP_TOKEN }));
  console.log(JSON.stringify(result));
  process.exit(result.some((r) => r.error) ? 1 : 0);
} catch (e) {
  console.error(`promote refused: ${e.message}`);
  process.exit(1);
}
