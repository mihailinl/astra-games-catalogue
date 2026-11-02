#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Install the pinned gi-probe for the ingest job (gi-probe.json).
//
//   node bin/fetch-gi-probe.mjs --dir <bin dir>
//
// With no version pinned it installs nothing and says so; ingest then waits
// (lib/probe.mjs fails closed). With a pin it downloads the binary, refuses
// it unless its SHA-256 equals the pin, marks it executable and appends
// GI_PROBE=<path> to $GITHUB_ENV.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { ROOT } from "../lib/vendored.mjs";

const args = process.argv.slice(2);
const dir = args.indexOf("--dir") >= 0 ? args[args.indexOf("--dir") + 1] : null;
const pin = JSON.parse(fs.readFileSync(path.join(ROOT, "gi-probe.json"), "utf8"));
try {
  if (!dir) throw new Error("usage: bin/fetch-gi-probe.mjs --dir <bin dir>");
  if (!pin.version) {
    console.log("gi-probe is not pinned (astra-game-launcher 0.5.0 is not released): ingest will wait, and list nothing");
    process.exit(0);
  }
  if (!/^https:\/\/github\.com\//.test(String(pin.url)) || !/^[0-9a-f]{64}$/.test(String(pin.sha256))) {
    throw new Error("gi-probe.json pins a version without a github.com url and a sha256");
  }
  // optional: the build's tool.source_tree_sha256, which lib/probe.mjs
  // requires of every report (the launcher's build.rs tree hash of the tag)
  if (pin.source_tree_sha256 != null && !/^[0-9a-f]{64}$/.test(String(pin.source_tree_sha256))) {
    throw new Error("gi-probe.json's source_tree_sha256 is not 64 hex digits");
  }
  const res = await fetch(pin.url, { redirect: "follow" });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${pin.url}`);
  const bytes = Buffer.from(await res.arrayBuffer());
  const got = crypto.createHash("sha256").update(bytes).digest("hex");
  if (got !== pin.sha256) throw new Error(`gi-probe ${pin.version} hashes to ${got}, and gi-probe.json pins ${pin.sha256}`);
  fs.mkdirSync(dir, { recursive: true });
  const bin = path.join(dir, "gi-probe");
  fs.writeFileSync(bin, bytes, { mode: 0o755 });
  if (process.env.GITHUB_ENV) fs.appendFileSync(process.env.GITHUB_ENV, `GI_PROBE=${bin}\n`);
  console.log(`gi-probe ${pin.version} installed at ${bin}`);
} catch (e) {
  console.error(`gi-probe not installed: ${e.message}`);
  process.exit(1);
}
