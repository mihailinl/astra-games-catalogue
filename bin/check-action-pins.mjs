#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Re-resolve every pinned action's tag online and confirm the pin is the
// tag's PEELED commit: for an annotated tag `refs/tags/<t>^{}` (the commit),
// never `refs/tags/<t>` (the tag object). The failure this exists for is
// real: an init-ci once pinned the tag object of an annotated tag.
//
//   node bin/check-action-pins.mjs

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { ROOT } from "../lib/vendored.mjs";

const pins = JSON.parse(fs.readFileSync(path.join(ROOT, ".github", "action-pins.json"), "utf8"));
let bad = 0;
for (const [action, { tag, sha }] of Object.entries(pins)) {
  if (action.startsWith("$")) continue;
  const out = execFileSync("git", ["ls-remote", `https://github.com/${action}`, `refs/tags/${tag}`, `refs/tags/${tag}^{}`], { encoding: "utf8" });
  const refs = Object.fromEntries(out.trim().split("\n").filter(Boolean).map((l) => l.split("\t").reverse()));
  const peeled = refs[`refs/tags/${tag}^{}`] ?? refs[`refs/tags/${tag}`];
  if (!peeled) {
    console.error(`FAIL  ${action} has no tag ${tag}`);
    bad++;
  } else if (peeled !== sha) {
    console.error(`FAIL  ${action}@${tag} peels to ${peeled}; action-pins.json says ${sha}${refs[`refs/tags/${tag}`] === sha ? " (that is the TAG OBJECT)" : ""}`);
    bad++;
  } else console.log(`ok    ${action}@${tag} = ${sha}${refs[`refs/tags/${tag}^{}`] ? " (annotated, peeled)" : " (lightweight)"}`);
}
process.exit(bad ? 1 : 0);
