// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The Ingest run's candidates, as a job downloaded them (download-artifact
// with `pattern: games-candidate-*`). Two layouts reach a reader, and both are
// read: several matching artifacts land in <dir>/<artifact>/candidate.json,
// but exactly ONE matching artifact is extracted straight into <dir>, as
// <dir>/candidate.json. A run that leased one release produces the second.

import fs from "node:fs";
import path from "node:path";

/** Candidate files: <dir>/*.json, and <dir>/<artifact>/candidate.json, in name order. */
export function readCandidates(dir) {
  if (!dir || !fs.existsSync(dir)) return [];
  const files = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    if (e.isFile() && e.name.endsWith(".json")) files.push(path.join(dir, e.name));
    else if (e.isDirectory() && fs.existsSync(path.join(dir, e.name, "candidate.json"))) files.push(path.join(dir, e.name, "candidate.json"));
  }
  return files.map((f) => JSON.parse(fs.readFileSync(f, "utf8")));
}
