// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The catalogue's state: what is on the `data` branch.
//
// main holds the code and the policy (first-party.json, loaders.json)
// and changes by pull request. `data` holds what the catalogue has
// accepted and decided, and only sign.yml and resign.yml write it, in the
// publish-games environment. Every file is written with the vendored
// canonical serialiser (sorted keys, integers only, I-JSON strings), so a
// diff of `data` reads as what changed and nothing else.
//
//   entries.json        [{entry, meta}] accepted releases; `entry` is exactly
//                       the astra.games.index/1 entry, `meta` is ours
//   bindings.json       {repo_id: {account, repo_id, repo_owner_id, binding_token, bound_at}}
//   engine-codes.json   {code: {account, repo_id, repo_owner_id}}
//   moderation.json     rows only moderator acts write (R33)
//   withdrawn.json      {rows, held, lifts, spent}: applied rows (each with the ref of
//                       its act, and `cascade` when a revoke wrote it for a dependant),
//                       takedowns over the bound, the kept lifts (who, why, which acts,
//                       whether one was a security revoke; at most 256), and the
//                       takedown units spent in the trailing 24 hours, by apply time
//   holds.json          releases waiting for a person (changed hands, no pin)
//   health.json         the plugins service's counts per entry id (merged §5.2)
//   floors.json         the games kind's serial floor per document, the key ids
//                       spent per document schema ({schema: [{key_id, public_key}]}, signing.mjs),
//                       and the keys that signed the last withdrawn list (withdrawn_signers)
//   acts/<seq>.json     every act applied, in order — the public record, never
//                       rewritten; the state is held to it (acts.mjs actsUnaccounted)
//   dist/               the two signed envelopes, as served

import fs from "node:fs";
import path from "node:path";

import { stableStringify } from "./vendor/astra-registry/tools/lib/canonical.mjs";

export const FILES = Object.freeze({
  entries: "entries.json",
  bindings: "bindings.json",
  engineCodes: "engine-codes.json",
  moderation: "moderation.json",
  withdrawn: "withdrawn.json",
  holds: "holds.json",
  health: "health.json",
  floors: "floors.json",
});

export function emptyModeration() {
  return {
    games: [],
    anticheat: [],
    loaders: { add: [], remove: [] },
    reviewed: [],
    foundations: {},
    recommended_foundations: {},
  };
}

const EMPTY = () => ({
  entries: [],
  bindings: {},
  engineCodes: {},
  moderation: emptyModeration(),
  withdrawn: { rows: [], held: [], lifts: [], spent: [] },
  holds: [],
  health: {},
  floors: {},
});

export function loadState(dir) {
  const s = EMPTY();
  for (const [key, file] of Object.entries(FILES)) {
    const p = path.join(dir, file);
    if (fs.existsSync(p)) s[key] = JSON.parse(fs.readFileSync(p, "utf8"));
  }
  s.moderation = { ...emptyModeration(), ...s.moderation };
  // a withdrawn.json written before lifts existed has no such member
  s.withdrawn = { rows: [], held: [], lifts: [], spent: [], ...s.withdrawn };
  s.acts = loadActs(dir);
  return s;
}

export function loadActs(dir) {
  const d = path.join(dir, "acts");
  if (!fs.existsSync(d)) return [];
  return fs
    .readdirSync(d)
    .filter((f) => /^\d{6,}\.json$/.test(f))
    .sort()
    .map((f) => JSON.parse(fs.readFileSync(path.join(d, f), "utf8")));
}

export function nextActSeq(dir) {
  const acts = loadActs(dir);
  return acts.length ? Math.max(...acts.map((a) => Number(a.seq))) + 1 : 1;
}

export function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, stableStringify(value));
}

export function saveState(dir, s) {
  for (const [key, file] of Object.entries(FILES)) writeJson(path.join(dir, file), s[key]);
}

export function saveAct(dir, act) {
  writeJson(path.join(dir, "acts", `${String(act.seq).padStart(6, "0")}.json`), act);
}

/** Policy files from main (the repository root), read-only. */
export function loadPolicy(root) {
  const read = (f) => (fs.existsSync(path.join(root, f)) ? JSON.parse(fs.readFileSync(path.join(root, f), "utf8")) : null);
  return { firstParty: read("first-party.json"), loaders: read("loaders.json") };
}
