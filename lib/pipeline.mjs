// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// One signing run, end to end, as sign.yml and resign.yml run it:
//
//   1. load the state (`data` branch) and the policy (main);
//   2. accept the candidates ingest produced (schema and state re-checks only);
//   3. validate, record and apply the acts, in order;
//   4. admit takedowns the bound held earlier, if the window has room;
//   5. sign BOTH documents under one issued_at, self-verify, and write them
//      with the state — or write nothing at all.
//
// Step 5 runs on every call, whether or not anything changed: that is the
// daily re-sign, and it is what makes "every act re-signs both documents"
// true by construction rather than by each act remembering to.

import path from "node:path";

import { acceptCandidate } from "./accept.mjs";
import { actProblems, admitHeld, applyAct } from "./acts.mjs";
import { loadReserved, validateEntries } from "./schemas.mjs";
import { selectSigner, signBoth } from "./signing.mjs";
import { loadTrust } from "./trust.mjs";
import { loadPolicy, loadState, nextActSeq, saveAct, saveState, writeJson } from "./state.mjs";

const HEALTH_KEYS = ["rating_avg", "rating_count", "open_reports_unanswered", "reports_sent", "reports_failed"];

/**
 * The plugins service's counts per entry id (merged §5.2). Integers only:
 * rating_avg in hundredths of a star; reports_* are reports users CHOSE to
 * send. A malformed payload is refused whole rather than half-applied.
 */
export function checkHealth(health) {
  if (!health || typeof health !== "object" || Array.isArray(health)) throw new Error("health is {entry_id: counts}");
  const out = {};
  for (const [id, h] of Object.entries(health)) {
    if (!h || typeof h !== "object") throw new Error(`health.${id} is not an object`);
    const row = {};
    for (const k of HEALTH_KEYS) {
      if (h[k] === undefined) continue;
      if (!Number.isSafeInteger(h[k]) || h[k] < 0) throw new Error(`health.${id}.${k} is not a non-negative integer`);
      row[k] = h[k];
    }
    if (row.rating_avg !== undefined && row.rating_avg > 500) throw new Error(`health.${id}.rating_avg is hundredths of a 5-star scale`);
    out[id] = row;
  }
  return out;
}

/**
 * @param {{dataDir: string, root: string, env: object, now: number, trustFile: string, roots?: object,
 *          candidates?: object[], acts?: object[], health?: object, members?: object}} o
 *   `roots` is for tests only: production verifies trust.json under the compiled roots.
 * @returns {{accepted: object[], acts: object[], admitted: object[], issuedAt: number, keyId: string, refusedActs: object[]}}
 */
export function runSign({ dataDir, root, env, now, trustFile, roots, candidates = [], acts = [], health, members }) {
  const policy = loadPolicy(root);
  const state = loadState(dataDir);
  const reserved = loadReserved();
  // Refuse to sign before touching anything: a trust.json that does not
  // verify under the compiled roots or carries no games kind keys, no key, a
  // spent key, or a key trust.json does not authorise ends the run with the
  // state unchanged.
  const { kindKeys } = loadTrust({ file: trustFile, now, ...(roots ? { roots } : {}) });
  const signer = selectSigner({ env, floors: state.floors, kindKeys, now });

  if (health !== undefined) state.health = checkHealth(health);
  // one schemalite process for every candidate's entry
  const withEntry = candidates.filter((c) => c?.entry);
  const shapes = new Map(validateEntries(withEntry.map((c) => c.entry)).map((r, i) => [withEntry[i], r]));
  const accepted = candidates.map((c) => ({ request: c?.request ?? null, ...acceptCandidate(c, state, { reserved, now, shape: shapes.get(c) ?? null }) }));

  const applied = [];
  const refusedActs = [];
  let seq = nextActSeq(dataDir);
  const records = [];
  for (const act of acts) {
    const problems = actProblems(act, state);
    if (problems.length) {
      refusedActs.push({ type: act?.type ?? null, problems });
      continue;
    }
    const summary = applyAct(act, state, { now, reserved });
    const record = { ...act, seq, applied_at: now, summary };
    records.push(record);
    applied.push(record);
    seq += 1;
  }

  const admitted = admitHeld(state, now);
  const signed = signBoth({ state, seedLoaders: policy.loaders, signer, kindKeys, now, members });

  state.floors = signed.floors;
  saveState(dataDir, state);
  for (const r of records) saveAct(dataDir, r);
  writeJson(path.join(dataDir, "dist", "games-index.json"), signed.index);
  writeJson(path.join(dataDir, "dist", "games-withdrawn.json"), signed.withdrawn);
  return { accepted, acts: applied, admitted, issuedAt: signed.issuedAt, keyId: signer.key_id, refusedActs };
}
