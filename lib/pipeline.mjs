// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// One signing run, end to end, as sign.yml and resign.yml run it:
//
//   1. load the state (`data` branch) and the policy (main);
//   2. accept the candidates ingest produced (schema and state re-checks only);
//   3. validate, record and apply the acts, in order, each confirmation ref
//      once (a re-served act is answered "applied, seq N", never re-applied);
//   4. admit takedowns the bound held earlier, if the window has room;
//   5. sign BOTH documents under one issued_at, self-verify, and write them
//      with the state — or write nothing at all. The withdrawn list is held
//      to the one published last (step 1 reads it from dist/): a security
//      revoke never leaves it without its lift.
//
// Step 5 runs on every call, whether or not anything changed: that is the
// daily re-sign, and it is what makes "every act re-signs both documents"
// true by construction rather than by each act remembering to.

import fs from "node:fs";
import path from "node:path";

import { acceptCandidate } from "./accept.mjs";
import { ActRefused, actProblems, admitHeld, appliedRefs, applyAct } from "./acts.mjs";
import { buildIndexBody, buildWithdrawnBody, INDEX_SCHEMA, successorProblems, verifyEnvelopeAll, WITHDRAWN_SCHEMA, withdrawnProblems } from "./documents.mjs";
import { loadReserved, validateEntries } from "./schemas.mjs";
import { selectSigners, SignRefused, signBoth, spentLedger } from "./signing.mjs";
import { publicKeyFromBase64, signingDigest } from "./vendor/astra-registry/bot/lib/sign.mjs";
import { loadTrust, verifyingKeys } from "./trust.mjs";
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
 * The withdrawn list this signer published last, which the next one is held
 * to (documents.mjs successorProblems): the signed envelope every run writes
 * to dist/ in the same step as the state. It is in the data directory the
 * run loaded, so nothing is fetched. With it come the state's records of the
 * lifts as this run loaded them: a list's lift does not say whether it
 * lifted a security revoke, or when the signer applied it.
 *
 * null on a first run only. A first run is one whose data shows no trace of
 * a signing: no serial floor above 0 and no key recorded as spent
 * (floors.json), no signed index in dist/, no act recorded (acts/), no
 * accepted release (entries.json, which only a run that signed writes), and
 * no lift, held takedown or spent takedown unit (withdrawn.json, which only
 * an act writes). Nothing says so by hand; there is no flag. Losing dist/
 * alone, or dist/ and floors.json, therefore never reads as a first run: a
 * catalogue that ever signed has accepted a release. Rows seeded into
 * withdrawn.json by hand are not a trace: they are signed into the first
 * list, so nothing vanishes. What this cannot see is the whole data branch
 * replaced at once, consistently, by an older one or by nothing; `data` is
 * written only by sign.yml and resign.yml, by fast-forward pushes.
 *
 * Anything else refuses the run, and is never read as "nothing to compare
 * with": the list is missing after a signing; it cannot be parsed; no key
 * this signer trusts signed it (the two games kind keys of trust.json, and
 * the keys floors.json records as spent for the list's schema, which are the
 * keys it has signed lists with); or it is not the issue floors.json says
 * was signed last (an older list, correctly signed, lacks the newest
 * revokes). The way back is to put the served list in dist/ again: it is
 * the same file.
 *
 * @param {{dataDir: string, state: object, kindKeys: {current: object, next: object}}} o
 * @returns {{body: object, lifts: object[]} | null}
 */
export function lastWithdrawn({ dataDir, state, kindKeys }) {
  const name = "dist/games-withdrawn.json";
  const file = path.join(dataDir, name);
  const refuse = (what) => {
    throw new SignRefused("E_STATE_PREVIOUS", `${what}; refusing to sign a withdrawn list that cannot be compared with the last one published (a security revoke must not leave it without a lift)`);
  };
  const floor = state.floors?.withdrawn ?? 0;
  if (!fs.existsSync(file)) {
    const traces = [];
    if (floor > 0 || (state.floors?.index ?? 0) > 0) traces.push(`floors.json records signed documents (index ${state.floors.index ?? 0}, withdrawn ${floor})`);
    if (fs.existsSync(path.join(dataDir, "dist", "games-index.json"))) traces.push("dist/ holds a signed index");
    if (state.acts.length) traces.push(`${state.acts.length} applied act${state.acts.length > 1 ? "s are" : " is"} recorded`);
    const spent = Object.values(state.floors?.spent ?? {}).flat().length;
    if (spent) traces.push(`floors.json records ${spent} spent key${spent > 1 ? "s" : ""}`);
    if (state.entries.length) traces.push(`entries.json lists ${state.entries.length} accepted release${state.entries.length > 1 ? "s" : ""}`);
    const w = state.withdrawn;
    const kept = [["lift", w.lifts], ["held takedown", w.held], ["spent takedown unit", w.spent]].filter(([, a]) => Array.isArray(a) && a.length);
    if (kept.length) traces.push(`withdrawn.json keeps ${kept.map(([what, a]) => `${a.length} ${what}${a.length > 1 ? "s" : ""}`).join(", ")}`);
    if (traces.length) refuse(`${name} is missing, and this is not a first run: ${traces.join(", ")}`);
    return null;
  }
  let envelope;
  try {
    envelope = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    refuse(`${name} cannot be read (${e.message})`);
  }
  const keys = [
    ...verifyingKeys(kindKeys),
    ...spentLedger(state.floors)[WITHDRAWN_SCHEMA].filter((k) => k.public_key !== null).map((k) => ({ key_id: k.key_id, publicKey: publicKeyFromBase64(k.public_key) })),
  ];
  const v = verifyEnvelopeAll(envelope, WITHDRAWN_SCHEMA, keys);
  if (!v.ok) refuse(`${name} does not verify: ${v.reason} (trusted: ${keys.map((k) => k.key_id).join(", ")}; it names ${v.offered.join(", ") || "no key"})`);
  const body = envelope.signed;
  if (!Array.isArray(body?.rows) || !(body.lifts === undefined || Array.isArray(body.lifts))) refuse(`${name} is signed and is not a withdrawn list (no rows)`);
  if (body.serial !== floor) refuse(`${name} is serial ${body.serial} and floors.json says the last list signed is ${floor}: one of the two is not from the last run`);
  return { body, lifts: structuredClone(state.withdrawn.lifts ?? []) };
}

/**
 * The withdrawn list's rules that hold over `before` and no longer over
 * `after`: its own (documents.mjs withdrawnProblems: a lift beside its row,
 * two acts' rows in one second, an entry_id no client can read) and what it
 * owes the list published last (successorProblems: a security revoke gone
 * without its lift). A problem the state already had is not this act's.
 *
 * @param {object} before
 * @param {object} after
 * @param {number} now
 * @param {{body: object, lifts: object[]} | null} previous lastWithdrawn; null when no list was ever published
 */
export function listProblemsIntroduced(before, after, now, previous) {
  const problems = (s) => {
    const body = buildWithdrawnBody({ state: s, issuedAt: now, keyId: "games-current" });
    return [...withdrawnProblems(body), ...successorProblems(previous, body, now)];
  };
  const had = new Set(problems(before));
  return problems(after).filter((p) => !had.has(p));
}

/**
 * Why the two documents of this state cannot be built or put in canonical
 * form, which is what signing does first; null when they can. The canonical
 * form refuses what JSON cannot carry alike everywhere: a number past 2^53,
 * a string with half a surrogate pair. Both can arrive in an act (a date, a
 * reason_text, a row's name), and neither is seen before the bytes are made.
 */
export function unsignable(state, { now, seedLoaders, members }) {
  try {
    const keyId = "games-current";
    signingDigest(INDEX_SCHEMA, buildIndexBody({ state, seedLoaders, issuedAt: now, keyId, members }));
    signingDigest(WITHDRAWN_SCHEMA, buildWithdrawnBody({ state, issuedAt: now, keyId }));
    return null;
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
}

/**
 * One act on a copy of the state: the copy and the act's summary, or why
 * the act is refused. Everything signing would stop on because of THIS act
 * is found here, where it costs one refused act and not the run: applying
 * it throws (ActRefused: no second free for its row; or anything else), the
 * withdrawn list would break its own rules, or the documents could no
 * longer be built and canonicalised. A state that already could not be
 * signed is not this act's doing: the act is applied and the run stops at
 * signing, as it would have without it, so the service serves the act again.
 */
export function tryAct(act, state, { now, reserved, seedLoaders, members, previous }) {
  const trial = structuredClone(state);
  let summary;
  try {
    summary = applyAct(act, trial, { now, reserved });
  } catch (e) {
    return { problems: [e instanceof ActRefused ? e.message : `applied to a copy of the state, this act stopped the signer: ${e instanceof Error ? e.message : String(e)}`] };
  }
  // The documents first: building them is what the list's rules read, so a
  // state they cannot be built from is found here, inside the catch.
  const cannot = unsignable(trial, { now, seedLoaders, members });
  if (cannot !== null && unsignable(state, { now, seedLoaders, members }) === null) {
    return { problems: [`applied, this act would leave documents that cannot be signed: ${cannot}`] };
  }
  const broke = listProblemsIntroduced(state, trial, now, previous);
  if (broke.length) return { problems: broke.map((b) => `applied, this act would leave a withdrawn list the signer refuses to sign: ${b}`) };
  return { state: trial, summary };
}

/**
 * @param {{dataDir: string, root: string, env: object, now: number, trustFile: string, roots?: object,
 *          candidates?: object[], acts?: object[], health?: object, members?: object}} o
 *   `roots` is for tests only: production verifies trust.json under the compiled roots.
 * @returns {{accepted: object[], acts: object[], duplicateActs: {ref, type, seq}[], admitted: object[], issuedAt: number, keyId: string,
 *            refusedActs: {ref, type, problems}[]}}
 *   keyId is the primary signer's key id (comma-separated if the schemas' differ): the
 *   sign-result's `key_id`, which the service bounds to 64 bytes. signedBy names every
 *   key that signed, per schema, the primary first. warnings: things that signed but
 *   need a person (signing.mjs droppedCoSigners).
 *   An act whose confirmation ref is already recorded is a duplicate: not
 *   applied again, and answered with the seq it was applied under.
 */
export function runSign({ dataDir, root, env, now, trustFile, roots, candidates = [], acts = [], health, members }) {
  const policy = loadPolicy(root);
  let state = loadState(dataDir);
  const reserved = loadReserved();
  // Refuse to sign before touching anything: a trust.json that does not
  // verify under the compiled roots or carries no games kind keys, no key, a
  // spent key, or a key trust.json does not authorise ends the run with the
  // state unchanged.
  const { kindKeys } = loadTrust({ file: trustFile, now, ...(roots ? { roots } : {}) });
  // documents beside no floors.json: the floors and the spent ledger were lost,
  // and reading that as "nothing signed, nothing spent" would let a spent key
  // sign alone again (signing.mjs spentLedger refuses the other ways to lose it)
  if (fs.existsSync(path.join(dataDir, "dist", "games-index.json")) && !fs.existsSync(path.join(dataDir, "floors.json"))) {
    throw new SignRefused("E_STATE_SPENT", "dist/ holds signed documents and floors.json is missing; refusing to guess which keys are spent");
  }
  // the signers per document schema, by each seed's role in trust.json: a key
  // is spent per schema, and a spent key only ever co-signs (signing.mjs)
  const signers = selectSigners({ env, floors: state.floors, kindKeys, now });
  // the list published last, before anything in the state moves
  const previous = lastWithdrawn({ dataDir, state, kindKeys });

  if (health !== undefined) state.health = checkHealth(health);
  // one schemalite process for every candidate's entry
  const withEntry = candidates.filter((c) => c?.entry);
  const shapes = new Map(validateEntries(withEntry.map((c) => c.entry)).map((r, i) => [withEntry[i], r]));
  const accepted = candidates.map((c) => ({ request: c?.request ?? null, ...acceptCandidate(c, state, { reserved, now, shape: shapes.get(c) ?? null }) }));

  const applied = [];
  const refusedActs = [];
  const duplicateActs = [];
  let seq = nextActSeq(dataDir);
  const records = [];
  // by confirmation ref: what data already records, and what this run applies
  const done = appliedRefs(state.acts);
  for (const act of acts) {
    const ref = typeof act?.confirmation?.ref === "string" ? act.confirmation.ref : null;
    if (ref !== null && done.has(ref)) {
      duplicateActs.push({ ref, type: act?.type ?? null, seq: done.get(ref) });
      continue;
    }
    const problems = actProblems(act, state, { now });
    if (problems.length) {
      refusedActs.push({ ref, type: act?.type ?? null, problems });
      continue;
    }
    // Applied to a copy first. An act that leaves a withdrawn list this
    // signer would refuse to sign must be REFUSED, with the reason, and the
    // run go on without it: applied and then failing the run's own
    // verification, it ends the run with no report, the service serves the
    // act again, and no act is signed after it until somebody removes it.
    const tried = tryAct(act, state, { now, reserved, seedLoaders: policy.loaders, members, previous });
    if (tried.problems) {
      refusedActs.push({ ref, type: act?.type ?? null, problems: tried.problems });
      continue;
    }
    state = tried.state;
    const summary = tried.summary;
    const record = { ...act, seq, applied_at: now, summary };
    records.push(record);
    applied.push(record);
    done.set(ref, seq);
    seq += 1;
  }

  const admitted = admitHeld(state, now);
  const signed = signBoth({ state, seedLoaders: policy.loaders, signers, kindKeys, now, previous, members });

  state.floors = signed.floors;
  saveState(dataDir, state);
  for (const r of records) saveAct(dataDir, r);
  writeJson(path.join(dataDir, "dist", "games-index.json"), signed.index);
  writeJson(path.join(dataDir, "dist", "games-withdrawn.json"), signed.withdrawn);
  return { accepted, acts: applied, duplicateActs, admitted, issuedAt: signed.issuedAt, keyId: [...new Set(Object.values(signers).map((s) => s.key_id))].join(","),
    signedBy: signed.signedBy, warnings: [...new Set(Object.values(signers).flatMap((s) => s.warnings ?? []))], refusedActs };
}
