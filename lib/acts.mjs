// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Moderator acts, as data.
//
// An act is one JSON document, `astra.games.act/1`, made by the plugins
// service after the moderator's one console 2FA (merged §3.2 lane C; lane C
// design §1.4) and pulled by sign.yml's `work` job (GET bot/games/work) —
// the service cannot push it here. The signer validates it, records it as acts/<seq>.json on the
// `data` branch — the public, append-only record of every decision — applies
// it to the state, and re-signs BOTH documents in the same run. No act
// edits a document directly; the documents are always rebuilt from state.
//
//   {
//     "schema": "astra.games.act/1",
//     "type": "M_REVOKE",
//     "at": 1798675100,
//     "by": { "account": "mod-7" },
//     "confirmation": { "kind": "console-2fa", "ref": "<the service's act id>" },
//     ...the type's payload
//   }
//
// The confirmation is checked for presence and shape here; the site and the
// plugins service own the 2FA itself. Its ref is the act's identity: an act
// already recorded under it is never applied again (appliedRefs).
//
// Types:
//   withdrawals   M_YANK  M_DELIST  M_DEPRECATE  M_REVOKE         (A§4.4, merged §2.2)
//   rows          M_GAMES_EDIT  M_ANTICHEAT_EDIT  M_LOADERS_EDIT   (A§5.3, R33)
//   review        M_MARK_SOURCE_REVIEWED                           (R19)
//   codes         M_REASSIGN_ENGINE_CODE  M_ADOPT_ENGINE_CODE      (merged §2.1, §5.2)
//   foundations   M_SET_UNMAINTAINED  M_SET_RECOMMENDED_FOUNDATION (merged §5.2)
//   releases      M_PROMOTE (a first-party prerelease → listed)  M_RELEASE_HOLD

import { acceptCandidate } from "./accept.mjs";
import { entryIdsInRepo } from "./model.mjs";
import { descriptorCodes, foldCode, identityOf, sameIdentity } from "./rules.mjs";
import { validateMany } from "./schemas.mjs";
import { exactRange, parseRange, satisfies } from "./semver.mjs";

export const ACT_SCHEMA = "astra.games.act/1";
export const WITHDRAWAL_ACTS = Object.freeze({ M_YANK: "yank", M_DELIST: "delist", M_DEPRECATE: "deprecate", M_REVOKE: "revoke" });
/** What an old client applies when it does not know the act (games-withdrawn-v1.md §4). */
export const FLOOR_EFFECT = Object.freeze({ yank: "no-offer", delist: "no-offer", deprecate: "no-offer", revoke: "no-play" });
export const REASON_CODES = Object.freeze(["security", "broken", "author-request", "rights-holder", "policy"]);
/** A§4.4: the games catalogue's limit of takedowns in any trailing 24 hours. */
export const TAKEDOWN_LIMIT = 3;
export const TAKEDOWN_WINDOW = 86400;
export const TAKEDOWN_ACTS = Object.freeze(["yank", "delist", "revoke"]);

export const ACT_TYPES = Object.freeze([
  ...Object.keys(WITHDRAWAL_ACTS),
  "M_GAMES_EDIT", "M_ANTICHEAT_EDIT", "M_LOADERS_EDIT",
  "M_MARK_SOURCE_REVIEWED",
  "M_REASSIGN_ENGINE_CODE", "M_ADOPT_ENGINE_CODE",
  "M_SET_UNMAINTAINED", "M_SET_RECOMMENDED_FOUNDATION",
  "M_PROMOTE", "M_RELEASE_HOLD",
]);

const HEX64 = /^[0-9a-f]{64}$/;
const isStr = (v, max = 2000) => typeof v === "string" && v.length > 0 && v.length <= max;
const isId = (v) => Number.isSafeInteger(v) && v > 0;

function listedEntry(state, entryId) {
  return state.entries.find((e) => e.entry.id === entryId && e.meta.status === "listed") ?? null;
}

function foundationClaims(e, code) {
  const f = foldCode(code);
  return e.entry.kind === "foundation" && (
    (e.entry.target?.engine && foldCode(e.entry.target.engine) === f) ||
    (e.entry.descriptor && descriptorCodes(e.entry.descriptor).some((c) => foldCode(c) === f))
  );
}

/** The row-shaped checks an S schema can make, through schemalite (a minimal index around the row). */
function rowShape(kind, row) {
  const doc = { schema: "astra.games.index/1", serial: 0, issued_at: 0, expires_at: 0, key_id: "games-current", entries: [], games: [] };
  if (kind === "games") doc.games = [row];
  if (kind === "anticheat") doc.anticheat = [row];
  if (kind === "loaders") doc.loaders = [row];
  return validateMany([{ schema: "games-index-v1", doc }])[0];
}

/** @returns {string[]} why this act cannot be applied to this state; empty when it can */
export function actProblems(act, state) {
  const p = [];
  if (!act || typeof act !== "object") return ["an act is a JSON object"];
  if (act.schema !== ACT_SCHEMA) p.push(`schema is not ${ACT_SCHEMA}`);
  if (!ACT_TYPES.includes(act.type)) return [...p, `unknown act type ${JSON.stringify(act.type)}`];
  if (!Number.isSafeInteger(act.at) || act.at <= 0) p.push("at is not Unix seconds");
  if (!isStr(act.by?.account, 64)) p.push("by.account is missing");
  if (act.confirmation?.kind !== "console-2fa" || !isStr(act.confirmation?.ref, 200)) {
    p.push("confirmation is not {kind: console-2fa, ref}: every act carries the moderator's one console confirmation");
  }

  const t = act.type;
  if (t in WITHDRAWAL_ACTS) {
    if (!isId(act.repo_id)) p.push("repo_id is not a repository id");
    if (!isStr(act.versions, 200) || !parseRange(act.versions)) p.push(`versions ${JSON.stringify(act.versions)} is not a range this catalogue reads (*, comparators, ||)`);
    if (!REASON_CODES.includes(act.reason_code)) p.push(`reason_code ${JSON.stringify(act.reason_code)} is not one of ${REASON_CODES.join(", ")}`);
    if (act.reason_code === "security" && t !== "M_REVOKE") p.push("a security reason is always a revoke (games-withdrawn-v1.md §2.1)");
    if (act.reason_text !== undefined && typeof act.reason_text !== "string") p.push("reason_text is not a string");
    const ids = entryIdsInRepo(state.entries, act.repo_id);
    if (act.entry_id !== undefined && !isStr(act.entry_id, 200)) p.push("entry_id is not a string");
    if (act.entry_id === undefined && ids.length > 1) p.push(`repository ${act.repo_id} hosts ${ids.length} entries (${ids.join(", ")}); name entry_id (R43)`);
    if (act.entry_id !== undefined && ids.length && !ids.includes(act.entry_id)) p.push(`${act.entry_id} is not an entry of repository ${act.repo_id}`);
    if (act.cascade !== undefined) {
      if (t !== "M_REVOKE") p.push("only a revoke cascades");
      if (!Array.isArray(act.cascade?.revoke) || !act.cascade.revoke.every((x) => isStr(x, 200))) p.push("cascade is {revoke: [entry ids]}");
    }
    if (act.break_glass !== undefined && typeof act.break_glass !== "boolean") p.push("break_glass is a boolean");
  } else if (t === "M_GAMES_EDIT") {
    if (!["upsert", "delete"].includes(act.op)) p.push("op is upsert or delete");
    if (act.op === "upsert") {
      const s = rowShape("games", act.row);
      if (!s.ok) p.push(`row: ${s.error}`);
      if (act.row && "engine" in act.row && act.row.engine !== null && !["none"].includes(act.row.engine) && !/^[a-z][a-z0-9-]{1,31}$/.test(String(act.row.engine))) {
        p.push("row.engine is an engine code or \"none\"");
      }
    } else if (act.op === "delete" && !isId(act.id)) p.push("delete names the Steam id");
  } else if (t === "M_ANTICHEAT_EDIT") {
    if (!["add", "remove"].includes(act.op)) p.push("op is add or remove");
    const s = rowShape("anticheat", act.row);
    if (!s.ok) p.push(`row: ${s.error}`);
  } else if (t === "M_LOADERS_EDIT") {
    if (!["add", "remove"].includes(act.op)) p.push("op is add or remove");
    if (act.op === "add") {
      const s = rowShape("loaders", { name: act.row?.name, sha256: act.row?.sha256, default_enabled: false });
      if (!s.ok) p.push(`row: ${s.error}`);
    } else if (!HEX64.test(String(act.row?.sha256 ?? ""))) p.push("remove names a sha256");
  } else if (t === "M_MARK_SOURCE_REVIEWED") {
    const e = state.entries.find((x) => x.entry.id === act.entry_id && x.entry.version === act.version);
    if (!e) p.push(`${act.entry_id} ${act.version} is not in the catalogue`);
  } else if (t === "M_REASSIGN_ENGINE_CODE") {
    const owned = Object.keys(state.engineCodes).find((c) => foldCode(c) === foldCode(act.code ?? ""));
    if (!owned) p.push(`${act.code} has no owner to reassign from`);
    const to = act.to;
    if (!to || !isStr(to.account, 64) || !isId(to.repo_id) || !isId(to.repo_owner_id)) p.push("to is {account, repo_id, repo_owner_id}");
    else if (!state.entries.some((e) => e.entry.kind === "foundation" && e.meta.status === "listed" && sameIdentity(e.entry.publisher, to))) {
      p.push("to publishes no listed foundation; a code moves to a publisher that can ship its descriptor");
    }
    if (!isStr(act.reason_text, 2000)) p.push("reason_text says why (the transparency log shows it)");
  } else if (t === "M_ADOPT_ENGINE_CODE") {
    // merged §5.2 (2): admitted only when the act cites ALL of (a), (b) and (c).
    const owned = Object.keys(state.engineCodes).find((c) => foldCode(c) === foldCode(act.code ?? ""));
    if (!owned) p.push(`${act.code} has no owner to adopt from`);
    const ev = act.evidence ?? {};
    if (!Array.isArray(ev.unanswered_reports) || ev.unanswered_reports.length < 1 || !ev.unanswered_reports.every((x) => isStr(x, 200))) {
      p.push("(a) evidence.unanswered_reports cites at least one report the old publisher left unanswered");
    }
    if (!["probe", "reports"].includes(ev.descriptor_failure?.kind) || !Array.isArray(ev.descriptor_failure?.refs) || ev.descriptor_failure.refs.length < 1) {
      p.push("(b) evidence.descriptor_failure is {kind: probe|reports, refs: [≥1]}: the descriptor fails on a current build of a game it claims");
    }
    const succ = listedEntry(state, act.successor_entry_id);
    if (!succ || !foundationClaims(succ, act.code ?? "")) p.push(`(c) ${act.successor_entry_id} is not a listed foundation for ${act.code}`);
    if (ev.successor_probe !== "pass") p.push("(c) evidence.successor_probe is \"pass\": the successor passes gi-probe");
    if (!Number.isSafeInteger(ev.successor_installs_without_failure) || ev.successor_installs_without_failure < 1) {
      p.push("(c) evidence.successor_installs_without_failure is at least 1");
    }
    if (succ && owned && sameIdentity(succ.entry.publisher, state.engineCodes[owned])) p.push("the successor already owns the code");
  } else if (t === "M_SET_UNMAINTAINED") {
    const e = listedEntry(state, act.entry_id);
    if (!e || e.entry.kind !== "foundation") p.push(`${act.entry_id} is not a listed foundation`);
    if (typeof act.unmaintained !== "boolean") p.push("unmaintained is a boolean");
    if (act.successor_entry_id != null && !listedEntry(state, act.successor_entry_id)) p.push(`${act.successor_entry_id} is not listed`);
  } else if (t === "M_SET_RECOMMENDED_FOUNDATION") {
    if (!/^[a-z][a-z0-9-]{1,31}$/.test(String(act.code ?? ""))) p.push("code is an engine code");
    if (act.entry_id !== null) {
      const e = listedEntry(state, act.entry_id);
      if (!e || !foundationClaims(e, act.code ?? "")) p.push(`${act.entry_id} is not a listed foundation for ${act.code}`);
    }
  } else if (t === "M_PROMOTE") {
    const e = state.entries.find((x) => x.entry.id === act.entry_id && x.entry.version === act.version);
    if (!e) p.push(`${act.entry_id} ${act.version} is not in the catalogue`);
    else if (e.meta.status !== "prerelease") p.push(`${act.entry_id} ${act.version} is ${e.meta.status}, not a prerelease`);
    else if (!e.meta.first_party) p.push("only first-party prereleases are ingested and promoted (A§5.2 step 8)");
  } else if (t === "M_RELEASE_HOLD") {
    if (!state.holds.some((h) => h.hold_id === act.hold_id)) p.push(`no hold ${JSON.stringify(act.hold_id)}`);
    if (!["accept", "refuse"].includes(act.decision)) p.push("decision is accept or refuse");
  }
  return p;
}

// ── one act, once ─────────────────────────────────────────────────────────

/**
 * The confirmation ref of every act already recorded, to its seq. The
 * service re-serves an act until a sign result names it (design §1.4), so a
 * run whose report never landed sees the same act again: by its ref it is
 * answered "applied, seq N" and NOT applied twice — a second revoke would
 * spend a second takedown unit, a second M_RELEASE_HOLD would find no hold.
 */
export function appliedRefs(recorded) {
  const out = new Map();
  for (const a of recorded ?? []) {
    const ref = a?.confirmation?.ref;
    if (typeof ref === "string" && !out.has(ref)) out.set(ref, Number(a.seq));
  }
  return out;
}

// ── the takedown bound (A§4.4) ────────────────────────────────────────────

const unitOf = (row) => `${row.repo_id}#${row.entry_id ?? "*"}`;

function unitsInWindow(state, now) {
  return new Set(state.withdrawn.rows.filter((r) => TAKEDOWN_ACTS.includes(r.act) && r.at > now - TAKEDOWN_WINDOW).map(unitOf));
}

/**
 * Add rows, spending the bound: a takedown (yank, delist, revoke) costs one
 * unit per (repository, entry) in the trailing 24 hours, each dependant in
 * its OWN repository. A unit already spent in the window costs nothing again.
 * Over the bound a row is HELD — it waits in withdrawn.held and is admitted,
 * oldest first, by a later run (resign.yml runs daily, sign.yml on every
 * change) — unless the act carries break_glass. A deprecation is a banner,
 * not a takedown, and is never held.
 */
function addRows(state, rows, { now, breakGlass }) {
  const out = { applied: [], held: [] };
  for (const row of rows) {
    if (TAKEDOWN_ACTS.includes(row.act) && !breakGlass) {
      const used = unitsInWindow(state, now);
      if (!used.has(unitOf(row)) && used.size >= TAKEDOWN_LIMIT) {
        state.withdrawn.held.push({ row, held_at: now });
        out.held.push(row);
        continue;
      }
    }
    state.withdrawn.rows.push({ ...row, at: row.at ?? now });
    out.applied.push(row);
  }
  return out;
}

/** Admit held takedowns while the window has room, oldest first. */
export function admitHeld(state, now) {
  const admitted = [];
  const still = [];
  for (const h of [...state.withdrawn.held].sort((a, b) => a.held_at - b.held_at)) {
    const used = unitsInWindow(state, now);
    if (used.has(unitOf(h.row)) || used.size < TAKEDOWN_LIMIT) {
      state.withdrawn.rows.push({ ...h.row, at: now });
      admitted.push(h.row);
    } else still.push(h);
  }
  state.withdrawn.held = still;
  return admitted;
}

// ── the foundation cascade (A§4.4 M3) ─────────────────────────────────────

/**
 * Entries built on the revoked foundation releases: those whose
 * `foundation` claim names the foundation's manifest id at a revoked
 * version, or whose computed built_on names the revoked entry and version.
 */
export function dependantsOf(state, revoked) {
  const byId = new Map();
  for (const f of revoked) {
    for (const e of state.entries) {
      if (e.entry.id === f.entry.id) continue;
      const claim = e.entry.foundation;
      const hit =
        (claim && claim.id === f.meta.manifest_id && claim.version === f.entry.version) ||
        (e.entry.built_on && e.entry.built_on.entry === f.entry.id && e.entry.built_on.version === f.entry.version);
      if (!hit) continue;
      const k = e.entry.id;
      if (!byId.has(k)) byId.set(k, { entry_id: k, repo_id: e.entry.source.repo_id, versions: [] });
      byId.get(k).versions.push(e.entry.version);
    }
  }
  return [...byId.values()];
}

// ── apply ─────────────────────────────────────────────────────────────────

/**
 * Apply one valid act to the state. Returns a summary for the run log; the
 * caller records the act and re-signs both documents.
 */
export function applyAct(act, state, { now, reserved }) {
  const t = act.type;
  if (t in WITHDRAWAL_ACTS) {
    const kind = WITHDRAWAL_ACTS[t];
    const base = { repo_id: act.repo_id, versions: act.versions, act: kind, floor_effect: FLOOR_EFFECT[kind], reason_code: act.reason_code, at: act.at };
    if (act.entry_id) base.entry_id = act.entry_id;
    if (act.reason_text) base.reason_text = act.reason_text;
    const rows = [base];
    if (kind === "revoke") {
      const revoked = state.entries.filter(
        (e) => e.entry.kind === "foundation" && Number(e.entry.source.repo_id) === act.repo_id &&
          (!act.entry_id || e.entry.id === act.entry_id) && satisfies(e.entry.version, act.versions),
      );
      const explicit = new Set(act.cascade?.revoke ?? []);
      for (const d of dependantsOf(state, revoked)) {
        const versions = exactRange(d.versions);
        const entry_id = d.entry_id; // always named: a dependant's repo may host several
        if (explicit.has(d.entry_id)) {
          rows.push({ repo_id: d.repo_id, versions, entry_id, act: "revoke", floor_effect: "no-play", reason_code: act.reason_code, reason_text: `Revoked with the foundation it is built on. ${act.reason_text ?? ""}`.trim(), at: act.at });
        } else {
          // The default: a banner plus a yank (A§4.4 M3). Installed copies keep working.
          const reason_code = act.reason_code === "security" ? "policy" : act.reason_code;
          const text = `Built on a foundation release that was revoked (${revoked.map((f) => `${f.entry.id} ${f.entry.version}`).join(", ")}).`;
          rows.push({ repo_id: d.repo_id, versions, entry_id, act: "deprecate", floor_effect: "no-offer", reason_code, reason_text: text, at: act.at });
          rows.push({ repo_id: d.repo_id, versions, entry_id, act: "yank", floor_effect: "no-offer", reason_code, reason_text: text, at: act.at });
        }
      }
    }
    const r = addRows(state, rows, { now, breakGlass: act.break_glass === true });
    return { applied: r.applied.length, held: r.held.length };
  }
  if (t === "M_GAMES_EDIT") {
    const id = act.op === "upsert" ? Number(act.row.id) : Number(act.id);
    state.moderation.games = state.moderation.games.filter((g) => Number(g.id) !== id);
    if (act.op === "upsert") state.moderation.games.push({ ...act.row, store: "steam", id });
    return { games: state.moderation.games.length };
  }
  if (t === "M_ANTICHEAT_EDIT") {
    const key = (r) => `${r.kind}\u0000${r.value}`;
    state.moderation.anticheat = state.moderation.anticheat.filter((r) => key(r) !== key(act.row));
    if (act.op === "add") state.moderation.anticheat.push({ name: act.row.name, kind: act.row.kind, value: act.row.value });
    return { anticheat: state.moderation.anticheat.length };
  }
  if (t === "M_LOADERS_EDIT") {
    const sha = String(act.row.sha256).toLowerCase();
    const l = state.moderation.loaders;
    l.add = l.add.filter((r) => r.sha256 !== sha);
    l.remove = l.remove.filter((s) => s !== sha);
    if (act.op === "add") l.add.push({ name: act.row.name, sha256: sha, default_enabled: false });
    else l.remove.push(sha);
    return { loaders: { add: l.add.length, remove: l.remove.length } };
  }
  if (t === "M_MARK_SOURCE_REVIEWED") {
    const e = state.entries.find((x) => x.entry.id === act.entry_id && x.entry.version === act.version);
    const row = { entry_id: act.entry_id, version: act.version, sha256: e.entry.source.sha256, at: act.at, by: act.by.account };
    state.moderation.reviewed = state.moderation.reviewed.filter((r) => !(r.entry_id === act.entry_id && r.version === act.version));
    state.moderation.reviewed.push(row);
    return { reviewed: `${act.entry_id} ${act.version}` };
  }
  if (t === "M_REASSIGN_ENGINE_CODE") {
    const code = Object.keys(state.engineCodes).find((c) => foldCode(c) === foldCode(act.code));
    state.engineCodes[code] = identityOf(act.to);
    // the squatter's descriptor stops being served; the new owner ships its own
    delete (state.moderation.descriptor_moves ??= {})[code];
    return { code, to: act.to.account };
  }
  if (t === "M_ADOPT_ENGINE_CODE") {
    const code = Object.keys(state.engineCodes).find((c) => foldCode(c) === foldCode(act.code));
    const old = state.engineCodes[code];
    const succ = listedEntry(state, act.successor_entry_id);
    // the old owner's latest descriptor moves with the code, whole
    const oldWithDescriptor = state.entries
      .filter((e) => e.entry.descriptor && sameIdentity(e.entry.publisher, old) && descriptorCodes(e.entry.descriptor).some((c) => foldCode(c) === foldCode(code)))
      .sort((a, b) => (a.meta.released_at ?? 0) - (b.meta.released_at ?? 0));
    const src = oldWithDescriptor[oldWithDescriptor.length - 1];
    const moved = new Set(src ? descriptorCodes(src.entry.descriptor).map((c) => Object.keys(state.engineCodes).find((k) => foldCode(k) === foldCode(c)) ?? c) : [code]);
    for (const c of moved) state.engineCodes[c] = identityOf(succ.entry.publisher);
    state.moderation.descriptor_moves ??= {};
    if (src) state.moderation.descriptor_moves[code] = { to_entry_id: succ.entry.id, descriptor: src.entry.descriptor, descriptor_sha256: src.entry.descriptor_sha256, from_entry_id: src.entry.id, at: act.at };
    // every old-owner foundation for the code: unmaintained, pointing at the successor (merged §5.2 (3))
    for (const e of state.entries) {
      if (e.entry.kind === "foundation" && sameIdentity(e.entry.publisher, old) && foundationClaims(e, code)) {
        state.moderation.foundations[e.entry.id] = { unmaintained: true, successor_entry_id: succ.entry.id };
      }
    }
    return { code, moved: [...moved], from: old.account, to: succ.entry.publisher.account };
  }
  if (t === "M_SET_UNMAINTAINED") {
    state.moderation.foundations[act.entry_id] = { unmaintained: act.unmaintained, successor_entry_id: act.successor_entry_id ?? null };
    return { entry_id: act.entry_id, unmaintained: act.unmaintained };
  }
  if (t === "M_SET_RECOMMENDED_FOUNDATION") {
    if (act.entry_id === null) delete state.moderation.recommended_foundations[act.code];
    else state.moderation.recommended_foundations[act.code] = act.entry_id;
    return { code: act.code, entry_id: act.entry_id };
  }
  if (t === "M_PROMOTE") {
    const e = state.entries.find((x) => x.entry.id === act.entry_id && x.entry.version === act.version);
    e.meta.status = "listed";
    e.meta.promoted_at = act.at;
    return { promoted: `${act.entry_id} ${act.version}` };
  }
  if (t === "M_RELEASE_HOLD") {
    const h = state.holds.find((x) => x.hold_id === act.hold_id);
    state.holds = state.holds.filter((x) => x.hold_id !== act.hold_id);
    if (act.decision === "refuse") return { hold: act.hold_id, decision: "refuse" };
    // Accepting a change of hands rebinds the repository to who holds it NOW:
    // installed users see it as `changed_hands` and are asked again (merged §2.3).
    const c = structuredClone(h.candidate);
    const src = c.entry.source;
    const account = c.meta?.claimant?.account ?? c.meta?.binding?.account ?? c.entry.publisher.account;
    c.entry.publisher = { account, repo_id: src.repo_id, repo_owner_id: src.repo_owner_id };
    c.verdict = "accept";
    c.findings = c.findings.filter((f) => !/^(H_|R_)/.test(f.code));
    if (!c.meta.first_party) {
      state.bindings[String(src.repo_id)] = { ...c.entry.publisher, binding_token: c.meta?.claimant?.binding_token ?? c.meta?.binding?.binding_token ?? null, bound_at: now };
    }
    for (const [code, who] of Object.entries(state.engineCodes)) {
      if (Number(who.repo_id) === Number(src.repo_id)) state.engineCodes[code] = { ...c.entry.publisher };
    }
    const r = acceptCandidate(c, state, { reserved, now, releasedBy: act.by.account });
    return { hold: act.hold_id, decision: "accept", result: r.result, reason: r.reason };
  }
  throw new Error(`no applier for ${t}`);
}
