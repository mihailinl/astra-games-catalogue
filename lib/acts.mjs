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
//   lifts         M_LIFT (a withdrawal row leaves the list, and a signed lift says so:
//                 the only thing that ends a security revoke on a client)
//                                                    (games-withdrawn-v1.md §2.2)

import { acceptCandidate } from "./accept.mjs";
import { clientEntryId, entryIdsInRepo, entryKey, isSticky, LIFT_KEEP_SECONDS, liftAppliedAt, liftIsSticky, LIFTS_MAX, subjectKey } from "./model.mjs";
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
/** Lifts of security revokes in any trailing 24 hours, by when the signer applies them. The fourth is refused, never held. */
export const LIFT_LIMIT = 3;
/** A lift of a security revoke stays in the list at least this long (lib/model.mjs, where the list's own rules read it too). */
export { LIFT_KEEP_SECONDS };
/**
 * How far an act's `at` may run ahead of the signer's clock, for EVERY act
 * type. The catalogue had no such number (MAX_AHEAD_SECONDS is a client's
 * tolerance for a document's issued_at, a day); five minutes covers two
 * machines' clocks. A withdrawal dated later than that would be published
 * and could then never be lifted: its lift needs `lifts_at <= at <= clock`.
 */
export const ACT_CLOCK_SKEW = 300;
/**
 * From here on an `at` is a millisecond timestamp somebody forgot to divide
 * (10^11 seconds is the year 5138; 10^11 milliseconds was March 1973).
 */
export const AT_SECONDS_BELOW = 1e11;
/** What a withdrawal row's `act` may be, and so what a lift's `kinds` may name. */
export const ROW_KINDS = Object.freeze(["yank", "delist", "deprecate", "revoke"]);
/** An act the state cannot take, found only while applying it. The run refuses the act and goes on. */
export class ActRefused extends Error {}
export const TAKEDOWN_WINDOW = 86400;
export const TAKEDOWN_ACTS = Object.freeze(["yank", "delist", "revoke"]);

export const ACT_TYPES = Object.freeze([
  ...Object.keys(WITHDRAWAL_ACTS),
  "M_GAMES_EDIT", "M_ANTICHEAT_EDIT", "M_LOADERS_EDIT",
  "M_MARK_SOURCE_REVIEWED",
  "M_REASSIGN_ENGINE_CODE", "M_ADOPT_ENGINE_CODE",
  "M_SET_UNMAINTAINED", "M_SET_RECOMMENDED_FOUNDATION",
  "M_PROMOTE", "M_RELEASE_HOLD",
  "M_LIFT",
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

// ── lifts (games-withdrawn-v1.md §2.2) ────────────────────────────────────

// What makes a row sticky, and how a lift's record is read (sticky unless it
// says not, aged from when the signer applied it), is in lib/model.mjs: the
// list's rule across two issues (documents.mjs successorProblems) reads both.
export { isSticky };

/**
 * A lift against rows, one member at a time: the rows of its repository, of
 * those the ones with its entry_id, of those the ones with its versions, of
 * those the ones whose `at` is its `lifts_at`. Subjects are compared as a
 * CLIENT reads them (lib/model.mjs): entry_id trimmed and lowercased, none
 * equal to none only, versions byte for byte. The one narrowing serves the
 * refusal (which member matched nothing) and the removal (what is named).
 */
function narrow(rows, lift) {
  const entry = entryKey(lift);
  const inRepo = rows.filter((r) => Number(r.repo_id) === lift.repo_id);
  const ofEntry = entry === null ? [] : inRepo.filter((r) => entryKey(r) === entry);
  const ofVersions = ofEntry.filter((r) => r.versions === lift.versions);
  const named = ofVersions.filter((r) => r.at === lift.lifts_at);
  return { inRepo, ofEntry, ofVersions, named };
}

/**
 * The rows a lift names: every row of that subject carrying that second.
 * The signer never lets two acts' rows share both (freeSecond), so that is
 * what ONE act wrote for the subject: one row, or the banner and the yank
 * of a foundation cascade.
 */
export function rowsNamedBy(rows, lift) {
  return narrow(rows, lift).named;
}

const heldRows = (withdrawn) => (withdrawn.held ?? []).map((h) => h.row);
const quoted = (values) => [...new Set(values)].map((v) => (v === undefined ? "none" : JSON.stringify(v))).join(", ");

/** The kinds of the rows and held takedowns a lift names, distinct and sorted: what its `kinds` must equal. */
function kindsNamedBy(withdrawn, lift) {
  return [...new Set(rowsNamedBy([...withdrawn.rows, ...heldRows(withdrawn)], lift).map((r) => r.act))].sort();
}

/**
 * Why a lift names nothing, by the first member that matches nothing; null
 * when it names a row of the list or a takedown still held over the bound.
 */
function liftMismatch(withdrawn, act) {
  const { inRepo, ofEntry, ofVersions, named } = narrow([...withdrawn.rows, ...heldRows(withdrawn)], act);
  if (!inRepo.length) return `repo_id ${act.repo_id} has no row to lift, in the list or held`;
  if (!ofEntry.length) return `entry_id ${quoted([act.entry_id])} matches no row of repository ${act.repo_id}; its rows name ${quoted(inRepo.map((r) => r.entry_id))}`;
  if (!ofVersions.length) return `versions ${JSON.stringify(act.versions)} matches no row of that subject as written; its rows carry ${quoted(ofEntry.map((r) => r.versions))}`;
  if (!named.length) return `lifts_at ${act.lifts_at} matches no row of that subject; its rows were taken at ${quoted(ofVersions.map((r) => r.at))}`;
  return null;
}

/**
 * Which lifts stay when the list is over LIFTS_MAX. A lift of a row that was
 * not sticky goes first, oldest first: no client needs it, the row's absence
 * already released the act. Then a lift of a security revoke older than
 * LIFT_KEEP_SECONDS, oldest first. A younger one is never dropped: the act
 * that would need its place is refused instead (actProblems).
 *
 * A lift's age is counted from when the signer APPLIED it, never from its
 * own `at`: a lift may honestly be dated long ago (`at` is only bounded
 * from above), and one aged by that date would be accepted and dropped in
 * the same run, never published.
 */
export function retainLifts(lifts, now) {
  const kept = [...lifts];
  const oldest = (xs) => xs.sort((a, b) => liftAppliedAt(a) - liftAppliedAt(b) || a.at - b.at || a.lifts_at - b.lifts_at)[0];
  while (kept.length > LIFTS_MAX) {
    const drop = oldest(kept.filter((l) => !liftIsSticky(l))) ?? oldest(kept.filter((l) => liftAppliedAt(l) <= now - LIFT_KEEP_SECONDS));
    if (!drop) break;
    kept.splice(kept.indexOf(drop), 1);
  }
  return kept;
}

/**
 * Why an entry_id cannot be written into a row or a lift; null when every
 * client reads it the same way (or there is none).
 *
 * Unreadable (empty once trimmed, a control character) is the client's own
 * rule. The second refusal is the signer's: lowercase comes from each
 * reader's Unicode tables, and those differ between versions for recently
 * added letters (Node 26.13 and rustc 1.99 agree on every code point;
 * Python 3's older tables differ from both on 28). A character that is
 * already lowercase stays so in every version, so that is the only kind of
 * non-ASCII character an act may carry. Catalogue entry ids are ASCII
 * (`<login>/<slug>`), so this refuses nothing a real id needs.
 */
function entryIdProblem(raw) {
  const e = clientEntryId(raw);
  if (e.unreadable) return `entry_id is not an id a client can read: ${e.unreadable}`;
  if (e.none) return null;
  for (const ch of raw) {
    const cp = ch.codePointAt(0);
    if (cp <= 0x7f) continue;
    const unassigned = /\p{Cn}/u.test(ch);
    if (unassigned || ch.toLowerCase() !== ch) {
      return `entry_id holds a non-ASCII character that is not already lowercase (U+${cp.toString(16).toUpperCase().padStart(4, "0")}${unassigned ? ", unassigned" : ""}): a client lowercases an id by its own Unicode tables, which may not be the signer's; write the id in lowercase`;
    }
  }
  return null;
}

/** The row-shaped checks an S schema can make, through schemalite (a minimal index around the row). */
function rowShape(kind, row) {
  const doc = { schema: "astra.games.index/1", serial: 0, issued_at: 0, expires_at: 0, key_id: "games-current", entries: [], games: [] };
  if (kind === "games") doc.games = [row];
  if (kind === "anticheat") doc.anticheat = [row];
  if (kind === "loaders") doc.loaders = [row];
  return validateMany([{ schema: "games-index-v1", doc }])[0];
}

/**
 * @param {{now?: number}} [o] the signer's clock. Without it (the plugins
 *   service's shape port, the stand's pre-check) the checks that need a
 *   clock use the act's own `at`, and the one that compares the two is skipped.
 * @returns {string[]} why this act cannot be applied to this state; empty when it can
 */
export function actProblems(act, state, { now } = {}) {
  const p = [];
  if (!act || typeof act !== "object") return ["an act is a JSON object"];
  if (act.schema !== ACT_SCHEMA) p.push(`schema is not ${ACT_SCHEMA}`);
  if (!ACT_TYPES.includes(act.type)) return [...p, `unknown act type ${JSON.stringify(act.type)}`];
  if (!Number.isSafeInteger(act.at) || act.at <= 0) p.push("at is not Unix seconds");
  else if (act.at >= AT_SECONDS_BELOW) p.push("at is Unix seconds, not milliseconds");
  else if (now !== undefined && act.at > now + ACT_CLOCK_SKEW) {
    // Every type. A withdrawal dated ahead would be published and could never
    // be lifted; any act dated ahead sorts as the newest for as long as it is.
    p.push(`at is ${act.at - now} seconds ahead of the signer's clock; an act is dated when it was taken (at most ${ACT_CLOCK_SKEW} seconds of skew)`);
  }
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
    else if (entryIdProblem(act.entry_id)) p.push(entryIdProblem(act.entry_id));
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
  } else if (t === "M_LIFT") {
    // shape: the members that name a row, then why
    const before = p.length;
    if (!isId(act.repo_id)) p.push("repo_id is not a repository id");
    if (!isStr(act.versions, 200)) p.push("versions is the lifted row's versions, exactly as that row carries it");
    if (act.entry_id !== undefined && !isStr(act.entry_id, 200)) p.push("entry_id is not a string");
    else if (entryIdProblem(act.entry_id)) p.push(entryIdProblem(act.entry_id));
    if (!Number.isSafeInteger(act.lifts_at) || act.lifts_at <= 0) p.push("lifts_at is the lifted row's at, in Unix seconds");
    else if (Number.isSafeInteger(act.at) && act.lifts_at > act.at) p.push("lifts_at is after the lift's own at: a lift is never older than the row it lifts");
    // What the lift is expected to remove. A client matches a lift by subject
    // and second alone, so the act says the kinds itself and the signer holds
    // it to them: a moderator who copied the wrong second (an act's own `at`
    // where its row had moved to the next one) must not lift another act's row.
    if (!Array.isArray(act.kinds) || !act.kinds.length || !act.kinds.every((k) => ROW_KINDS.includes(k)) || new Set(act.kinds).size !== act.kinds.length) {
      p.push(`kinds is the acts of the rows this lift removes: a non-empty array of distinct values out of ${ROW_KINDS.join(", ")}`);
    }
    const shaped = p.length === before;
    if (!isStr(act.reason_text, 2000)) p.push("reason_text says why (the transparency log shows it)");
    // state: a row with exactly that subject and that at, or the part that matched none
    if (shaped) {
      const why = liftMismatch(state.withdrawn, act);
      const there = why ? [] : kindsNamedBy(state.withdrawn, act);
      if (why) p.push(why);
      else if (there.join() !== [...act.kinds].sort().join()) {
        p.push(`kinds [${[...act.kinds].sort().join(", ")}] is not what this lift would remove: the rows of that subject taken at ${act.lifts_at} are [${there.join(", ")}]; a lift removes all of them and nothing else, so name exactly those, or the second of the row that was meant`);
      } else if (rowsNamedBy(state.withdrawn.rows, act).some(isSticky)) {
        // A security revoke is what a lift re-arms on every client. One console
        // session must not be able to re-arm everything: bounded like takedowns,
        // and refused rather than held, because a lift is never urgent.
        const clock = now ?? act.at;
        const lifts = state.withdrawn.lifts ?? [];
        const recent = lifts.filter((l) => liftIsSticky(l) && liftAppliedAt(l) > clock - TAKEDOWN_WINDOW);
        if (recent.length >= LIFT_LIMIT) {
          const free = Math.min(...recent.map(liftAppliedAt)) + TAKEDOWN_WINDOW;
          p.push(`the lift bound: ${recent.length} security revokes were lifted in the last 24 hours and at most ${LIFT_LIMIT} may be; this lift is refused, not held, and can be taken again from ${new Date(free * 1000).toISOString().slice(0, 19)}Z`);
        }
        // Refused unless this very lift would still be in the list once it is applied.
        const mine = { sticky: true, at: act.at, lifts_at: act.lifts_at, applied_at: clock };
        const kept = retainLifts([...lifts, mine], clock);
        if (kept.length > LIFTS_MAX || !kept.includes(mine)) {
          p.push(`the lift list is full: it holds ${LIFTS_MAX} lifts of security revokes, none older than 365 days, and one of those is never dropped for another`);
        }
      }
    }
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

/**
 * The units spent in the trailing window, by when the signer APPLIED each
 * takedown (withdrawn.spent), never by the act's own `at`: five revokes
 * dated two days back are five takedowns today. A lifted takedown stays
 * spent, because its entry here does not depend on the row or on the lift
 * still existing; revoking and lifting in turn is no way round the bound.
 * A row written before this ledger existed (no act_ref) counts by its `at`,
 * as it always did.
 */
function unitsInWindow(state, now) {
  const since = now - TAKEDOWN_WINDOW;
  const spent = (state.withdrawn.spent ?? []).filter((e) => e.at > since).map((e) => e.unit);
  const legacy = state.withdrawn.rows.filter((r) => r.act_ref === undefined && TAKEDOWN_ACTS.includes(r.act) && r.at > since).map(unitOf);
  return new Set([...spent, ...legacy]);
}

/**
 * The first second, from `from` on, that no row, held takedown or kept lift
 * of this subject carries.
 *
 * A client matches a lift to a row by subject and `at` alone, never by the
 * act's kind. So two acts' rows of one subject must never share a second (one
 * lift would name both), and a new row must never carry the second of a kept
 * lift (the lift would name it, and a list that carries both is one its own
 * signer refuses). The later row moves; it is not refused, because a
 * security revoke must not wait for a retry. Nothing reads a row's `at` as
 * its act's: a held takedown already gets the second it is admitted in, an
 * act is told apart by its confirmation ref, and the bound counts by apply
 * time. The act record keeps its own `at`; its summary says the row's.
 *
 * The move stops where an act's own `at` must: at the signer's clock plus
 * ACT_CLOCK_SKEW, and inside the integers JSON can carry. Past that there
 * is no second to give (null): a row dated later could never be lifted,
 * and one past 2^53 cannot be signed at all.
 */
function freeSecond(state, subject, from, now) {
  const key = subjectKey(subject);
  const taken = new Set();
  for (const r of [...state.withdrawn.rows, ...heldRows(state.withdrawn)]) if (subjectKey(r) === key) taken.add(r.at);
  for (const l of state.withdrawn.lifts ?? []) if (subjectKey(l) === key) taken.add(l.lifts_at);
  const last = Math.min(now + ACT_CLOCK_SKEW, Number.MAX_SAFE_INTEGER);
  let at = from;
  while (at <= last && taken.has(at)) at += 1;
  return at <= last ? at : null;
}

/** Put one row in the list, and spend its unit if it is a takedown. It never touches a lift. */
function putRow(state, row, now) {
  state.withdrawn.rows.push(row);
  if (TAKEDOWN_ACTS.includes(row.act)) (state.withdrawn.spent ??= []).push({ unit: unitOf(row), at: now });
}

/**
 * Add one act's rows, spending the bound: a takedown (yank, delist, revoke)
 * costs one unit per (repository, entry) in the trailing 24 hours, each
 * dependant in its OWN repository. A unit already spent in the window costs
 * nothing again. Over the bound a row is HELD — it waits in withdrawn.held
 * and is admitted, oldest first, by a later run (resign.yml runs daily,
 * sign.yml on every change) — unless the act carries break_glass. A
 * deprecation is a banner, not a takedown, and is never held.
 *
 * The rows one act writes for one subject (a cascade's banner and its yank)
 * get the same second, the first free one from the act's `at`. Each row
 * remembers its act (`act_ref`), which the list never carries.
 */
function addRows(state, rows, { now, breakGlass, ref }) {
  const out = { applied: [], held: [] };
  const second = new Map();
  for (const wanted of rows) {
    const key = subjectKey(wanted);
    if (!second.has(key)) {
      const from = wanted.at ?? now;
      const at = freeSecond(state, wanted, from, now);
      if (at === null) {
        throw new ActRefused(`no second is free for a row of repository ${wanted.repo_id}${wanted.entry_id ? ` ${wanted.entry_id}` : ""} ${wanted.versions}: every second from ${from} to the signer's clock plus ${ACT_CLOCK_SKEW} seconds carries a row or a lift of that subject already, and a row dated later could never be lifted; take the act again later`);
      }
      second.set(key, at);
    }
    const row = { ...wanted, at: second.get(key), act_ref: ref };
    if (TAKEDOWN_ACTS.includes(row.act) && !breakGlass) {
      const used = unitsInWindow(state, now);
      if (!used.has(unitOf(row)) && used.size >= TAKEDOWN_LIMIT) {
        state.withdrawn.held.push({ row, held_at: now });
        out.held.push(row);
        continue;
      }
    }
    putRow(state, row, now);
    out.applied.push(row);
  }
  return out;
}

/** Whether the row a cascade row was written beside (its act's own row) is still in the list or still held. */
function causeStands(state, ref) {
  return [...state.withdrawn.rows, ...heldRows(state.withdrawn)].some((r) => r.act_ref === ref && !r.cascade);
}

/**
 * Admit held takedowns while the window has room, oldest first. A held
 * cascade row whose cause is gone (the foundation's revoke was lifted) is
 * dropped, never admitted: it would take down a dependant for a revoke that
 * no longer stands.
 */
export function admitHeld(state, now) {
  state.withdrawn.spent = (state.withdrawn.spent ?? []).filter((e) => e.at > now - TAKEDOWN_WINDOW);
  const admitted = [];
  const queue = [...state.withdrawn.held].sort((a, b) => a.held_at - b.held_at);
  for (const h of queue) {
    if (h.row.cascade && !causeStands(state, h.row.act_ref)) {
      state.withdrawn.held = state.withdrawn.held.filter((x) => x !== h);
      continue;
    }
    const used = unitsInWindow(state, now);
    if (used.has(unitOf(h.row)) || used.size < TAKEDOWN_LIMIT) {
      const rest = state.withdrawn.held.filter((x) => x !== h);
      const at = freeSecond({ ...state, withdrawn: { ...state.withdrawn, held: rest } }, h.row, now, now);
      if (at === null) continue; // no second free for its subject this run: it waits for the next
      state.withdrawn.held = rest;
      putRow(state, { ...h.row, at }, now);
      admitted.push(h.row);
    }
  }
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

// ── the state against the record (acts/) ──────────────────────────────────

/**
 * Every security revoke acts/ records, accounted for in the state. acts/ is
 * the append-only record (one file per act, never rewritten); the state is
 * what a run rewrites. A state put back from an older run, together with
 * dist/ and floors.json so that the list it signs agrees with the one in
 * dist/, has lost what was applied since; acts/ has not, and the service's
 * re-serve of a lost act is answered "applied, seq N", so nothing else ever
 * brings it back.
 *
 * A recorded M_REVOKE for `security` is accounted for when:
 *   - its own row (by `act_ref`, not a cascade row), still a security
 *     revoke, is in the list or held;
 *     a row from before act_ref (none) counts by its subject; or
 *   - a later recorded M_LIFT ended it: dropped it while held
 *     (`dropped_held_refs`), or lifted its row (`lifted_refs`) and the state
 *     keeps that lift's record as a security lift (`sticky: true`) applied
 *     when the act's record says (`applied_at`). Retention may drop the
 *     record of a lift applied LIFT_KEEP_SECONDS ago or more, and only then
 *     is it not required. A record edited to `sticky: false` or an older
 *     `applied_at` would let a young lift leave the list; it is refused.
 * An M_LIFT recorded before `lifted_refs` existed names its rows by subject
 * and second, so it is matched that way: the subject in the client's
 * reading, and `lifts_at` equal to the revoke's `at` unless the revoke was
 * held (a held row takes the second it is admitted at).
 *
 * @param {object} state as loaded, with `acts`
 * @param {number} now
 * @returns {string[]} one line per act not accounted for, naming its ref
 */
export function actsUnaccounted(state, now) {
  const acts = [...(state.acts ?? [])].sort((a, b) => Number(a.seq) - Number(b.seq));
  const lifts = acts.filter((a) => a.type === "M_LIFT");
  const present = [...state.withdrawn.rows, ...heldRows(state.withdrawn)];
  const records = state.withdrawn.lifts ?? [];
  const p = [];
  for (const r of acts) {
    if (r.type !== "M_REVOKE" || r.reason_code !== "security") continue;
    const ref = r.confirmation?.ref;
    const subject = subjectKey(r);
    if (present.some((x) => x.act_ref === ref && !x.cascade && isSticky(x))) continue;
    if (present.some((x) => x.act_ref === undefined && isSticky(x) && subject !== null && subjectKey(x) === subject)) continue;
    const at = r.summary?.held === 0 ? r.summary.at : undefined;
    const later = lifts.filter((l) => Number(l.seq) > Number(r.seq));
    const byRef = (l, member) => Array.isArray(l.summary?.[member]) && l.summary[member].includes(ref);
    const legacy = (l) => l.summary?.lifted_refs === undefined && subject !== null && subjectKey(l) === subject && (at === undefined || l.lifts_at === at);
    if (later.some((l) => byRef(l, "dropped_held_refs") || (legacy(l) && (l.summary?.dropped_held ?? []).includes("revoke")))) continue;
    const lifted = later.filter((l) => byRef(l, "lifted_refs") || (legacy(l) && (l.summary?.lifted ?? []).includes("revoke")));
    const recorded = (l) => records.some((x) => subjectKey(x) === subjectKey(l) && x.lifts_at === l.lifts_at && x.sticky === true && x.applied_at === l.applied_at);
    if (lifted.some((l) => l.applied_at <= now - LIFT_KEEP_SECONDS || recorded(l))) continue;
    const said = `acts/${String(r.seq).padStart(6, "0")}.json (ref ${ref}), a security revoke of repo ${r.repo_id} ${r.entry_id ?? ""} ${r.versions}`;
    p.push(lifted.length
      ? `act-unaccounted: ${said}, was lifted by ${lifted.map((l) => `acts/${String(l.seq).padStart(6, "0")}.json (ref ${l.confirmation?.ref}, applied at ${l.applied_at})`).join(", ")}, and withdrawn.json keeps no record of that lift as a security lift applied then; the list could drop a lift clients still need`
      : `act-unaccounted: ${said}, is neither in withdrawn.json (row or held, by its ref) nor ended by a recorded lift; the state is older than acts/, and the list it would sign offers what the revoke took down`);
  }
  return p;
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
          rows.push({ repo_id: d.repo_id, versions, entry_id, act: "revoke", floor_effect: "no-play", reason_code: act.reason_code, reason_text: `Revoked with the foundation it is built on. ${act.reason_text ?? ""}`.trim(), at: act.at, cascade: true });
        } else {
          // The default: a banner plus a yank (A§4.4 M3). Installed copies keep working.
          const reason_code = act.reason_code === "security" ? "policy" : act.reason_code;
          const text = `Built on a foundation release that was revoked (${revoked.map((f) => `${f.entry.id} ${f.entry.version}`).join(", ")}).`;
          rows.push({ repo_id: d.repo_id, versions, entry_id, act: "deprecate", floor_effect: "no-offer", reason_code, reason_text: text, at: act.at, cascade: true });
          rows.push({ repo_id: d.repo_id, versions, entry_id, act: "yank", floor_effect: "no-offer", reason_code, reason_text: text, at: act.at, cascade: true });
        }
      }
    }
    const r = addRows(state, rows, { now, breakGlass: act.break_glass === true, ref: act.confirmation.ref });
    // `at` is the second the act's own row carries: its `at`, or the first free one after it for the subject.
    // A later lift names the row by it (and a held row by this one until it is admitted, then by that second).
    return { applied: r.applied.length, held: r.held.length, at: [...r.applied, ...r.held][0].at };
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
  if (t === "M_LIFT") {
    // Every row the lift names leaves the list in this same issue, and the
    // lift is kept. A HELD takedown it names is dropped: no client ever saw
    // it, so nothing is published for it. It lifts no other subject: the
    // rows a revoke cascaded onto its dependants are lifted by their own
    // acts. But the cascade takedowns of that revoke that are still HELD go
    // with it, or the next run would admit a takedown whose cause is gone.
    const named = rowsNamedBy(state.withdrawn.rows, act);
    const namedHeld = state.withdrawn.held.filter((h) => rowsNamedBy([h.row], act).length > 0);
    const causes = new Set([...named, ...namedHeld.map((h) => h.row)].filter((r) => r.act_ref !== undefined && !r.cascade).map((r) => r.act_ref));
    const orphans = state.withdrawn.held.filter((h) => !namedHeld.includes(h) && h.row.cascade && causes.has(h.row.act_ref));
    // A takedown written before the ledger existed (no act_ref) is counted by
    // its row (unitsInWindow). Lifted, the row is gone: its unit moves to the
    // ledger at the row's own second, so lifting it gives nothing back.
    for (const r of named) {
      if (r.act_ref === undefined && TAKEDOWN_ACTS.includes(r.act)) (state.withdrawn.spent ??= []).push({ unit: unitOf(r), at: r.at });
    }
    state.withdrawn.rows = state.withdrawn.rows.filter((r) => !named.includes(r));
    state.withdrawn.held = state.withdrawn.held.filter((h) => !namedHeld.includes(h) && !orphans.includes(h));
    if (named.length) {
      // the subject as the ROW wrote it, so the list's row and its lift are spelled alike
      const row = named[0];
      const lift = { repo_id: row.repo_id, versions: row.versions, lifts_at: row.at, at: act.at, applied_at: now, by: act.by.account, reason_text: act.reason_text, lifted: named.map((r) => r.act).sort(), sticky: named.some(isSticky) };
      if (row.entry_id !== undefined) lift.entry_id = row.entry_id;
      state.withdrawn.lifts = retainLifts([...(state.withdrawn.lifts ?? []), lift], now);
    }
    // the acts whose own rows this lift ended, kept in its record in acts/ (actsUnaccounted reads them)
    const refs = (rows) => [...new Set(rows.filter((r) => r.act_ref !== undefined && !r.cascade).map((r) => r.act_ref))].sort();
    return {
      lifted: named.map((r) => r.act).sort(), repo_id: act.repo_id, ...(act.entry_id !== undefined ? { entry_id: act.entry_id } : {}), versions: act.versions, lifts_at: act.lifts_at,
      lifted_refs: refs(named),
      ...(namedHeld.length ? { dropped_held: namedHeld.map((h) => h.row.act).sort(), dropped_held_refs: refs(namedHeld.map((h) => h.row)) } : {}),
      ...(orphans.length ? { dropped_held_cascade: orphans.length } : {}),
    };
  }
  throw new Error(`no applier for ${t}`);
}
