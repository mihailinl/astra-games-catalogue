// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The two documents' bodies, built from the catalogue's state — and the
// checks a JSON Schema cannot make, which both the signer (before it signs)
// and the K12 canary (against AstraPlugins' goldens) run.
//
// astra.games.index/1 (games-index-v1.md): listed entries with the
// moderator overlays applied, games[], anticheat[], loaders[] and
// engine_codes{}. astra.games.withdrawn/1 (games-withdrawn-v1.md): the rows.
//
// ── the merged plan's §5.2 members, and why they wait for the schema ──────
//
// §5.2 adds `health{}`, `unmaintained` and `successor_entry_id` to an entry
// and a per-code `recommended_foundation`. The pinned S schema
// (games-index-v1.schema.json at d46e44a) does not declare them yet, and its
// `entry` and root both say additionalProperties: false — so a document
// carrying them fails AstraPlugins' own validator, and a client parsing with
// deny_unknown_fields would refuse the whole index. The catalogue therefore
// COMPUTES and KEEPS them (state, acts) and EMITS each member only when the
// pinned schema declares it. The day lane S adds them and this repository
// re-pins, they appear with no code change; until then nothing a client
// cannot parse is ever signed. Names chosen here, for S to confirm:
//
//   entry.health = {last_release_at, rating_avg, rating_count,
//                   open_reports_unanswered, failure_rate?}
//       rating_avg is in HUNDREDTHS of a star and failure_rate in BASIS
//       POINTS: the canonical serialiser signs integers only (JCS has no
//       canonical fraction; the registry's jcs refuses one, as trust.rs does)
//   entry.unmaintained (bool), entry.successor_entry_id (string|null)
//   root.recommended_foundations = {code: entry_id}

import crypto from "node:crypto";

import { signingDigest } from "./vendor/astra-registry/bot/lib/sign.mjs";
import { BODY_KEY_ID, verifyingKeys } from "./trust.mjs";
import { descriptorDigest, effectiveLoaders, entryIdsInRepo, isSticky, LIFT_KEEP_SECONDS, liftAppliedAt, liftIsSticky, LIFTS_MAX, subjectKey } from "./model.mjs";
import { descriptorCodes, foldCode, sameIdentity } from "./rules.mjs";
import { loadSchema, validateMany } from "./schemas.mjs";
import { compare } from "./semver.mjs";

export const INDEX_SCHEMA = "astra.games.index/1";
export const WITHDRAWN_SCHEMA = "astra.games.withdrawn/1";
export const DAY = 86400;
export const EXPIRY_SECONDS = 7 * DAY; // a signature's life: A§5.3's 7-day target, under the cap

export const MAX_SPAN_SECONDS = 8 * DAY;
/**
 * The most bytes a served document may have, on the raw bytes before parsing:
 * the service's ceiling (minice plugins-signed domain.rs MAX_DOCUMENT_BYTES,
 * SERVE-50). The client refuses an over-cap document whole
 * (games-index-v1 preamble, read_capped).
 */
export const MAX_DOCUMENT_BYTES = 1_048_576;
export const MAX_AHEAD_SECONDS = 1 * DAY;
/**
 * The most lifts the withdrawn list carries (games-withdrawn-v1.md §2.2, the
 * schema's maxItems; lib/model.mjs). The state holds no more than this:
 * lib/acts.mjs retainLifts says which leave. A lift is at most about
 * 0.5 KiB here, so a full list is about 128 KiB of MAX_DOCUMENT_BYTES.
 */
export { LIFTS_MAX };
export const FAILURE_RATE_MIN_REPORTS = 20;

/** Which §5.2 members the pinned schema declares. */
export function declaredMembers(schema = loadSchema("games-index-v1")) {
  const entry = schema?.$defs?.entry?.properties ?? {};
  const root = schema?.properties ?? {};
  return {
    health: "health" in entry,
    unmaintained: "unmaintained" in entry,
    successor_entry_id: "successor_entry_id" in entry,
    recommended_foundations: "recommended_foundations" in root,
  };
}

/** merged §5.2: health per entry id, from the plugins service's counts and our own release times. */
export function healthOf(entryId, state) {
  const h = state.health?.[entryId] ?? {};
  const releases = state.entries.filter((e) => e.entry.id === entryId && e.meta.status === "listed").map((e) => e.meta.released_at ?? 0);
  const out = {
    last_release_at: releases.length ? Math.max(...releases) : 0,
    rating_avg: Number.isSafeInteger(h.rating_avg) ? h.rating_avg : 0,
    rating_count: Number.isSafeInteger(h.rating_count) ? h.rating_count : 0,
    open_reports_unanswered: Number.isSafeInteger(h.open_reports_unanswered) ? h.open_reports_unanswered : 0,
  };
  // Only from reports a user chose to send, never telemetry; under 20, no value.
  const sent = Number.isSafeInteger(h.reports_sent) ? h.reports_sent : 0;
  const failed = Number.isSafeInteger(h.reports_failed) ? h.reports_failed : 0;
  if (sent >= FAILURE_RATE_MIN_REPORTS) out.failure_rate = Math.round((Math.min(failed, sent) * 10000) / sent);
  return out;
}

/** The descriptor of record for each entry: kept only by the owner of every code it claims; moved by adoption. */
function descriptorFor(e, state) {
  const moved = Object.values(state.moderation.descriptor_moves ?? {}).find((m) => m.to_entry_id === e.entry.id);
  const own = e.entry.descriptor;
  if (own) {
    const codes = descriptorCodes(own);
    const owned = codes.every((c) => {
      const owner = Object.entries(state.engineCodes).find(([k]) => foldCode(k) === foldCode(c))?.[1];
      return owner && sameIdentity(owner, e.entry.publisher);
    });
    if (owned) return { descriptor: own, descriptor_sha256: e.entry.descriptor_sha256 };
  }
  if (moved) return { descriptor: moved.descriptor, descriptor_sha256: moved.descriptor_sha256 };
  return { descriptor: null, descriptor_sha256: null };
}

/**
 * @param {{state: object, seedLoaders: object, issuedAt: number, keyId: string, members?: object}} o
 */
export function buildIndexBody({ state, seedLoaders, issuedAt, keyId, members = declaredMembers(), expirySeconds = EXPIRY_SECONDS }) {
  const reviewed = new Set((state.moderation.reviewed ?? []).map((r) => `${r.entry_id}@${r.version}@${r.sha256}`));
  const foundations = state.moderation.foundations ?? {};
  const listed = state.entries
    .filter((e) => e.meta.status === "listed")
    .sort((a, b) => (a.entry.id < b.entry.id ? -1 : a.entry.id > b.entry.id ? 1 : compare(a.entry.version, b.entry.version)));
  const entries = listed.map((e) => {
    const entry = { ...structuredClone(e.entry), ...descriptorFor(e, state) };
    entry.review = reviewed.has(`${entry.id}@${entry.version}@${entry.source.sha256}`) ? "source_reviewed" : "unchecked";
    if (members.health) entry.health = healthOf(entry.id, state);
    const f = foundations[entry.id];
    if (members.unmaintained && entry.kind === "foundation") entry.unmaintained = f?.unmaintained === true;
    if (members.successor_entry_id && entry.kind === "foundation") entry.successor_entry_id = f?.successor_entry_id ?? null;
    return entry;
  });
  const body = {
    schema: INDEX_SCHEMA,
    serial: issuedAt,
    issued_at: issuedAt,
    expires_at: issuedAt + expirySeconds,
    key_id: keyId,
    entries,
    games: (state.moderation.games ?? []).map(projectGameRow).sort((a, b) => a.id - b.id),
    anticheat: [...(state.moderation.anticheat ?? [])].map(({ name, kind, value }) => ({ name, kind, value })),
    loaders: effectiveLoaders(seedLoaders, state.moderation),
    engine_codes: Object.fromEntries(Object.entries(state.engineCodes).sort(([a], [b]) => (a < b ? -1 : 1)).map(([c, w]) => [c, { account: w.account, repo_id: w.repo_id, repo_owner_id: w.repo_owner_id }])),
  };
  if (members.recommended_foundations) body.recommended_foundations = { ...(state.moderation.recommended_foundations ?? {}) };
  return body;
}

export function projectGameRow(r) {
  const out = { store: "steam", id: Number(r.id) };
  for (const k of ["engine", "prefer", "deny", "refuse", "allow_foundations", "note"]) if (k in r) out[k] = r[k];
  return out;
}

export function buildWithdrawnBody({ state, issuedAt, keyId, expirySeconds = EXPIRY_SECONDS }) {
  const rows = [...state.withdrawn.rows]
    .sort((a, b) => a.at - b.at || a.repo_id - b.repo_id || String(a.entry_id ?? "").localeCompare(String(b.entry_id ?? "")))
    .map((r) => {
      const row = { repo_id: r.repo_id, versions: r.versions, act: r.act, floor_effect: r.floor_effect, reason_code: r.reason_code, at: r.at };
      if (r.entry_id) row.entry_id = r.entry_id;
      if (r.reason_text) row.reason_text = r.reason_text;
      return row;
    });
  // Always present, `[]` when there is none. The state's lift also says who
  // and why, which acts it lifted and whether one was a security revoke; the
  // list carries what a client reads. The state never holds more than
  // LIFTS_MAX (lib/acts.mjs retainLifts), and the slice is only what keeps a
  // state somebody edited by hand inside the schema.
  const lifts = [...(state.withdrawn.lifts ?? [])]
    .sort((a, b) => a.at - b.at || a.lifts_at - b.lifts_at || a.repo_id - b.repo_id || String(a.entry_id ?? "").localeCompare(String(b.entry_id ?? "")))
    .slice(-LIFTS_MAX)
    .map((l) => {
      const lift = { repo_id: l.repo_id, versions: l.versions, lifts_at: l.lifts_at, at: l.at };
      if (l.entry_id !== undefined) lift.entry_id = l.entry_id;
      return lift;
    });
  return { schema: WITHDRAWN_SCHEMA, serial: issuedAt, issued_at: issuedAt, expires_at: issuedAt + expirySeconds, key_id: keyId, rows, lifts };
}

// ── what a schema cannot say ──────────────────────────────────────────────

/** games-index-v1.md §1 and the withdrawn spec's freshness: the same numbers for both documents. */
export function freshnessProblems(body, now) {
  const p = [];
  if (body.serial !== body.issued_at) p.push(`serial ${body.serial} is not issued_at ${body.issued_at}`);
  if (body.issued_at > now + MAX_AHEAD_SECONDS) p.push("issued-at-too-far-ahead: issued_at is more than 1 day ahead of the clock");
  if (body.expires_at - body.issued_at > MAX_SPAN_SECONDS) p.push("expiry-span-too-long: expires_at - issued_at exceeds 8 days");
  if (body.expires_at <= body.issued_at) p.push("expires_at is not after issued_at");
  return p;
}

export function withdrawnProblems(body, indexBody = null) {
  const p = [];
  for (const r of body.rows ?? []) {
    if (r.reason_code === "security" && r.act !== "revoke") p.push(`security-requires-revoke: repo ${r.repo_id} ${r.versions} is security with act ${r.act}`);
  }
  // Subjects as a client reads them (lib/model.mjs subjectKey), the one reading the signer uses anywhere.
  const rows = body.rows ?? [];
  const lifts = body.lifts ?? [];
  for (const x of [...rows, ...lifts]) {
    if (subjectKey(x) === null) p.push(`entry-id-readable: repo ${x.repo_id} carries entry_id ${JSON.stringify(x.entry_id)}, which a client cannot read: it could not key the row (and would then release nothing from this list) and skips such a lift`);
  }
  for (const l of lifts) {
    const key = subjectKey(l);
    if (key !== null && rows.some((r) => subjectKey(r) === key && r.at === l.lifts_at)) {
      p.push(`lift-not-contradicted: repo ${l.repo_id} ${l.entry_id ?? ""} ${l.versions} at ${l.lifts_at} is lifted and is still a row; a row beats its lift, so the lifted row leaves the list with it`);
    }
  }
  // One lift names every row of its subject and second, so two acts must never share one. The only rows
  // that may: the banner and the yank one cascade writes for a dependant.
  const seconds = new Map();
  for (const r of rows) {
    const key = subjectKey(r);
    if (key === null) continue;
    const k = `${key}\u0000${r.at}`;
    seconds.set(k, [...(seconds.get(k) ?? []), r]);
  }
  for (const group of seconds.values()) {
    const acts = group.map((r) => r.act).sort();
    if (group.length > 1 && !(acts.length === 2 && acts[0] === "deprecate" && acts[1] === "yank")) {
      p.push(`one-act-per-second: repo ${group[0].repo_id} ${group[0].entry_id ?? ""} ${group[0].versions} carries ${acts.join(" and ")} at ${group[0].at}; one lift would name them all, so two acts' rows of one subject never share a second`);
    }
  }
  if (indexBody) {
    const entries = indexBody.entries.map((entry) => ({ entry }));
    for (const r of body.rows ?? []) {
      if (!r.entry_id && entryIdsInRepo(entries, r.repo_id).length > 1) p.push(`repo ${r.repo_id} hosts several entries and a row names no entry_id (R43)`);
    }
  }
  return p;
}

// ── what a list owes the one published before it ──────────────────────────

/**
 * The withdrawn list about to be signed, against the one this signer
 * published last. Every other rule here reads one document. This one reads
 * two, because what it guards cannot be seen in one.
 *
 * A security revoke is STICKY on a client: one that applied it releases it
 * only when a signed lift names it (its subject and the row's `at`), never
 * because the list stopped carrying the row. A fresh install, or a
 * reinstall, reads only the current list. So a list from which such a row is
 * simply gone is correctly signed, releases the revoke nowhere it was seen,
 * and offers the revoked versions to everybody new. A row leaves the state
 * in one place (lib/acts.mjs applyAct, M_LIFT), which writes its lift in the
 * same step; a state file lost or replaced by an older one, a migration of
 * the state, or a later code path does not go through it.
 *
 *   sticky-row-vanished   every sticky row of the previous list is still a
 *       sticky row of this one (the same subject as a client reads it,
 *       lib/model.mjs subjectKey, and the same `at`), or a lift of this one
 *       names it (that subject, `lifts_at` equal to the row's `at`). A row
 *       whose subject no client can key matches nothing, so it is refused.
 *   sticky-lift-vanished  every lift of the previous list is still in this
 *       one (subject and `lifts_at`), unless retention may have dropped it
 *       (lib/acts.mjs retainLifts): a lift of a row that was not sticky, or
 *       one the signer applied LIFT_KEEP_SECONDS ago or more. The list's lift
 *       says neither, so both are read from the state's records of that
 *       lift, as the run LOADED them (`previous.lifts`). A lift the state has
 *       no record of is read as a young lift of a security revoke.
 *
 * A row that is not sticky may vanish: clients release those by absence.
 *
 * `previous` is null when no list was ever published; the first owes
 * nothing. It is never left out: a caller that forgot it would skip the rule
 * in silence.
 *
 * @param {{body: object, lifts: object[]} | null} previous pipeline.mjs lastWithdrawn
 * @param {object} body the list about to be signed
 * @param {number} now Unix seconds, the signer's clock
 * @returns {string[]}
 */
export function successorProblems(previous, body, now) {
  if (previous === undefined) throw new TypeError("successorProblems needs the withdrawn list published last, or null when none ever was");
  if (previous === null) return [];
  const p = [];
  const was = previous.body;
  const rows = (body.rows ?? []).filter(isSticky).map((r) => ({ subject: subjectKey(r), at: r.at }));
  const lifts = (body.lifts ?? []).map((l) => ({ subject: subjectKey(l), at: l.lifts_at }));
  const names = (list, subject, at) => subject !== null && list.some((x) => x.subject === subject && x.at === at);
  const said = (x, at) => `repo ${x.repo_id} ${x.entry_id ?? ""} ${x.versions} at ${at}`;
  for (const r of (was.rows ?? []).filter(isSticky)) {
    const subject = subjectKey(r);
    if (names(rows, subject, r.at) || names(lifts, subject, r.at)) continue;
    p.push(`sticky-row-vanished: ${said(r, r.at)} is a security revoke in the list published before this one (serial ${was.serial}), and this one neither carries that row nor lifts it; a client that applied it keeps it, and a fresh install would be offered what it revokes`);
  }
  for (const l of was.lifts ?? []) {
    const subject = subjectKey(l);
    // a lift no client can key releases nothing anywhere, and nobody misses it
    if (subject === null || names(lifts, subject, l.lifts_at)) continue;
    const records = previous.lifts.filter((s) => subjectKey(s) === subject && s.lifts_at === l.lifts_at);
    if (records.length && records.every((s) => !liftIsSticky(s) || liftAppliedAt(s) <= now - LIFT_KEEP_SECONDS)) continue;
    const why = records.length ? "it lifted a security revoke and the signer applied it less than 365 days ago" : "the state has no record of it, so it is read as a young lift of a security revoke";
    p.push(`sticky-lift-vanished: ${said(l, l.lifts_at)} is lifted in the list published before this one (serial ${was.serial}), and this one does not carry that lift; ${why}; a client that has not read it yet would keep the revoke for good`);
  }
  return p;
}

export function indexProblems(body) {
  const p = [];
  const seen = new Set();
  const codes = Object.entries(body.engine_codes ?? {});
  for (const e of body.entries ?? []) {
    const k = `${e.id}@${e.version}`;
    if (seen.has(k)) p.push(`${k} is listed twice`);
    seen.add(k);
    if (e.descriptor) {
      let digest = null;
      try {
        digest = descriptorDigest(e.descriptor);
      } catch (err) {
        p.push(`${k}: the descriptor has no canonical form (${err.message})`);
      }
      if (digest !== null && digest !== e.descriptor_sha256) p.push(`${k}: descriptor_sha256 is not sha256(JCS(descriptor))`);
      for (const c of descriptorCodes(e.descriptor)) {
        const owner = codes.find(([code]) => foldCode(code) === foldCode(c))?.[1];
        if (!owner) p.push(`${k}: carries a descriptor for ${c}, which engine_codes does not list`);
        else if (!sameIdentity(owner, e.publisher)) p.push(`${k}: carries the descriptor for ${c}, which ${owner.account} owns`);
      }
    }
  }
  return p;
}

/**
 * What a verifier checks about document BODIES, signature aside: the S
 * schema through schemalite (one Python process for the batch), then the
 * rules above. With `strict` it adds the signer's own invariants over the
 * index (descriptor digests, engine-code ownership, no duplicate release),
 * which the signer holds its output to before it signs; the K12 canary runs
 * the non-strict set over AstraPlugins' goldens, which is what the spec
 * defines as a refusal.
 *
 * @param {{domain: string, body: object, indexBody?: object}[]} items
 * @param {{now: number, strict?: boolean}} o
 * @returns {string[][]} problems per item
 */
export function bodyProblemsMany(items, { now, strict = false }) {
  const shapes = validateMany(items.map((it) => ({ schema: it.domain === INDEX_SCHEMA ? "games-index-v1" : "games-withdrawn-v1", doc: it.body })));
  return items.map((it, i) => {
    const problems = [];
    const { domain, body } = it;
    if (body?.schema !== domain) problems.push(`the body's schema is ${body?.schema}, not ${domain}`);
    if (!shapes[i].ok) problems.push(`schema: ${shapes[i].error}`);
    if (body && typeof body === "object" && shapes[i].ok) {
      problems.push(...freshnessProblems(body, now));
      if (domain === WITHDRAWN_SCHEMA) problems.push(...withdrawnProblems(body, it.indexBody ?? null));
      else if (strict) problems.push(...indexProblems(body));
    }
    return problems;
  });
}

export function bodyProblems(domain, body, { now, indexBody = null, strict = false }) {
  return bodyProblemsMany([{ domain, body, indexBody }], { now, strict })[0];
}

// ── the signature: every key that verifies, never only the first ──────────

/**
 * Verify an envelope under `keys` and collect EVERY key that verifies —
 * never stopping at the first.
 *
 * The vendored registry verifier (verifyEnvelope) is first-wins, which is
 * right for the registry's own documents (the question there is "did a
 * trusted key sign it") and wrong for a games document, whose body names a
 * ROLE that must be among the roles of the keys that verified it. A document
 * co-signed by current and next across a ceremony (signing.mjs) reads, to a
 * first-wins verifier, as whichever key it met first — so the same bytes
 * passed or failed by the order of their signatures. This is the client's
 * and the service's rule instead (minice plugins-signed envelope.rs
 * verify_envelope_all; trust-kind-keys-v1 §6): try every offered signature
 * against every trusted key and collect every key that verifies, "so a
 * document dual-signed by current and next retires current for its schema
 * whatever order its signatures are in".
 *
 * Signatures are matched by trying the keys, never by the `key_id` they
 * claim: an entry naming a key id the verifier does not trust (a co-signer
 * the trust.json at hand no longer lists) is simply not counted, never an
 * error. An entry whose `sig` is not, after trimming, the padded standard
 * base64 of 64 bytes (SIG_B64) is skipped, as the service's strict decoder
 * skips it: Node's base64 decoder also takes unpadded, url-safe and
 * whitespace-riddled spellings, and a verifier laxer than the client's can
 * pass what the client refuses. The digest is the vendored signingDigest, so
 * the construction is the registry's.
 *
 * @param {unknown} doc the whole envelope
 * @param {string} domain the verifier's own constant, not the document's `schema`
 * @param {{key_id: string, publicKey: import("node:crypto").KeyObject}[]} keys
 * @returns {{ok: true, verified: object[], offered: string[]} | {ok: false, reason: string, offered: string[]}}
 *   `verified` holds the keys of `keys` that verified, in the order of `keys`
 */
/** A signature as the client and the service decode it: standard base64 of 64 bytes, padded. */
export const SIG_B64 = /^[A-Za-z0-9+/]{86}==$/;

export function verifyEnvelopeAll(doc, domain, keys) {
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return { ok: false, reason: "not a JSON object", offered: [] };
  if (!("signed" in doc)) return { ok: false, reason: "no `signed` member", offered: [] };
  const signatures = Array.isArray(doc.signatures) ? doc.signatures : null;
  if (!signatures) return { ok: false, reason: "no `signatures` array", offered: [] };
  const offered = signatures.map((s) => (typeof s?.key_id === "string" ? s.key_id : "<unnamed>"));
  if (!keys.length) return { ok: false, reason: "no trusted key was supplied", offered };
  let digest;
  try {
    digest = signingDigest(domain, doc.signed);
  } catch (e) {
    return { ok: false, reason: `the signed body has no canonical form (${e.message})`, offered };
  }
  const found = new Set();
  for (const entry of signatures) {
    if (typeof entry?.sig !== "string" || !SIG_B64.test(entry.sig.trim())) continue;
    const sig = Buffer.from(entry.sig.trim(), "base64");
    for (const candidate of keys) {
      if (!found.has(candidate) && crypto.verify(null, digest, candidate.publicKey, sig)) found.add(candidate);
    }
  }
  if (!found.size) return { ok: false, reason: "no trusted key signed this document", offered };
  return { ok: true, verified: keys.filter((k) => found.has(k)), offered };
}

/**
 * The signature half of verifying a games document under one trust.json's
 * games kind keys: every key that verifies (verifyEnvelopeAll) under the two
 * `games` kind keys ONLY (never an index key, never another kind's —
 * lib/trust.mjs) and only those whose not_before has come by `now` (the
 * client's `valid_at(kind, judged_at)`); the body's claimed role among the
 * roles of those keys; and each verifying key's not_before against the body's
 * issued_at.
 *
 * @param {object} envelope
 * @param {string} domain
 * @param {{current: object, next: object}} kindKeys
 * @param {number} now Unix seconds
 * @returns {{problems: string[], verifiedBy: {key_id: string, role: string, notBefore: number}[]}}
 */
export function signatureCheck(envelope, domain, kindKeys, now) {
  if (!Number.isSafeInteger(now)) throw new TypeError("signatureCheck needs now, in Unix seconds: a key counts only from its not_before");
  const usable = verifyingKeys(kindKeys).filter((k) => k.notBefore <= now);
  if (!usable.length) return { problems: ["signature: no games kind key of trust.json has reached its not_before"], verifiedBy: [] };
  const v = verifyEnvelopeAll(envelope, domain, usable);
  if (!v.ok) return { problems: [`signature: ${v.reason} (only the two games kind keys of trust.json may sign it, each from its not_before)`], verifiedBy: [] };
  const body = envelope.signed;
  const problems = [];
  if (!v.verified.some((k) => BODY_KEY_ID[k.role] === body?.key_id)) {
    problems.push(`the body names ${body?.key_id} and the keys that verified it are ${v.verified.map((k) => `the ${k.role} key ${k.key_id}`).join(" and ")}`);
  }
  if (!Number.isSafeInteger(body?.issued_at)) problems.push("issued_at is not an integer, so no key's not_before can be checked");
  else for (const k of v.verified) if (body.issued_at < k.notBefore) problems.push(`${k.key_id} signed before its not_before`);
  return { problems, verifiedBy: v.verified };
}

/**
 * Everything a verifier checks about signed games documents: each envelope's
 * signature under the domain the VERIFIER names (signatureCheck: every
 * verifying key collected, the body's role among theirs, each one's
 * not_before), then the body checks.
 *
 * @param {{envelope: object, domain: string, indexBody?: object}[]} items
 * @param {{kindKeys: {current: object, next: object}, now: number, strict?: boolean}} o
 * @returns {string[][]}
 */
export function verifyDocuments(items, { kindKeys, now, strict = true }) {
  const bodies = bodyProblemsMany(items.map((it) => ({ domain: it.domain, body: it.envelope?.signed, indexBody: it.indexBody })), { now, strict });
  return items.map((it, i) => [...signatureCheck(it.envelope, it.domain, kindKeys, now).problems, ...bodies[i]]);
}

export function verifyDocument(envelope, { domain, kindKeys, now, indexBody = null, strict = true }) {
  return verifyDocuments([{ envelope, domain, indexBody }], { kindKeys, now, strict })[0];
}
