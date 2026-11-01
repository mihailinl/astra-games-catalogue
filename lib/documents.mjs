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

import { verifyEnvelope, publicKeyFromBase64 } from "./vendor/astra-registry/bot/lib/sign.mjs";
import { descriptorDigest, effectiveLoaders, entryIdsInRepo } from "./model.mjs";
import { descriptorCodes, foldCode, sameIdentity } from "./rules.mjs";
import { loadSchema, validateMany } from "./schemas.mjs";
import { compare } from "./semver.mjs";

export const INDEX_SCHEMA = "astra.games.index/1";
export const WITHDRAWN_SCHEMA = "astra.games.withdrawn/1";
export const DAY = 86400;
export const EXPIRY_SECONDS = 7 * DAY; // the 7-day target (A§5.3)
export const MAX_SPAN_SECONDS = 8 * DAY;
export const MAX_AHEAD_SECONDS = 1 * DAY;
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
export function buildIndexBody({ state, seedLoaders, issuedAt, keyId, members = declaredMembers() }) {
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
    expires_at: issuedAt + EXPIRY_SECONDS,
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

export function buildWithdrawnBody({ state, issuedAt, keyId }) {
  const rows = [...state.withdrawn.rows]
    .sort((a, b) => a.at - b.at || a.repo_id - b.repo_id || String(a.entry_id ?? "").localeCompare(String(b.entry_id ?? "")))
    .map((r) => {
      const row = { repo_id: r.repo_id, versions: r.versions, act: r.act, floor_effect: r.floor_effect, reason_code: r.reason_code, at: r.at };
      if (r.entry_id) row.entry_id = r.entry_id;
      if (r.reason_text) row.reason_text = r.reason_text;
      return row;
    });
  return { schema: WITHDRAWN_SCHEMA, serial: issuedAt, issued_at: issuedAt, expires_at: issuedAt + EXPIRY_SECONDS, key_id: keyId, rows };
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
  if (indexBody) {
    const entries = indexBody.entries.map((entry) => ({ entry }));
    for (const r of body.rows ?? []) {
      if (!r.entry_id && entryIdsInRepo(entries, r.repo_id).length > 1) p.push(`repo ${r.repo_id} hosts several entries and a row names no entry_id (R43)`);
    }
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

/**
 * Everything a verifier checks about signed documents: each envelope's
 * signature under the domain the VERIFIER names, the signing key agreeing
 * with the body's own key_id, then the body checks.
 *
 * @param {{envelope: object, domain: string, indexBody?: object}[]} items
 * @param {{keys: {key_id: string, public_key: string}[], now: number, strict?: boolean}} o
 * @returns {string[][]}
 */
export function verifyDocuments(items, { keys, now, strict = true }) {
  const trusted = keys.filter((k) => k.public_key).map((k) => ({ key_id: k.key_id, publicKey: publicKeyFromBase64(k.public_key) }));
  const bodies = bodyProblemsMany(items.map((it) => ({ domain: it.domain, body: it.envelope?.signed, indexBody: it.indexBody })), { now, strict });
  return items.map((it, i) => {
    const problems = [];
    const v = verifyEnvelope(it.envelope, it.domain, trusted);
    if (!v.ok) problems.push(`signature: ${v.reason}`);
    if (v.ok && it.envelope?.signed?.key_id !== v.key_id) problems.push(`the body says key_id ${it.envelope?.signed?.key_id} and ${v.key_id} signed it`);
    return [...problems, ...bodies[i]];
  });
}

export function verifyDocument(envelope, { domain, keys, now, indexBody = null, strict = true }) {
  return verifyDocuments([{ envelope, domain, indexBody }], { keys, now, strict })[0];
}
