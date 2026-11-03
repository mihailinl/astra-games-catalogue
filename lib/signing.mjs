// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Signing both documents (A§5.3; merged §2.2, R24; the key model of minice
// docs/architecture/2026-11-01-content-catalogue.md §5).
//
// ── the construction ───────────────────────────────────────────────────────
//
// The plugin envelope, by the plugin registry's own code (vendored sign.mjs):
//
//     { "$comment", "signed": <body>, "signatures": [ { "key_id", "sig" } ] }
//     sig = Ed25519(seed, SHA-256( domain ‖ 0x00 ‖ JCS(signed) ))
//
// with domain = the document's schema string, supplied by the VERIFIER from
// its own constant. One construction and one canonicaliser for every signed
// document in the estate.
//
// ── keys: the two `games` kind keys of trust.json ─────────────────────────
//
// lib/trust.mjs reads them out of the root-signed trust.json. The
// publish-games environment holds GAMES_SIGNING_KEY_CURRENT; when
// GAMES_SIGNING_KEY_NEXT is set, NEXT signs — that is the whole of a routine
// rotation, because clients already accept both keys. The secret must be the
// private half of the kind key of its role (E_KEY_NOT_AUTHORISED otherwise),
// usable from its not_before. Once next has signed a document of a schema,
// current is SPENT for that schema and the signer never signs that schema
// with it again (E_KEY_RETIRED): a rotation is made for a reason, and quietly
// sliding back would undo it. Two spent keys for a schema is the one routine
// event that needs a ceremony (a fresh next in trust.json).
//
// "Spent" is per DOCUMENT SCHEMA, not per kind (minice design §11a.9,
// 2026-11-02; AstraPlugins games-index-v1 §3). The index and the withdrawn
// list are signed and served on separate schedules, and a client retires
// current for one schema only when a next-signed document OF THAT SCHEMA
// arrives, so a still-valid current-signed withdrawn list is never refused
// because the index rotated first: withdrawals must never go dark. The
// signer keeps the same ledger: floors.json's `spent` maps each schema to the
// key ids spent for it, and each document is signed by the signer selected
// for its own schema. A run picks the role by the environment, the same for
// both documents, so a routine rotation still moves both together; the
// ledger is what stops either from ever sliding back.
//
// Each value is the base64 of the raw 32-byte Ed25519 seed. It is read from
// the environment only, never from an argument.
//
// ── what the documents carry ──────────────────────────────────────────────
//
// signatures[].key_id is the kind key's id (e.g. astra-games-2026a); the
// body's key_id is its ROLE, `games-current` or `games-next`, because the
// pinned games-index-v1/withdrawn-v1 schemas enumerate exactly those two.
// A verifier checks that the key that verified holds the role the body names.
//
// ── serial, freshness, the per-kind floor ─────────────────────────────────
//
// serial = issued_at, Unix seconds. The floor is per DOCUMENT of the kind (one
// for the index, one for the withdrawn list), not per key: a new serial is strictly above
// the last one signed for that document whichever key signed it, so a key
// that is still trusted cannot replay an older document. A serial that would
// have to sit more than 1 day ahead of the clock is refused (clients refuse
// it). The signature's life is expires_at − issued_at = EXPIRY_SECONDS
// (7 days, A§5.3's target), under the 8-day cap every verifier holds; there
// is no per-key lifetime. Both documents are signed in every run, with one
// issued_at, so a client never sees a fresh index beside a stale withdrawal
// list.

import { privateKeyFromSeed, publicKeyBase64, signEnvelope } from "./vendor/astra-registry/bot/lib/sign.mjs";
import {
  buildIndexBody, buildWithdrawnBody, EXPIRY_SECONDS, INDEX_SCHEMA, MAX_AHEAD_SECONDS, MAX_SPAN_SECONDS, verifyDocuments, WITHDRAWN_SCHEMA,
} from "./documents.mjs";
import { BODY_KEY_ID, KIND } from "./trust.mjs";

export const ENV_KEYS = Object.freeze({ current: "GAMES_SIGNING_KEY_CURRENT", next: "GAMES_SIGNING_KEY_NEXT" });

export class SignRefused extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.code = code;
  }
}

function seedFrom(b64, name) {
  const seed = Buffer.from(String(b64).trim(), "base64");
  if (seed.length !== 32) throw new SignRefused("E_KEY_MALFORMED", `${name} is not the base64 of a 32-byte Ed25519 seed`);
  return seed;
}

export const SCHEMAS = Object.freeze([INDEX_SCHEMA, WITHDRAWN_SCHEMA]);

/**
 * The key ids spent for each document schema, out of floors.json's `spent`.
 * Fail closed: anything that is not the shape this code writes refuses the
 * run rather than read as "nothing spent", which would let current sign again.
 *
 * A flat list is the per-kind ledger written before 2026-11-02, when one key
 * signed both documents in every run: a key spent then was spent for both
 * schemas, so it counts for both.
 *
 * @param {object} floors
 * @returns {Record<string, Set<string>>}
 */
export function spentBySchema(floors) {
  const out = Object.fromEntries(SCHEMAS.map((s) => [s, new Set()]));
  const raw = floors?.spent;
  if (raw === undefined) return out;
  const ids = (v, where) => {
    if (!Array.isArray(v) || !v.every((x) => typeof x === "string" && x.length > 0)) {
      throw new SignRefused("E_STATE_SPENT", `floors.json spent${where} is not a list of key ids; refusing to guess which keys are spent`);
    }
    return v;
  };
  if (Array.isArray(raw)) {
    for (const id of ids(raw, "")) for (const s of SCHEMAS) out[s].add(id);
    return out;
  }
  if (raw === null || typeof raw !== "object") throw new SignRefused("E_STATE_SPENT", "floors.json spent is neither a per-schema map nor a list");
  const names = Object.keys(raw);
  if (names.length !== SCHEMAS.length || !SCHEMAS.every((s) => Object.hasOwn(raw, s))) {
    throw new SignRefused("E_STATE_SPENT", `floors.json spent must name exactly ${SCHEMAS.join(" and ")}, not ${names.join(", ") || "nothing"}`);
  }
  for (const s of SCHEMAS) for (const id of ids(raw[s], `[${s}]`)) out[s].add(id);
  return out;
}

/**
 * The one key this run signs documents of `schema` with.
 *
 * @param {{env: object, floors: object, kindKeys: {current: object, next: object}, now: number, schema: string}} o
 * @returns {{schema: string, role: string, key_id: string, body_key_id: string, privateKey: import("node:crypto").KeyObject, public_key: string}}
 */
export function selectSigner({ env, floors, kindKeys, now, schema }) {
  if (!SCHEMAS.includes(schema)) throw new SignRefused("E_SCHEMA", `no signer for ${schema}; the games kind keys sign ${SCHEMAS.join(" and ")}`);
  const role = env[ENV_KEYS.next] ? "next" : env[ENV_KEYS.current] ? "current" : null;
  if (!role) throw new SignRefused("E_KEY_ABSENT", `neither ${ENV_KEYS.current} nor ${ENV_KEYS.next} is set; this job is not in the publish-games environment`);
  const authorised = kindKeys[role];
  if (spentBySchema(floors)[schema].has(authorised.key_id)) {
    throw new SignRefused("E_KEY_RETIRED", `${authorised.key_id} was rotated away from for ${schema} and is spent for it; sign with ${ENV_KEYS.next}, or re-authorise in a ceremony`);
  }
  const privateKey = privateKeyFromSeed(seedFrom(env[ENV_KEYS[role]], ENV_KEYS[role]));
  const pub = publicKeyBase64(privateKey);
  if (pub !== authorised.public_key) {
    throw new SignRefused("E_KEY_NOT_AUTHORISED", `${ENV_KEYS[role]} is not the ${KIND} ${role} key trust.json authorises (${authorised.key_id}); clients would refuse what it signs`);
  }
  if (authorised.notBefore > now) {
    throw new SignRefused("E_KEY_NOT_YET_VALID", `${authorised.key_id} is authorised from ${authorised.not_before}`);
  }
  return { schema, role, key_id: authorised.key_id, body_key_id: BODY_KEY_ID[role], privateKey, public_key: pub };
}

/** A signer for each schema, chosen by the same environment. */
export function selectSigners({ env, floors, kindKeys, now }) {
  return Object.fromEntries(SCHEMAS.map((schema) => [schema, selectSigner({ env, floors, kindKeys, now, schema })]));
}

/** issued_at for this run: now, or just above the kind's floors, never more than a day ahead. */
export function nextIssuedAt({ now, floors }) {
  const issued = Math.max(now, (floors?.index ?? 0) + 1, (floors?.withdrawn ?? 0) + 1);
  if (issued > now + MAX_AHEAD_SECONDS) {
    throw new SignRefused("E_SERIAL_AHEAD", `the ${KIND} serial floor would put issued_at ${issued - now}s ahead of the clock; clients refuse more than a day`);
  }
  return issued;
}

const COMMENT = {
  [INDEX_SCHEMA]: "astra.games.index/1 — signed by astra-games-catalogue. Only `signed` is authenticated; verify it under the domain your own code names.",
  [WITHDRAWN_SCHEMA]: "astra.games.withdrawn/1 — signed by astra-games-catalogue. Only `signed` is authenticated; verify it under the domain your own code names.",
};

/**
 * Build, sign and self-verify both documents. Returns the envelopes and the
 * floors to persist; throws SignRefused rather than return anything a client
 * would refuse.
 *
 * `signers` maps each schema to the signer selected for it (selectSigners);
 * the spent ledger is checked again here and moves per schema: a document of
 * a schema signed by next spends current for that schema only.
 *
 * @param {{state: object, seedLoaders: object, signers: Record<string, object>, kindKeys: object, now: number, members?: object, expirySeconds?: number}} o
 */
export function signBoth({ state, seedLoaders, signers, kindKeys, now, members, expirySeconds = EXPIRY_SECONDS }) {
  if (expirySeconds > MAX_SPAN_SECONDS) throw new SignRefused("E_EXPIRY_TOO_LONG", `a signature lives at most ${MAX_SPAN_SECONDS / 86400} days`);
  const spent = spentBySchema(state.floors);
  for (const schema of SCHEMAS) {
    const signer = signers?.[schema];
    if (signer?.schema !== schema) throw new SignRefused("E_SCHEMA", `no signer was selected for ${schema}`);
    if (spent[schema].has(signer.key_id)) throw new SignRefused("E_KEY_RETIRED", `${signer.key_id} is spent for ${schema}`);
  }
  const issuedAt = nextIssuedAt({ now, floors: state.floors });
  const indexBody = buildIndexBody({ state, seedLoaders, issuedAt, keyId: signers[INDEX_SCHEMA].body_key_id, members, expirySeconds });
  const withdrawnBody = buildWithdrawnBody({ state, issuedAt, keyId: signers[WITHDRAWN_SCHEMA].body_key_id, expirySeconds });
  const sign = (domain, signed) => ({ $comment: COMMENT[domain], ...signEnvelope({ domain, signed, signers: [{ key_id: signers[domain].key_id, privateKey: signers[domain].privateKey }] }) });
  const index = sign(INDEX_SCHEMA, indexBody);
  const withdrawn = sign(WITHDRAWN_SCHEMA, withdrawnBody);

  const [pi, pw] = verifyDocuments([
    { envelope: index, domain: INDEX_SCHEMA },
    { envelope: withdrawn, domain: WITHDRAWN_SCHEMA, indexBody },
  ], { kindKeys, now, strict: true });
  const problems = [...pi.map((p) => `index: ${p}`), ...pw.map((p) => `withdrawn: ${p}`)];
  if (problems.length) throw new SignRefused("E_SELF_VERIFY", problems.join("; "));

  for (const schema of SCHEMAS) if (signers[schema].role === "next") spent[schema].add(kindKeys.current.key_id);
  const floors = { kind: KIND, index: issuedAt, withdrawn: issuedAt, spent: Object.fromEntries(SCHEMAS.map((s) => [s, [...spent[s]].sort()])) };
  return { index, withdrawn, floors, issuedAt };
}
