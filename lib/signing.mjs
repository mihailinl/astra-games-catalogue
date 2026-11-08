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
// ── keys: roles come from trust.json, and the ceremony bridge is always on ─
//
// lib/trust.mjs reads the two `games` kind keys out of the root-signed
// trust.json. The publish-games environment holds up to two seeds, in
// GAMES_SIGNING_KEY_CURRENT and GAMES_SIGNING_KEY_NEXT, each the base64 of a
// raw 32-byte Ed25519 seed, read from the environment only, never from an
// argument. The slot a seed sits in decides NOTHING. Each seed's public key is
// looked up in trust.json, and its role there is what counts: `current`,
// `next`, or unlisted. A ceremony that promotes `next` to `current` changes
// the roles while the environment stays as it was, so a role read from a slot
// name is wrong from the moment trust.json N+1 is published: the old rule took
// GAMES_SIGNING_KEY_NEXT for trust's `next`, which was now a fresh key, and
// refused the promoted key as E_KEY_NOT_AUTHORISED.
//
// For each document schema:
//
//   1. A LISTED seed is authorised by trust.json, from its not_before
//      (E_KEY_NOT_YET_VALID before it; E_KEY_MALFORMED for a seed that is not
//      32 bytes). One key in both slots is a misplaced secret
//      (E_KEY_NOT_AUTHORISED).
//   2. An UNLISTED seed may only CO-SIGN, and only when floors.json records
//      its PUBLIC KEY as spent for that schema: it is a `current` the signer
//      rotated away from, which a ceremony has since dropped from trust.json.
//      Its key id is not in trust.json any more, so the ledger is what names
//      it. Any other unlisted seed (another kind's key, the plugin index's
//      key, a typo) is E_KEY_NOT_AUTHORISED.
//   3. The PRIMARY signer is the listed key that is not spent for the schema,
//      `next` before `current`. No such key is E_KEY_RETIRED (every seed is
//      spent) or E_KEY_ABSENT (no seed at all).
//   4. Every other seed CO-SIGNS, after the primary: a listed `current` (spent,
//      or about to be by rule 6) or an unlisted spent key (rule 2). A SPENT KEY
//      NEVER SIGNS ALONE. signBoth checks that again for whatever signer it is
//      handed, not only here.
//   5. The body's key_id is `games-current` whenever a key holding trust's
//      `current` role is among the signers, and `games-next` only when `next`
//      signs without one.
//   6. A document signed with trust's `next` among its signers spends trust's
//      `current` for that schema (below).
//
// Why that is the whole ceremony bridge, with no flag (AstraPlugins
// games-index-v1 §3, "A ceremony that promotes `next` to `current` is bridged
// by a co-signature"). Trust N lists current A and next B, and the signer has
// moved to B. Trust N+1 lists current B and a fresh next C. A document only B
// signed is refused on one side or the other: under N+1 a `games-next` body
// names a role B no longer holds, and under N a `games-current` body names a
// role B does not hold yet. A client that took N+1 would discard every copy
// it holds, and no newer trust.json would exist to cure it. A document signed
// by A AND B under `games-current` verifies under both: under N both roles
// verify and the claim is among them; under N+1 A is unlisted and ignored and
// B verifies as `current`. With both seeds in the environment after a
// rotation, rules 3 to 5 produce exactly that document, in every run, under N
// and under N+1 alike. So every document served after a rotation is already
// ready for the ceremony, and the ceremony has no ordering step to forget:
// the operator runs bin/ceremony-ready.mjs against what is served, then
// publishes N+1. A keeps co-signing until the next promotion replaces it.
// Under N+1 no client can verify A's signature and it changes nothing; it is
// there for the clients still on N. Only B alone (A's seed removed) signs
// `games-next` under N, as a routine rotation always did.
//
// "Spent" is per DOCUMENT SCHEMA, not per kind (minice design §11a.9,
// 2026-11-02; AstraPlugins games-index-v1 §3). The index and the withdrawn
// list are signed and served on separate schedules, and a client retires
// current for one schema only when a next-signed document OF THAT SCHEMA
// arrives, so a still-valid current-signed withdrawn list is never refused
// because the index rotated first: withdrawals must never go dark. The
// signer keeps the same ledger. floors.json's `spent` maps each schema to the
// keys spent for it, each {key_id, public_key}, and each document is signed
// by the signer selected for its own schema. The public key is recorded
// because after a ceremony the spent key is in no trust.json, and its public
// key is how its seed is recognised (rule 2). A bare key id is an entry
// written before 2026-11-07: it still reads, and still spends a listed key of
// that id, but it cannot vouch for an unlisted seed; the next run with `next`
// among its signers records the public key beside it.
//
// ── what the documents carry ──────────────────────────────────────────────
//
// signatures[] holds one entry per signer, the primary first. Its key_id is
// the kind key's id (e.g. astra-games-2026a; for an unlisted co-signer, the id
// the ledger recorded). The body's key_id is a ROLE, `games-current` or
// `games-next`, because the pinned games-index-v1/withdrawn-v1 schemas
// enumerate exactly those two. A verifier collects every key that verifies,
// whatever their order (documents.mjs verifyEnvelopeAll), and checks that the
// role the body names is among theirs.
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

import crypto from "node:crypto";

import { privateKeyFromSeed, publicKeyBase64, publicKeyFromBase64, signEnvelope, signingDigest } from "./vendor/astra-registry/bot/lib/sign.mjs";
import {
  buildIndexBody, buildWithdrawnBody, EXPIRY_SECONDS, INDEX_SCHEMA, MAX_AHEAD_SECONDS, MAX_SPAN_SECONDS, verifyDocuments, WITHDRAWN_SCHEMA,
} from "./documents.mjs";
import { BODY_KEY_ID, KEY_ID, KIND, rawKey, ROLES } from "./trust.mjs";

export const ENV_KEYS = Object.freeze({ current: "GAMES_SIGNING_KEY_CURRENT", next: "GAMES_SIGNING_KEY_NEXT" });
/** The two slots, in the order their seeds co-sign. A slot's name is not a role (header). */
const SLOTS = Object.freeze([ENV_KEYS.current, ENV_KEYS.next]);

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

// ── the spent ledger ──────────────────────────────────────────────────────

/**
 * The keys spent for each document schema, out of floors.json's `spent`: each
 * {key_id, public_key}, public_key null for a bare key id written before
 * 2026-11-07. Fail closed: anything that is not a shape this code writes, or
 * wrote, refuses the run rather than read as "nothing spent", which would let
 * a spent key sign again.
 *
 * Shapes that read:
 *   {"<schema>": ["<key id>" | {"key_id", "public_key"}, …], …}  exactly the
 *       two schemas; an object entry since 2026-11-07, a bare id before;
 *   ["<key id>", …]  the per-kind ledger written before 2026-11-02, when one
 *       key signed both documents in every run: a key spent then was spent
 *       for both schemas, so it counts for both.
 *
 * @param {object} floors
 * @returns {Record<string, {key_id: string, public_key: string|null}[]>}
 */
export function spentLedger(floors) {
  const out = Object.fromEntries(SCHEMAS.map((s) => [s, []]));
  const raw = floors?.spent;
  if (raw === undefined) return out;
  const refuse = (what) => {
    throw new SignRefused("E_STATE_SPENT", `floors.json spent${what}; refusing to guess which keys are spent`);
  };
  const entry = (x, where, { objects }) => {
    if (typeof x === "string" && x.length > 0) return { key_id: x, public_key: null };
    const isEntry = objects && x !== null && typeof x === "object" && !Array.isArray(x)
      && Object.keys(x).sort().join(",") === "key_id,public_key"
      && typeof x.key_id === "string" && KEY_ID.test(x.key_id) && rawKey(x.public_key) !== null;
    if (!isEntry) refuse(`${where} holds ${JSON.stringify(x)}, which is neither a key id nor {key_id, public_key}`);
    return { key_id: x.key_id, public_key: x.public_key };
  };
  const list = (v, where, opts) => {
    if (!Array.isArray(v)) refuse(`${where} is not a list of spent keys`);
    return v.map((x) => entry(x, where, opts));
  };
  if (Array.isArray(raw)) {
    const legacy = list(raw, "", { objects: false });
    for (const s of SCHEMAS) out[s].push(...legacy);
    return out;
  }
  if (raw === null || typeof raw !== "object") refuse(" is neither a per-schema map nor a list");
  const names = Object.keys(raw);
  if (names.length !== SCHEMAS.length || !SCHEMAS.every((s) => Object.hasOwn(raw, s))) {
    refuse(` must name exactly ${SCHEMAS.join(" and ")}, not ${names.join(", ") || "nothing"}`);
  }
  for (const s of SCHEMAS) out[s].push(...list(raw[s], `[${s}]`, { objects: true }));
  return out;
}

/** The key ids spent for each document schema (spentLedger, ids only). */
export function spentBySchema(floors) {
  return Object.fromEntries(Object.entries(spentLedger(floors)).map(([s, entries]) => [s, new Set(entries.map((e) => e.key_id))]));
}

/** A key trust.json lists is spent for a schema when the ledger names its id or its public key. */
const listedSpent = (entries, k) => entries.some((e) => e.key_id === k.key_id || (e.public_key !== null && e.public_key === k.public_key));

/** The ledger entry that records an UNLISTED key as spent: by public key only, since trust.json no longer names it. */
const unlistedSpent = (entries, publicKey) => entries.find((e) => e.public_key !== null && e.public_key === publicKey) ?? null;

/** One schema's ledger as floors.json stores it: deduplicated, sorted, a bare id only where no public key is known. */
function ledgerOut(entries) {
  const withKey = new Set(entries.filter((e) => e.public_key !== null).map((e) => e.key_id));
  const seen = new Map();
  for (const e of entries) {
    if (e.public_key === null && withKey.has(e.key_id)) continue;
    seen.set(`${e.key_id}\u0000${e.public_key ?? ""}`, e);
  }
  const order = (x, y) => (x < y ? -1 : x > y ? 1 : 0);
  return [...seen.values()]
    .sort((a, b) => order(a.key_id, b.key_id) || order(a.public_key ?? "", b.public_key ?? ""))
    .map((e) => (e.public_key === null ? e.key_id : { key_id: e.key_id, public_key: e.public_key }));
}

// ── selection ─────────────────────────────────────────────────────────────

/** trust.json's role for a public key: "current", "next", or null when it is not one of the kind's two keys. */
function roleOf(publicKey, kindKeys) {
  return ROLES.find((r) => kindKeys[r].public_key === publicKey) ?? null;
}

/** The body's key_id for a set of signers (header, rule 5). */
export function bodyKeyIdOf(keys) {
  if (keys.some((k) => k.role === "current")) return BODY_KEY_ID.current;
  if (keys.some((k) => k.role === "next")) return BODY_KEY_ID.next;
  throw new SignRefused("E_KEY_NOT_AUTHORISED", `no key trust.json lists for ${KIND} is among the signers`);
}

/** The seeds the environment holds, slot by slot; one key in both slots is refused. */
function seedsOf(env) {
  const seeds = [];
  for (const slot of SLOTS) {
    if (!env?.[slot]) continue;
    const privateKey = privateKeyFromSeed(seedFrom(env[slot], slot));
    const publicKey = publicKeyBase64(privateKey);
    const twin = seeds.find((s) => s.public_key === publicKey);
    if (twin) throw new SignRefused("E_KEY_NOT_AUTHORISED", `${slot} holds the same key as ${twin.slot}; one key in both slots is a misplaced secret, not a rotation`);
    seeds.push({ slot, privateKey, public_key: publicKey });
  }
  return seeds;
}

/**
 * The keys this run signs documents of `schema` with: the primary, then every
 * co-signer (header, rules 1 to 5).
 *
 * @param {{env: object, floors: object, kindKeys: {current: object, next: object}, now: number, schema: string}} o
 * @returns {{schema: string, role: string, key_id: string, public_key: string, privateKey: import("node:crypto").KeyObject,
 *            body_key_id: string, keys: {slot: string, role: string|null, key_id: string, public_key: string, spent: boolean,
 *            privateKey: import("node:crypto").KeyObject}[]}}
 *   role/key_id/public_key/privateKey are the primary's; `keys` is every signer, the primary first.
 */
export function selectSigner({ env, floors, kindKeys, now, schema }) {
  if (!SCHEMAS.includes(schema)) throw new SignRefused("E_SCHEMA", `no signer for ${schema}; the games kind keys sign ${SCHEMAS.join(" and ")}`);
  const seeds = seedsOf(env);
  if (!seeds.length) throw new SignRefused("E_KEY_ABSENT", `neither ${ENV_KEYS.current} nor ${ENV_KEYS.next} is set; this job is not in the publish-games environment`);
  const ledger = spentLedger(floors)[schema];
  const keys = seeds.map((s) => {
    const role = roleOf(s.public_key, kindKeys);
    if (role) {
      const k = kindKeys[role];
      if (k.notBefore > now) throw new SignRefused("E_KEY_NOT_YET_VALID", `${k.key_id} (in ${s.slot}) is authorised from ${k.not_before}`);
      return { slot: s.slot, role, key_id: k.key_id, public_key: s.public_key, spent: listedSpent(ledger, k), privateKey: s.privateKey };
    }
    // rule 2: an unlisted key co-signs only as a key this signer spent for this schema
    const recorded = unlistedSpent(ledger, s.public_key);
    if (!recorded) {
      throw new SignRefused("E_KEY_NOT_AUTHORISED", `${s.slot} holds a key that is neither a ${KIND} kind key of trust.json nor recorded in floors.json as spent for ${schema}; clients would refuse what it signs`);
    }
    return { slot: s.slot, role: null, key_id: recorded.key_id, public_key: s.public_key, spent: true, privateKey: s.privateKey };
  });
  // rule 3: the primary is a listed key not spent for this schema, next first
  const primary = keys.find((k) => k.role === "next" && !k.spent) ?? keys.find((k) => k.role === "current" && !k.spent);
  if (!primary) {
    const ids = keys.map((k) => k.key_id);
    throw new SignRefused("E_KEY_RETIRED", `${ids.join(" and ")} ${ids.length > 1 ? "were" : "was"} rotated away from for ${schema} and ${ids.length > 1 ? "are" : "is"} spent for it; a spent key never signs alone. Put the key that took over in the environment, or re-authorise in a ceremony`);
  }
  const ordered = [primary, ...keys.filter((k) => k !== primary)];
  return { schema, role: primary.role, key_id: primary.key_id, public_key: primary.public_key, privateKey: primary.privateKey, body_key_id: bodyKeyIdOf(ordered), keys: ordered };
}

/** The signers for each schema, chosen from the same environment. */
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
 * The signers of one schema checked against trust.json and the ledger,
 * whatever selected them: each key listed in trust.json (its role re-derived
 * here from its public key) or recorded as spent for this schema, its private
 * half matching, no key twice, and — rule 4 — at least one listed key that is
 * not spent, because a spent key never signs alone.
 */
function checkedSigners(signer, schema, { kindKeys, ledger }) {
  if (signer?.schema !== schema) throw new SignRefused("E_SCHEMA", `no signer was selected for ${schema}`);
  if (!Array.isArray(signer.keys) || !signer.keys.length) throw new SignRefused("E_KEY_ABSENT", `the signer selected for ${schema} holds no key`);
  const seen = new Set();
  const keys = signer.keys.map((k) => {
    if (seen.has(k.public_key)) throw new SignRefused("E_KEY_NOT_AUTHORISED", `${k.key_id} is among the signers of ${schema} twice`);
    seen.add(k.public_key);
    if (publicKeyBase64(k.privateKey) !== k.public_key) throw new SignRefused("E_KEY_NOT_AUTHORISED", `the private half handed in for ${k.key_id} is not that key's`);
    const role = roleOf(k.public_key, kindKeys);
    if (role) {
      if (kindKeys[role].key_id !== k.key_id) throw new SignRefused("E_KEY_NOT_AUTHORISED", `${k.key_id} is trust.json's ${role} key ${kindKeys[role].key_id} under another name`);
      return { ...k, role, spent: listedSpent(ledger, kindKeys[role]) };
    }
    const recorded = unlistedSpent(ledger, k.public_key);
    if (!recorded || recorded.key_id !== k.key_id) {
      throw new SignRefused("E_KEY_NOT_AUTHORISED", `${k.key_id} is neither a ${KIND} kind key of trust.json nor recorded in floors.json as spent for ${schema}`);
    }
    return { ...k, role: null, spent: true };
  });
  // rule 4, here as well as in selectSigner: a spent key never signs alone
  if (!keys.some((k) => k.role !== null && !k.spent)) {
    const ids = keys.map((k) => k.key_id);
    throw new SignRefused("E_KEY_RETIRED", `${ids.join(" and ")} ${ids.length > 1 ? "are" : "is"} spent for ${schema}, and a spent key never signs alone`);
  }
  return keys;
}

/**
 * Build, sign and self-verify both documents. Returns the envelopes and the
 * floors to persist; throws SignRefused rather than return anything a client
 * would refuse.
 *
 * `signers` maps each schema to the signers selected for it (selectSigners);
 * they are checked again here against trust.json and the ledger
 * (checkedSigners), the body's role is derived from the checked roles, and the
 * ledger moves per schema: a document of a schema with `next` among its
 * signers spends `current` for that schema only.
 *
 * @param {{state: object, seedLoaders: object, signers: Record<string, object>, kindKeys: object, now: number, members?: object, expirySeconds?: number}} o
 */
export function signBoth({ state, seedLoaders, signers, kindKeys, now, members, expirySeconds = EXPIRY_SECONDS }) {
  if (expirySeconds > MAX_SPAN_SECONDS) throw new SignRefused("E_EXPIRY_TOO_LONG", `a signature lives at most ${MAX_SPAN_SECONDS / 86400} days`);
  const ledger = spentLedger(state.floors);
  const keys = Object.fromEntries(SCHEMAS.map((schema) => [schema, checkedSigners(signers?.[schema], schema, { kindKeys, ledger: ledger[schema] })]));
  const issuedAt = nextIssuedAt({ now, floors: state.floors });
  const indexBody = buildIndexBody({ state, seedLoaders, issuedAt, keyId: bodyKeyIdOf(keys[INDEX_SCHEMA]), members, expirySeconds });
  const withdrawnBody = buildWithdrawnBody({ state, issuedAt, keyId: bodyKeyIdOf(keys[WITHDRAWN_SCHEMA]), expirySeconds });
  const sign = (domain, signed) => ({ $comment: COMMENT[domain], ...signEnvelope({ domain, signed, signers: keys[domain].map((k) => ({ key_id: k.key_id, privateKey: k.privateKey })) }) });
  const index = sign(INDEX_SCHEMA, indexBody);
  const withdrawn = sign(WITHDRAWN_SCHEMA, withdrawnBody);

  const [pi, pw] = verifyDocuments([
    { envelope: index, domain: INDEX_SCHEMA },
    { envelope: withdrawn, domain: WITHDRAWN_SCHEMA, indexBody },
  ], { kindKeys, now, strict: true });
  const problems = [...pi.map((p) => `index: ${p}`), ...pw.map((p) => `withdrawn: ${p}`)];
  // Every signature verifies under the key that made it. The verifier above
  // sees only this trust.json's keys, so a co-signature by a key it no longer
  // lists (the one the clients still on the previous trust.json need) is
  // checked here or nowhere.
  for (const [domain, envelope, name] of [[INDEX_SCHEMA, index, "index"], [WITHDRAWN_SCHEMA, withdrawn, "withdrawn"]]) {
    const digest = signingDigest(domain, envelope.signed);
    keys[domain].forEach((k, i) => {
      if (!crypto.verify(null, digest, publicKeyFromBase64(k.public_key), Buffer.from(envelope.signatures[i].sig, "base64"))) problems.push(`${name}: ${k.key_id}'s signature does not verify under its own key`);
    });
  }
  if (problems.length) throw new SignRefused("E_SELF_VERIFY", problems.join("; "));

  // rule 6: `next` among a schema's signers spends `current` for that schema
  for (const schema of SCHEMAS) {
    if (keys[schema].some((k) => k.role === "next")) ledger[schema].push({ key_id: kindKeys.current.key_id, public_key: kindKeys.current.public_key });
  }
  const floors = { kind: KIND, index: issuedAt, withdrawn: issuedAt, spent: Object.fromEntries(SCHEMAS.map((s) => [s, ledgerOut(ledger[s])])) };
  const signedBy = Object.fromEntries(SCHEMAS.map((s) => [s, keys[s].map((k) => k.key_id)]));
  return { index, withdrawn, floors, issuedAt, signedBy };
}
