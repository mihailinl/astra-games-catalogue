// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Which keys may sign the games documents: the `kind_keys` member of the
// root-signed trust.json (minice docs/architecture/2026-11-01-content-
// catalogue.md §5, "Keys"; agreed with minice-01).
//
// ── what changed, and why ──────────────────────────────────────────────────
//
// The games keys used to be two key ids compiled into the client with a
// keys.json here to match (A§5.4). They now live where every other signing
// key of the estate is authorised: trust.json, signed by the compiled ROOT
// keys, gains
//
//   "kind_keys": [ { "kind": "games", "role": "current"|"next",
//                    "key_id": "astra-games-2026a", "alg": "ed25519",
//                    "public_key": "<b64, 32 bytes>", "not_before": "<RFC 3339>" }, … ]
//
// with EXACTLY two entries per kind, both pre-authorised. So routine
// rotation is the signer switching from `current` to `next` — no client
// release, no ceremony. A ceremony (the owner's root passphrase) happens
// only on a compromise, when both keys of a kind are spent, or to add a
// kind. The key authorisation is long-lived; the short life belongs to the
// signatures (expires_at − issued_at ≤ 8 days, and a per-kind serial floor).
//
// ── the rules a verifier of astra.games.* holds ───────────────────────────
//
//   - trust.json verifies under the compiled roots (the vendored registry
//     roots.mjs, canary K9), under the domain astra.registry.trust/1, and has
//     not expired;
//   - a games document verifies ONLY under the two `games` kind keys — never
//     an `index_keys` key (the plugin index's) and never another kind's;
//   - a kind key never appears in `index_keys` (a client that predates
//     kind_keys reads only index_keys, so the separation is what stops an old
//     client accepting a kind key for the plugin index) — a trust.json that
//     breaks this is refused whole;
//   - a key is used only from its `not_before`.

import fs from "node:fs";

import { compiledRootKeys } from "./vendor/astra-registry/bot/lib/roots.mjs";
import { publicKeyFromBase64, TRUST_SCHEMA, verifyEnvelope } from "./vendor/astra-registry/bot/lib/sign.mjs";

export const KIND = "games";
export const ROLES = Object.freeze(["current", "next"]);
/** The body's `key_id` (games-index-v1.schema.json's enum names the ROLE). */
export const BODY_KEY_ID = Object.freeze({ current: "games-current", next: "games-next" });

export class TrustRefused extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.code = code;
  }
}

const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
const toSeconds = (s) => Math.floor(Date.parse(s) / 1000);

function rawKey(b64) {
  try {
    const raw = Buffer.from(String(b64), "base64");
    return raw.length === 32 && raw.toString("base64") === String(b64) ? raw : null;
  } catch {
    return null;
  }
}

/**
 * The kind's two keys out of an ALREADY VERIFIED trust body.
 * @returns {{current: object, next: object}} each {kind, role, key_id, alg, public_key, not_before, notBefore}
 */
export function kindKeysOf(signed, kind = KIND) {
  const all = Array.isArray(signed?.kind_keys) ? signed.kind_keys : null;
  if (!all) throw new TrustRefused("E_TRUST_NO_KIND_KEYS", "trust.json carries no kind_keys; nothing may sign the games documents until a ceremony adds them");
  const mine = all.filter((k) => k?.kind === kind);
  const roles = mine.map((k) => k.role).sort();
  if (mine.length !== 2 || roles[0] !== "current" || roles[1] !== "next") {
    throw new TrustRefused("E_TRUST_KIND_KEYS", `kind_keys must hold exactly one current and one next key for ${kind}; it holds ${JSON.stringify(roles)}`);
  }
  const indexKeys = Array.isArray(signed.index_keys) ? signed.index_keys : [];
  const out = {};
  for (const k of mine) {
    if (k.alg !== "ed25519") throw new TrustRefused("E_TRUST_KIND_KEYS", `${k.key_id}: alg ${JSON.stringify(k.alg)} is not ed25519`);
    if (typeof k.key_id !== "string" || !/^[a-z0-9][a-z0-9-]{2,63}$/.test(k.key_id)) throw new TrustRefused("E_TRUST_KIND_KEYS", `${JSON.stringify(k.key_id)} is not a key id`);
    if (!rawKey(k.public_key)) throw new TrustRefused("E_TRUST_KIND_KEYS", `${k.key_id}: public_key is not base64 of 32 bytes`);
    if (typeof k.not_before !== "string" || !RFC3339.test(k.not_before)) throw new TrustRefused("E_TRUST_KIND_KEYS", `${k.key_id}: not_before is not RFC 3339`);
    if (indexKeys.some((i) => i?.key_id === k.key_id || i?.public_key === k.public_key)) {
      throw new TrustRefused("E_TRUST_KIND_KEY_IN_INDEX_KEYS", `${k.key_id} is also an index key; a kind key never goes in index_keys`);
    }
    out[k.role] = { ...k, notBefore: toSeconds(k.not_before) };
  }
  // §5 (content-catalogue design ~l.330): next.not_before must be LATER than
  // current's, or the kind loses its keys -- fail closed, never "pick one".
  if (!(out.next.notBefore > out.current.notBefore)) {
    throw new TrustRefused("E_TRUST_KIND_KEYS", `${kind}'s next key (not_before ${out.next.not_before}) does not start after its current key (${out.current.not_before})`);
  }
  if (out.current.key_id === out.next.key_id || out.current.public_key === out.next.public_key) {
    throw new TrustRefused("E_TRUST_KIND_KEYS", `${kind}'s current and next are the same key`);
  }
  const otherKinds = all.filter((k) => k?.kind !== kind);
  for (const k of [out.current, out.next]) {
    if (otherKinds.some((o) => o?.public_key === k.public_key || o?.key_id === k.key_id)) {
      throw new TrustRefused("E_TRUST_KIND_KEYS", `${k.key_id} is also authorised for another kind`);
    }
  }
  return out;
}

/**
 * Read, verify and unpack trust.json.
 *
 * @param {{file?: string, doc?: object, now: number, roots?: {keys: object[]}, kind?: string}} o
 *   `roots` is the injection seam the tests hand throwaway roots through;
 *   production passes none and gets the compiled set.
 * @returns {{kindKeys: {current: object, next: object}, serial: number, signedBy: string}}
 */
export function loadTrust({ file, doc, now, roots = compiledRootKeys(), kind = KIND }) {
  let trust = doc;
  if (!trust) {
    if (!file || !fs.existsSync(file)) throw new TrustRefused("E_TRUST_ABSENT", `no trust.json at ${file}`);
    trust = JSON.parse(fs.readFileSync(file, "utf8"));
  }
  if (!roots?.keys?.length) throw new TrustRefused("E_TRUST_UNPROVISIONED", "no root keys to verify trust.json with");
  const v = verifyEnvelope(trust, TRUST_SCHEMA, roots.keys);
  if (!v.ok) throw new TrustRefused("E_TRUST_UNVERIFIED", `trust.json is not signed by a root key (${v.reason})`);
  const s = trust.signed;
  if (s?.schema !== TRUST_SCHEMA) throw new TrustRefused("E_TRUST_UNVERIFIED", `trust.json's schema is ${s?.schema}`);
  if (typeof s.expires_at === "string" && toSeconds(s.expires_at) <= now) {
    throw new TrustRefused("E_TRUST_EXPIRED", `trust.json expired at ${s.expires_at}; clients refuse it, so documents signed under it would not verify`);
  }
  return { kindKeys: kindKeysOf(s, kind), serial: s.serial ?? 0, signedBy: v.key_id };
}

/** The verifier's key set for a games document: exactly the kind's two keys, nothing else. */
export function verifyingKeys(kindKeys) {
  return ROLES.map((role) => ({ key_id: kindKeys[role].key_id, role, notBefore: kindKeys[role].notBefore, publicKey: publicKeyFromBase64(kindKeys[role].public_key) }));
}
