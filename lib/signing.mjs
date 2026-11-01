// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Signing both documents (A§5.3-5.4; merged §2.2, R11, R24).
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
// ── keys: current, next, and the ratchet ──────────────────────────────────
//
// Two key ids, `games-current` and `games-next`; clients compile both public
// keys (K14: keys.json here is what they compile). The signing environment
// holds GAMES_SIGNING_KEY_CURRENT; GAMES_SIGNING_KEY_NEXT stays offline
// until the ratchet. When NEXT is present, NEXT signs: the first document a
// client verifies under next retires current on that client for good, so
// once next has signed anything, current must never sign again — a document
// under a retired key is refused by every client that saw next. floors.json
// records that, and the signer refuses (E_KEY_RETIRED) rather than publish
// something half the clients will drop.
//
// Each value is the base64 of the raw 32-byte Ed25519 seed, the same
// spelling the plugin registry's ASTRA_INDEX_SIGNING_KEY uses. It is read
// from the environment only, never from an argument (a command line lands in
// `ps` and in logs).
//
// ── serial, freshness, floors ─────────────────────────────────────────────
//
// serial = issued_at, Unix seconds. Each key keeps its own floor per
// document: a new serial is strictly above the last one that key signed, so
// two runs in one second, or a runner whose clock stepped back, still move
// forward. A serial that would have to sit more than 1 day ahead of the clock
// to clear the floor is refused (clients refuse it). expires_at = issued_at
// + 7 days, under the 8-day cap. Both documents are signed in every run, with
// one issued_at, so a client never sees a fresh index beside a stale
// withdrawal list.

import { privateKeyFromSeed, publicKeyBase64, signEnvelope } from "./vendor/astra-registry/bot/lib/sign.mjs";
import {
  buildIndexBody, buildWithdrawnBody, INDEX_SCHEMA, MAX_AHEAD_SECONDS, verifyDocuments, WITHDRAWN_SCHEMA,
} from "./documents.mjs";

export const KEY_IDS = Object.freeze({ current: "games-current", next: "games-next" });
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

/**
 * The one key this run signs with.
 *
 * @param {{env: object, floors: object, keys: {key_id: string, public_key: string|null}[]}} o
 * @returns {{key_id: string, privateKey: import("node:crypto").KeyObject, public_key: string}}
 */
export function selectSigner({ env, floors, keys }) {
  const role = env[ENV_KEYS.next] ? "next" : env[ENV_KEYS.current] ? "current" : null;
  if (!role) throw new SignRefused("E_KEY_ABSENT", `neither ${ENV_KEYS.current} nor ${ENV_KEYS.next} is set; this job is not in the games-signing environment`);
  const key_id = KEY_IDS[role];
  if (role === "current" && floors?.[KEY_IDS.next]) {
    throw new SignRefused("E_KEY_RETIRED", "games-next has signed before, so every client that saw it has retired games-current; sign with GAMES_SIGNING_KEY_NEXT");
  }
  const privateKey = privateKeyFromSeed(seedFrom(env[ENV_KEYS[role]], ENV_KEYS[role]));
  const pub = publicKeyBase64(privateKey);
  const published = (keys ?? []).find((k) => k.key_id === key_id);
  if (!published?.public_key) {
    throw new SignRefused("E_KEY_NOT_PUBLISHED", `keys.json publishes no public key for ${key_id}; clients could not verify what this run signs (K14)`);
  }
  if (published.public_key !== pub) {
    throw new SignRefused("E_KEY_NOT_PUBLISHED", `the ${key_id} secret is not the key keys.json publishes for ${key_id} (K14)`);
  }
  return { key_id, privateKey, public_key: pub };
}

/** issued_at for this run: now, or just above the signing key's floors, never more than a day ahead. */
export function nextIssuedAt({ now, floors, keyId }) {
  const f = floors?.[keyId] ?? {};
  const issued = Math.max(now, (f.index ?? 0) + 1, (f.withdrawn ?? 0) + 1);
  if (issued > now + MAX_AHEAD_SECONDS) {
    throw new SignRefused("E_SERIAL_AHEAD", `${keyId}'s floor would put issued_at ${issued - now}s ahead of the clock; clients refuse more than a day`);
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
 * @param {{state: object, seedLoaders: object, signer: object, keys: object[], now: number, members?: object}} o
 */
export function signBoth({ state, seedLoaders, signer, keys, now, members }) {
  const issuedAt = nextIssuedAt({ now, floors: state.floors, keyId: signer.key_id });
  const indexBody = buildIndexBody({ state, seedLoaders, issuedAt, keyId: signer.key_id, members });
  const withdrawnBody = buildWithdrawnBody({ state, issuedAt, keyId: signer.key_id });
  const sign = (domain, signed) => ({ $comment: COMMENT[domain], ...signEnvelope({ domain, signed, signers: [{ key_id: signer.key_id, privateKey: signer.privateKey }] }) });
  const index = sign(INDEX_SCHEMA, indexBody);
  const withdrawn = sign(WITHDRAWN_SCHEMA, withdrawnBody);

  const [pi, pw] = verifyDocuments([
    { envelope: index, domain: INDEX_SCHEMA },
    { envelope: withdrawn, domain: WITHDRAWN_SCHEMA, indexBody },
  ], { keys, now, strict: true });
  const problems = [...pi.map((p) => `index: ${p}`), ...pw.map((p) => `withdrawn: ${p}`)];
  if (problems.length) throw new SignRefused("E_SELF_VERIFY", problems.join("; "));

  const floors = { ...state.floors, [signer.key_id]: { index: issuedAt, withdrawn: issuedAt } };
  return { index, withdrawn, floors, issuedAt };
}
