// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The precondition of a games ceremony that promotes `next` to `current`
// (AstraPlugins games-index-v1 §3, "A ceremony that promotes `next` to
// `current` is bridged by a co-signature", step 2): trust.json N+1 is
// published only when every served games document verifies under the live
// trust.json N AND under N+1. bin/ceremony-ready.mjs is the operator's door
// to it; this is the judgement, kept apart so the tests can hand in throwaway
// roots without the command line growing a way to.
//
// Why this exists. Trust N lists current A and next B, and the signer has
// moved to B. Under N+1 (current B, next C) a B-only document whose body says
// `games-next` names a role B no longer holds, so a client that takes N+1
// refuses it, discards its stored copies, and no newer trust.json exists to
// cure it. The signer now co-signs with A under `games-current` whenever both
// seeds are present (lib/signing.mjs); this checks that what the origin and
// the CDN actually SERVE is such a document, before anyone publishes N+1.
//
// For each document, all three:
//   (a) under N: every key that verifies is collected (documents.mjs
//       verifyEnvelopeAll), the body's role is among their roles, each one's
//       not_before is met, and the document has not expired;
//   (b) the same under N+1;
//   (c) N+1's `current` key is among the keys that verify it under N+1, and
//       so is some key other than N's `current`: a client that already retired
//       N's current for this schema (its mark records that key id) refuses a
//       document no other key verified.

import { INDEX_SCHEMA, signatureCheck, WITHDRAWN_SCHEMA } from "./documents.mjs";
import { kindKeysOf } from "./trust.mjs";

export const DEFAULT_TRUST_URL = "https://registry.minice.ai/registry/v1/trust.json";
export const DEFAULT_HOSTS = Object.freeze(["https://registry.minice.ai", "https://registry.knice.tech"]);
/** What a host serves, and the domain a client verifies each one under (its own constant, never the file's). */
export const SERVED = Object.freeze([
  Object.freeze({ path: "/registry/v1/games/index.json", domain: INDEX_SCHEMA }),
  Object.freeze({ path: "/registry/v1/games/withdrawn.json", domain: WITHDRAWN_SCHEMA }),
]);

/**
 * The games kind keys of a CANDIDATE trust.json N+1. Its root signature is
 * not checked: N+1 is judged before the owner signs it. Takes the envelope
 * ({signed, signatures}) or the bare body.
 */
export function candidateKindKeys(doc) {
  const body = doc !== null && typeof doc === "object" && !Array.isArray(doc) && "signed" in doc ? doc.signed : doc;
  return kindKeysOf(body);
}

/** One document under one trust.json's games keys, as a client judges it at `now`. */
export function judgeUnder(envelope, domain, kindKeys, now) {
  const { problems, verifiedBy } = signatureCheck(envelope, domain, kindKeys);
  const body = envelope?.signed;
  const out = [...problems];
  if (body?.schema !== domain) out.push(`the body's schema is ${body?.schema}, not ${domain}`);
  if (!Number.isSafeInteger(body?.expires_at)) out.push("expires_at is not an integer");
  else if (body.expires_at <= now) out.push(`it expired at ${body.expires_at} (now ${now})`);
  return { problems: out, verifiedBy };
}

/**
 * The three conditions for one served document.
 *
 * @param {{envelope: object, domain: string}} doc
 * @param {{trustN: {current: object, next: object}, trustN1: {current: object, next: object}, now: number}} o
 * @returns {{ok: boolean, failures: string[], underN: object[], underN1: object[], claim: unknown}}
 */
export function ceremonyChecks({ envelope, domain }, { trustN, trustN1, now }) {
  const a = judgeUnder(envelope, domain, trustN, now);
  const b = judgeUnder(envelope, domain, trustN1, now);
  const failures = [
    ...a.problems.map((p) => `(a) under trust N: ${p}`),
    ...b.problems.map((p) => `(b) under trust N+1: ${p}`),
  ];
  const n1Ids = b.verifiedBy.map((k) => k.key_id);
  if (!n1Ids.includes(trustN1.current.key_id)) {
    failures.push(`(c) N+1's current key ${trustN1.current.key_id} does not verify it`);
  }
  const retired = trustN.current.key_id;
  if (!n1Ids.some((id) => id !== retired)) {
    failures.push(`(c) a client that already retired ${retired} for ${domain} refuses it: no other key verifies it under N+1`);
  }
  return { ok: failures.length === 0, failures, underN: a.verifiedBy, underN1: b.verifiedBy, claim: envelope?.signed?.key_id };
}

const named = (keys) => (keys.length ? keys.map((k) => `${k.key_id} (${k.role})`).join(", ") : "no key");

/**
 * One line per document: `ok …` naming which keys verified under each trust,
 * or `FAIL …` naming the source, the schema and every failed condition.
 */
export function reportLine(source, domain, r, { serialN, serialN1 }) {
  const head = `${source} ${domain}`;
  if (r.ok) return `ok   ${head}: under N (serial ${serialN}) ${named(r.underN)}; under N+1 (serial ${serialN1}) ${named(r.underN1)}; body ${r.claim}`;
  return `FAIL ${head}: ${r.failures.join("; ")}`;
}
