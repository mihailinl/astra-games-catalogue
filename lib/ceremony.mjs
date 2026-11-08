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
// N+1 must be that promotion (promotionProblems): its `current` is N's `next`
// (same key, same id) and N's `current` is gone from it. Every other
// ceremony is refused here, because the conditions below are written for
// that one.
//
// For each document, all three:
//   (a) under N: the bytes are within the client's cap and have no duplicate
//       member; the body passes every check a verifier makes (documents.mjs,
//       strict: the schema, serial = issued_at, the span, issued_at not more
//       than a day ahead, the index's own invariants) and has not expired;
//       every key that verifies is collected (verifyEnvelopeAll), each one
//       only from its not_before, and the body's role is among theirs;
//   (b) the same under N+1;
//   (c) N+1's `current` key is among the keys that verify it under N+1; and
//       under N and under N+1 alike some key other than N's `current`
//       verifies it. A client whose mark retired N's current for this schema
//       refuses a document only that key verified (key-retired), and that
//       refusal does not make it fetch trust.json again.

import crypto from "node:crypto";

import { signingDigest, TRUST_SCHEMA } from "./vendor/astra-registry/bot/lib/sign.mjs";
import { jcs } from "./vendor/astra-registry/tools/lib/canonical.mjs";
import { bodyProblemsMany, INDEX_SCHEMA, MAX_DOCUMENT_BYTES, signatureCheck, WITHDRAWN_SCHEMA } from "./documents.mjs";
import { kindKeysOf } from "./trust.mjs";

export const HOSTS = Object.freeze(["https://registry.minice.ai", "https://registry.knice.tech"]);
export const TRUST_PATH = "/registry/v1/trust.json";
/** What a host serves, and the domain a client verifies each one under (its own constant, never the file's). */
export const SERVED = Object.freeze([
  Object.freeze({ path: "/registry/v1/games/index.json", domain: INDEX_SCHEMA }),
  Object.freeze({ path: "/registry/v1/games/withdrawn.json", domain: WITHDRAWN_SCHEMA }),
]);

// ── reading bytes the way a strict client does ────────────────────────────

/**
 * Every member name that appears twice in one object of a JSON text that
 * JSON.parse has already accepted. JSON.parse keeps the LAST of two equal
 * members without a word; the client's and the service's strict parsers
 * refuse the document, so a check that parses with JSON.parse alone can pass
 * bytes they refuse.
 *
 * @param {string} text valid JSON
 * @returns {string[]}
 */
export function duplicateMembers(text) {
  const dups = [];
  const stack = []; // per open container: {keys: Set|null (an array), expectKey: boolean}
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (ch === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      const top = stack.at(-1);
      if (top?.keys && top.expectKey) {
        const name = JSON.parse(text.slice(i, j + 1)); // "a" and "a" are one member
        if (top.keys.has(name)) dups.push(name);
        top.keys.add(name);
        top.expectKey = false;
      }
      i = j;
    } else if (ch === "{") stack.push({ keys: new Set(), expectKey: true });
    else if (ch === "[") stack.push({ keys: null, expectKey: false });
    else if (ch === "}" || ch === "]") stack.pop();
    else if (ch === "," && stack.at(-1)?.keys) stack.at(-1).expectKey = true;
  }
  return dups;
}

/**
 * Raw bytes → the parsed document, and what a strict client would refuse in
 * the bytes themselves. Throws (a SyntaxError or TypeError) when they are not
 * UTF-8 JSON at all: that is the caller's "could not read", never a verdict.
 *
 * @param {Buffer} raw
 * @param {{cap?: number|null}} o `cap`: the byte ceiling, or null for none (trust.json)
 * @returns {{doc: unknown, bytes: number, problems: string[]}}
 */
export function parseStrict(raw, { cap = MAX_DOCUMENT_BYTES } = {}) {
  const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw);
  const doc = JSON.parse(text);
  const problems = [];
  if (cap !== null && raw.length > cap) problems.push(`it is ${raw.length} bytes, over the ${cap}-byte ceiling a client refuses whole`);
  const dups = [...new Set(duplicateMembers(text))];
  if (dups.length) problems.push(`it repeats the member(s) ${dups.map((d) => JSON.stringify(d)).join(", ")}, which a strict parser refuses`);
  return { doc, bytes: raw.length, problems };
}

// ── the two trust.json documents ──────────────────────────────────────────

/** A trust.json's body: the envelope's `signed`, or the object itself when it is a bare body. */
export function trustBody(doc) {
  return doc !== null && typeof doc === "object" && !Array.isArray(doc) && "signed" in doc ? doc.signed : doc;
}

/**
 * The games kind keys of a CANDIDATE trust.json N+1. Its root signature is
 * not checked here (bin/ceremony-ready.mjs checks it when there is one).
 */
export function candidateKindKeys(doc) {
  return kindKeysOf(trustBody(doc));
}

/**
 * What the owner signs, so he signs the bytes this checked: sha256 of the
 * body's JCS, and the signing digest itself,
 * sha256("astra.registry.trust/1" ‖ 0x00 ‖ JCS(body)).
 */
export function trustBodyDigests(doc) {
  const body = trustBody(doc);
  return {
    jcs_sha256: crypto.createHash("sha256").update(jcs(body), "utf8").digest("hex"),
    signing_digest: signingDigest(TRUST_SCHEMA, body).toString("hex"),
  };
}

/**
 * N+1 must be the promotion this check is written for: N's `next` becomes
 * `current` (the same key under the same id: a client's retirement mark
 * records ids), and N's `current` is in neither role.
 *
 * @returns {string[]} empty when it is
 */
export function promotionProblems(trustN, trustN1) {
  const p = [];
  if (trustN1.current.public_key !== trustN.next.public_key) {
    p.push(`not a promotion: N+1's current key ${trustN1.current.key_id} is not N's next key ${trustN.next.key_id}`);
  } else if (trustN1.current.key_id !== trustN.next.key_id) {
    p.push(`not a promotion: N+1 renames N's next key ${trustN.next.key_id} to ${trustN1.current.key_id}; a promotion keeps the id, which clients' retirement marks record`);
  }
  for (const role of ["current", "next"]) {
    const k = trustN1[role];
    if (k.public_key === trustN.current.public_key || k.key_id === trustN.current.key_id) {
      p.push(`not a promotion: N+1 keeps N's current key ${trustN.current.key_id} (as ${role} ${k.key_id}); a promotion drops it`);
    }
  }
  return p;
}

// ── the documents ─────────────────────────────────────────────────────────

/**
 * The three conditions for one document. `bodyProblems` are the checks that
 * do not depend on the trust.json (ceremonyReport computes them for a batch);
 * they fail (a) and (b) alike.
 *
 * @param {{envelope: object, domain: string}} doc
 * @param {{trustN: {current: object, next: object}, trustN1: {current: object, next: object}, now: number, bodyProblems?: string[]}} o
 * @returns {{ok: boolean, failures: string[], underN: object[], underN1: object[], claim: unknown}}
 */
export function ceremonyChecks({ envelope, domain }, { trustN, trustN1, now, bodyProblems = [] }) {
  const a = signatureCheck(envelope, domain, trustN, now);
  const b = signatureCheck(envelope, domain, trustN1, now);
  const body = envelope?.signed;
  const both = [...bodyProblems];
  if (!Number.isSafeInteger(body?.expires_at)) both.push("expires_at is not an integer");
  else if (body.expires_at <= now) both.push(`it expired at ${body.expires_at} (now ${now})`);
  const failures = [
    ...both.map((p) => `(a)+(b) ${p}`),
    ...a.problems.map((p) => `(a) under trust N: ${p}`),
    ...b.problems.map((p) => `(b) under trust N+1: ${p}`),
  ];
  if (!b.verifiedBy.some((k) => k.key_id === trustN1.current.key_id)) {
    failures.push(`(c) N+1's current key ${trustN1.current.key_id} does not verify it`);
  }
  const retired = trustN.current.key_id;
  for (const [name, v] of [["N", a], ["N+1", b]]) {
    if (v.verifiedBy.length && !v.verifiedBy.some((k) => k.key_id !== retired)) {
      failures.push(`(c) under trust ${name}, a client that already retired ${retired} for ${domain} refuses it (key-retired): no other key verifies it`);
    }
  }
  return { ok: failures.length === 0, failures, underN: a.verifiedBy, underN1: b.verifiedBy, claim: body?.key_id };
}

/**
 * Every document of every source, judged. The body checks run once for the
 * batch (one schemalite process), strict, each withdrawn list beside the
 * index from its own source.
 *
 * @param {{source: string, domain: string, envelope: object, problems?: string[]}[]} docs
 *   `problems`: what parseStrict found in the bytes
 */
export function ceremonyReport(docs, { trustN, trustN1, now }) {
  const withBody = docs.filter((d) => d.envelope?.signed !== null && typeof d.envelope?.signed === "object" && !Array.isArray(d.envelope.signed));
  const indexOf = (source) => {
    const body = docs.find((x) => x.source === source && x.domain === INDEX_SCHEMA)?.envelope?.signed;
    return Array.isArray(body?.entries) ? body : null;
  };
  const results = bodyProblemsMany(withBody.map((d) => ({ domain: d.domain, body: d.envelope.signed, indexBody: d.domain === WITHDRAWN_SCHEMA ? indexOf(d.source) : null })), { now, strict: true });
  const bodies = new Map(withBody.map((d, i) => [d, results[i]]));
  return docs.map((d) => ({
    ...d,
    result: ceremonyChecks(d, { trustN, trustN1, now, bodyProblems: [...(d.problems ?? []), ...(bodies.get(d) ?? ["the document has no `signed` object"])] }),
  }));
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
