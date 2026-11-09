// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The catalogue's client for the plugins service's games bot doors (lane C
// design §1.3), and the pure halves of the jobs that call them.
//
// The PULL model. The service holds no GitHub credential in either
// direction (contract OD-12): the only thing it can do to this repository is
// have its waker dispatch ingest.yml or sign.yml with exactly {"ref":"main"}
// and no inputs (INV-33). So no payload ever arrives here; the `work` job of
// each workflow asks for its work, and the `report` job answers. Both run in
// the `games-service` environment, which holds NO secret: their only
// credential is a GitHub OIDC token for the audience the service pins, and
// the service pins the workflow, ref, environment, event and runner too
// (design §1.1). Nothing here signs, commits or pushes.
//
//   POST bot/games/leases          {run_id, run_attempt, max}  → astra.games.leases/1 {items, poll}
//   POST bot/games/releases        {run_id, found[{repo_id, tag}]} → {created: [lease items]}
//   POST bot/games/ingest-results  astra.games.ingest-result/1 {lease_id, candidate}
//   GET  bot/games/work            → astra.games.work/1 {acts, health|null}
//   POST bot/games/sign-results    astra.games.sign-result/1 {run_id, data_sha, issued_at, key_id, accepted, acts}
//   POST games/signed-wake         no credential, never parsed; wakes the service's fetch
//
// The base is the repository variable GAMES_SERVICE_URL, else the production
// URL below; it must be https. Every network dependency is injected, so the
// tests drive it with a fake fetch.

import { classOf } from "./codes.mjs";
import { FORBIDDEN_LEASE_MEMBERS, LEASE_ID, parseRequest } from "./ingest.mjs";

export const DEFAULT_BASE = "https://api.minice.ai/plugins/v1";
export const DEFAULT_AUDIENCE = "https://api.minice.ai/plugins/v1/games";
export const MAX_LEASES = 5;
export const MAX_POLL = 50;
/** Per repository polled: the newest releases worth telling the service about. */
export const POLL_RELEASES = 5;
export const MAX_FINDINGS = 64;
export const MAX_MESSAGE_BYTES = 2048;
// Contract 6.13.0 §4.6's bounds on the games wire. "A body past a bound is
// invalid. A sender cuts at the bound rather than send one past it" -- so
// every one of these is enforced where this catalogue builds the body that
// crosses the wire, not only trusted to the other side.
/** A candidate's parts[]. The manifest schema (maxItems 1024, vendored from
 * AstraPlugins) refuses an over-long [[integration.content]] table before
 * ingest ever runs, but ingest still builds a refused candidate's parts[]
 * from whatever content-typed files the zip actually has, so this is a
 * second, independent cut at the same bound (verified: a 1025-part manifest
 * is refused E_MANIFEST_INVALID, and its candidate's parts[] is still 1025
 * long until this cuts it). */
export const MAX_PARTS = 1024;
/** A work answer's acts[], oldest first; the rest wait for the next run. */
export const MAX_WORK_ACTS = 100;
/** A sign result's acts[]. */
export const MAX_RESULT_ACTS = 100;
/** A refused act's problems[]. */
export const MAX_PROBLEMS = 16;
/** A sign result's accepted[]: the 5 leases of a lease answer plus the 250 a register can create. */
export const MAX_ACCEPTED = 255;
// Contract 6.14.0 (minice plugins-api/src/games/wire.rs), being written now,
// adds two rules to the bot result wire, to keep RESULT_BODY_BYTES (5 MiB)
// honest while counting JSON escaping:
//   1. No C0 control character in free text, except \t \n \r -- a body with
//      any other U+0000-U+001F is refused `invalid`. Applies to every free-
//      text member this catalogue sends: a finding's message and
//      probe_code, an accepted entry's reason, every act problems[] string,
//      and a part's title (never a part's path -- see lib/content.mjs's
//      E_ARCHIVE_NAME_UNSAFE check, a control character there refuses the
//      part instead, because a path is an identity, not prose).
//   2. One act problem is at most MAX_PROBLEM_BYTES (was 2048).
// clipBytes (below) does both: it replaces a disallowed C0 with U+FFFD
// BEFORE the byte cut, so the replacement's 3 UTF-8 bytes count toward the
// bound same as any other character.
/** Every C0 control character (U+0000-U+001F) EXCEPT \t (\x09), \n (\x0a)
 * and \r (\x0d) -- the three contract 6.14.0 still allows through raw. */
const DISALLOWED_C0 = /[\x00-\x08\x0b\x0c\x0e-\x1f]/g;
/** A refused act's problems[]: at most this many UTF-8 bytes (contract 6.14.0; was 2048). */
export const MAX_PROBLEM_BYTES = 512;

export const SCHEMAS = Object.freeze({
  leases: "astra.games.leases/1",
  ingestResult: "astra.games.ingest-result/1",
  work: "astra.games.work/1",
  signResult: "astra.games.sign-result/1",
});

export class ServiceRefused extends Error {
  constructor(door, status, token) {
    super(`${door} answered HTTP ${status}${token ? ` (${token})` : ""}`);
    this.door = door;
    this.status = status;
    this.token = token;
  }
}

/**
 * Whether a ServiceRefused is the `unavailable` retry signal -- a door shut
 * before lane C's opening, a maintenance restart, or the rare
 * games_ingest_account_moved race after the server's own one retry -- rather
 * than a real failure. These are never a failed run: the lease that was not
 * settled simply expires and is re-leased (lib/service.mjs's design note
 * above bin/service.mjs's jobs). A 503 whose body is missing or unreadable
 * carries no token at all (refusalToken returns null); it reads as
 * `unavailable` only because the STATUS already says so. Any other status
 * with no token stays a failure, as does any status carrying a different
 * token.
 */
export function isUnavailable(e) {
  return e instanceof ServiceRefused && (e.token === "unavailable" || (e.token === null && e.status === 503));
}

/** The service base from the environment: https only, no trailing slash. */
export function serviceBase(env = process.env) {
  const base = String(env.GAMES_SERVICE_URL || DEFAULT_BASE).replace(/\/+$/, "");
  let u;
  try {
    u = new URL(base);
  } catch {
    throw new Error(`GAMES_SERVICE_URL ${JSON.stringify(base)} is not a URL`);
  }
  if (u.protocol !== "https:" || u.username || u.password || u.search || u.hash) {
    throw new Error(`GAMES_SERVICE_URL ${JSON.stringify(base)} is not a plain https base`);
  }
  return base;
}

/** A GitHub OIDC token for the service's audience (the job needs `id-token: write`). */
export async function oidcToken({ env = process.env, fetchImpl = fetch } = {}) {
  const reqUrl = env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const reqToken = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!reqUrl || !reqToken) throw new Error("no OIDC token request in this job (permissions: id-token: write)");
  const aud = encodeURIComponent(env.GAMES_SERVICE_AUDIENCE || DEFAULT_AUDIENCE);
  const r = await fetchImpl(`${reqUrl}&audience=${aud}`, { headers: { Authorization: `Bearer ${reqToken}` } });
  if (!r.ok) throw new Error(`the OIDC token request answered HTTP ${r.status}`);
  const { value } = await r.json();
  if (typeof value !== "string" || !value) throw new Error("the OIDC token answer carries no token");
  return value;
}

/** The refusal token of an error body, for the log only; never more than a short word. */
async function refusalToken(res) {
  try {
    const b = await res.json();
    const t = b?.error ?? b?.code ?? b?.refusal ?? null;
    return typeof t === "string" && /^[a-z_]{1,40}$/.test(t) ? t : null;
  } catch {
    return null;
  }
}

/**
 * @param {{env?: object, fetchImpl?: Function, token?: () => Promise<string>}} o
 */
export function serviceClient({ env = process.env, fetchImpl = fetch, token = null } = {}) {
  const base = serviceBase(env);
  // Contract 6.11.0 (ops PR #626, BOT-94) keeps ID-33: a token's `jti` is
  // good for ONE call, and the second call is answered `replay`. A token
  // memoised across calls (as this used to do with `cached ??= ...`) would
  // make every call after the first fail that way, so `bearer` mints a
  // fresh one every time -- never cached, not even within one client.
  const bearer = () => (token ? token() : oidcToken({ env, fetchImpl }));
  async function call(method, door, body) {
    const headers = { Authorization: `Bearer ${await bearer()}`, Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const res = await fetchImpl(`${base}/${door}`, { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    if (!res.ok) throw new ServiceRefused(door, res.status, await refusalToken(res));
    if (res.status === 204) return null;
    const text = await res.text();
    return text ? JSON.parse(text) : null;
  }
  return {
    base,
    leases: (body) => call("POST", "bot/games/leases", body),
    releases: (body) => call("POST", "bot/games/releases", body),
    ingestResult: (body) => call("POST", "bot/games/ingest-results", body),
    work: () => call("GET", "bot/games/work"),
    signResults: (body) => call("POST", "bot/games/sign-results", body),
    /** No credential, never parsed by the service; a failed wake is not a failed run (it also polls). */
    async signedWake() {
      const res = await fetchImpl(`${base}/games/signed-wake`, { method: "POST" });
      return res.status;
    },
  };
}

// ── ingest.yml `work`: lease, poll, register ─────────────────────────────

/**
 * Lease items as request files. Each item is held to parseRequest (the
 * ingest job reads it again); one that breaks its shape is dropped and
 * counted, never written, so a lease carrying an account or a plaintext token
 * never reaches an artifact of this public repository (BOT-10). Only the
 * members ingest reads are written.
 * @returns {{requests: object[], malformed: string[]}}
 */
export function leaseRequests(items) {
  const requests = [];
  const malformed = [];
  const seen = new Set();
  for (const [i, item] of (Array.isArray(items) ? items : []).entries()) {
    try {
      const r = parseRequest(item);
      if (seen.has(r.lease_id)) throw new Error(`lease ${r.lease_id} appears twice`);
      seen.add(r.lease_id);
      requests.push(r);
    } catch (e) {
      const id = typeof item?.lease_id === "string" && LEASE_ID.test(item.lease_id) ? item.lease_id : `#${i}`;
      const named = FORBIDDEN_LEASE_MEMBERS.filter((k) => item && typeof item === "object" && k in item);
      malformed.push(`${id}: ${named.length ? `carries ${named.join(", ")}` : e.message}`);
    }
  }
  return { requests, malformed };
}

/** The leases answer, read permissively: items[] and poll[], nothing else is required. */
export function readLeases(body) {
  if (!body || typeof body !== "object") throw new Error("the leases answer is not an object");
  if (body.schema !== undefined && body.schema !== SCHEMAS.leases) throw new Error(`the leases answer is ${JSON.stringify(body.schema)}, not ${SCHEMAS.leases}`);
  if (!Array.isArray(body.items)) throw new Error("the leases answer has no items[]");
  const poll = Array.isArray(body.poll) ? body.poll : [];
  const repos = [...new Set(poll.map(Number).filter((n) => Number.isSafeInteger(n) && n > 0))].slice(0, MAX_POLL);
  return { items: body.items, poll: repos };
}

/**
 * What a poll found: the newest non-draft releases of each repository, by
 * tag. A community prerelease is never ingested (E_PRERELEASE), so only a
 * first-party repository reports one. A repository GitHub did not answer
 * for is left out (asked again next run), never reported as empty.
 */
export async function pollReleases({ repoIds, github, firstPartyIds = new Set() }) {
  const found = [];
  const unanswered = [];
  for (const repoId of repoIds) {
    const r = await github.releases(repoId, POLL_RELEASES * 2);
    if (r.status !== "found") {
      if (r.status !== "not_found") unanswered.push(repoId);
      continue;
    }
    const tags = r.releases
      .filter((x) => !x.draft && (!x.prerelease || firstPartyIds.has(Number(repoId))))
      .map((x) => String(x.tag_name ?? ""))
      .filter((t) => /^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/.test(t))
      .slice(0, POLL_RELEASES);
    for (const tag of tags) found.push({ repo_id: Number(repoId), tag });
  }
  return { found, unanswered };
}

// ── ingest.yml `report`: one ingest result per lease ──────────────────────

const RANK = { refuse: 0, wait: 1, hold: 2, flag: 3 };
const rankOf = (code) => {
  try {
    return RANK[classOf(code)] ?? 4;
  } catch {
    return 4;
  }
};

/**
 * At most `max` UTF-8 bytes, cut between code points, after every
 * disallowed C0 character (contract 6.14.0, above) is replaced with U+FFFD.
 * Every free-text member this catalogue sends goes through this, so the
 * scrub is never skipped for one and not another.
 */
export function clipBytes(s, max = MAX_MESSAGE_BYTES) {
  const str = String(s ?? "").replace(DISALLOWED_C0, "\uFFFD");
  if (Buffer.byteLength(str, "utf8") <= max) return str;
  let out = "";
  let n = 0;
  for (const ch of str) {
    const b = Buffer.byteLength(ch, "utf8");
    if (n + b > max - 3) break;
    out += ch;
    n += b;
  }
  return `${out}...`;
}

/**
 * The astra.games.candidate/1 projection the result door stores (design §1.3):
 * the verdict, at most 64 findings (refusals first, each message at most
 * 2 KiB, rendered by the site as text only), the content parts the rights
 * gate asks about, and the entry's id and version. Never the entry's files,
 * the probe report or anything the data branch does not already publish.
 */
export function projectCandidate(c) {
  const findings = [...(c.findings ?? [])]
    .map((f, i) => ({ f, i }))
    .sort((a, b) => rankOf(a.f.code) - rankOf(b.f.code) || a.i - b.i)
    .slice(0, MAX_FINDINGS)
    .map(({ f }) => ({ code: String(f.code), message: clipBytes(f.message), ...(f.probe_code ? { probe_code: clipBytes(f.probe_code, 64) } : {}) }));
  return {
    schema: c.schema,
    request: { repo_id: Number(c.request?.repo_id), tag: c.request?.tag ?? null },
    verdict: c.verdict,
    findings,
    findings_total: (c.findings ?? []).length,
    flags: [...new Set(c.flags ?? [])],
    ingested_at: c.ingested_at,
    // Cut at MAX_PARTS even for a refused candidate: ingest's own schema
    // check (manifest.schema.json's maxItems 1024) stops an ACCEPTED
    // release from ever declaring more, but checkContent still runs on a
    // schema-invalid manifest and still fills c.parts from every
    // content-typed file the zip actually has, so a refused candidate's
    // parts[] is not otherwise bounded by that schema check at all.
    parts: (c.parts ?? []).slice(0, MAX_PARTS).map((p) => ({ path: p.path, kind: p.kind, sha256: p.sha256, title: clipBytes(p.title, 200) })),
    ...(c.entry ? { entry: { id: c.entry.id, version: c.entry.version, kind: c.entry.kind, sha256: c.entry.source?.sha256 ?? null } } : {}),
  };
}

export function ingestResultBody(leaseId, candidate) {
  return { schema: SCHEMAS.ingestResult, lease_id: leaseId, candidate: projectCandidate(candidate) };
}

// ── sign.yml `work` and `report` ──────────────────────────────────────────

/**
 * The work answer: acts oldest first as the service sent them, and health or
 * null. Contract 6.13.0 §4.6: at most MAX_WORK_ACTS acts, the oldest
 * unsettled ones; this catalogue processes at most that many and leaves the
 * rest for the next run (only what is processed here is ever settled, so an
 * act past the cut stays in the service's work answer until then). This is
 * a cut, never a refusal: the service already bounds what it sends, and a
 * service that somehow sent more must not make this job fail.
 */
export function readWork(body) {
  if (!body || typeof body !== "object") throw new Error("the work answer is not an object");
  if (body.schema !== undefined && body.schema !== SCHEMAS.work) throw new Error(`the work answer is ${JSON.stringify(body.schema)}, not ${SCHEMAS.work}`);
  const acts = body.acts ?? [];
  if (!Array.isArray(acts)) throw new Error("the work answer's acts is not a list");
  const health = body.health ?? null;
  if (health !== null && (typeof health !== "object" || Array.isArray(health))) throw new Error("the work answer's health is not an object or null");
  return { acts: acts.slice(0, MAX_WORK_ACTS), health };
}

/**
 * The astra.games.sign-result/1 body from bin/sign.mjs's report: every
 * candidate's outcome by its request, and every act's by its confirmation
 * ref — applied (with its seq, also for a duplicate already applied) or
 * refused (with its problems).
 */
const namesLease = (a) => typeof a?.request?.lease_id === "string" && a.request.lease_id.length > 0;

/** The accepted[] items signResultBody leaves out, because they name no lease. */
export function signUnnamed(report) {
  return (report?.accepted ?? []).filter((a) => !namesLease(a)).length;
}

export function signResultBody({ runId, dataSha, report }) {
  // Contract 6.13.0 §4.6: at most MAX_RESULT_ACTS acts[], each with at most
  // MAX_PROBLEMS problems[]. readWork already cuts the acts this job ever
  // settles to MAX_WORK_ACTS, so acts here should already be within bound;
  // this is the independent cut on the body actually sent, the same
  // belt-and-suspenders as projectCandidate's MAX_PARTS cut.
  const acts = [
    ...report.acts.map((a) => ({ ref: a.confirmation.ref, outcome: "applied", seq: a.seq })),
    ...(report.duplicateActs ?? []).map((d) => ({ ref: d.ref, outcome: "applied", seq: d.seq })),
    ...report.refusedActs.map((r) => ({ ref: r.ref ?? null, outcome: "refused", problems: r.problems.slice(0, MAX_PROBLEMS).map((p) => clipBytes(p, MAX_PROBLEM_BYTES)) })),
  ].slice(0, MAX_RESULT_ACTS);
  return {
    schema: SCHEMAS.signResult,
    run_id: Number(runId),
    data_sha: dataSha,
    issued_at: report.issuedAt,
    key_id: report.keyId,
    // BOT-96: every accepted[] item names the lease it settles. A candidate the
    // sign job could not read has no request (pipeline.mjs), and one such item
    // would make the service refuse the WHOLE result as `invalid`, leaving every
    // other release of the run unsettled. It is left out; its lease expires and
    // is re-leased, which is the retry. signUnnamed() counts what was left out.
    // MAX_ACCEPTED (255: the 5 leases of a lease answer plus the 250 a
    // register can create) is cut after that filter, on what is actually sent.
    accepted: report.accepted.filter(namesLease).slice(0, MAX_ACCEPTED).map((a) => ({ request: a.request, result: a.result, reason: clipBytes(a.reason) })),
    acts,
  };
}
