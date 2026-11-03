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

/** At most `max` UTF-8 bytes, cut between code points. */
export function clipBytes(s, max = MAX_MESSAGE_BYTES) {
  const str = String(s ?? "");
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
    parts: (c.parts ?? []).map((p) => ({ path: p.path, kind: p.kind, sha256: p.sha256, title: clipBytes(p.title, 200) })),
    ...(c.entry ? { entry: { id: c.entry.id, version: c.entry.version, kind: c.entry.kind, sha256: c.entry.source?.sha256 ?? null } } : {}),
  };
}

export function ingestResultBody(leaseId, candidate) {
  return { schema: SCHEMAS.ingestResult, lease_id: leaseId, candidate: projectCandidate(candidate) };
}

// ── sign.yml `work` and `report` ──────────────────────────────────────────

/** The work answer: acts oldest first as the service sent them, and health or null. */
export function readWork(body) {
  if (!body || typeof body !== "object") throw new Error("the work answer is not an object");
  if (body.schema !== undefined && body.schema !== SCHEMAS.work) throw new Error(`the work answer is ${JSON.stringify(body.schema)}, not ${SCHEMAS.work}`);
  const acts = body.acts ?? [];
  if (!Array.isArray(acts)) throw new Error("the work answer's acts is not a list");
  const health = body.health ?? null;
  if (health !== null && (typeof health !== "object" || Array.isArray(health))) throw new Error("the work answer's health is not an object or null");
  return { acts, health };
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
  const acts = [
    ...report.acts.map((a) => ({ ref: a.confirmation.ref, outcome: "applied", seq: a.seq })),
    ...(report.duplicateActs ?? []).map((d) => ({ ref: d.ref, outcome: "applied", seq: d.seq })),
    ...report.refusedActs.map((r) => ({ ref: r.ref ?? null, outcome: "refused", problems: r.problems.map((p) => clipBytes(p)) })),
  ];
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
    accepted: report.accepted.filter(namesLease).map((a) => ({ request: a.request, result: a.result, reason: clipBytes(a.reason) })),
    acts,
  };
}
