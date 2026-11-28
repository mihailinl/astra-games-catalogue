#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The `work` and `report` jobs' entry point: the plugins service's games bot
// doors under a GitHub OIDC token (lib/service.mjs). These jobs run in the
// `games-service` environment, which holds no secret; nothing here signs,
// commits or pushes, and nothing the service answers is ever interpolated
// into a shell — it is written to files and read back by the next job.
//
//   node bin/service.mjs ingest-work   --out <dir>
//       lease (POST bot/games/leases), poll the repositories the answer
//       names and register what was found (POST bot/games/releases); writes
//       <dir>/games-request-<lease>.json per lease and, to $GITHUB_OUTPUT,
//       `leases` (a JSON list of lease ids) and `malformed` (a count)
//   node bin/service.mjs ingest-report --candidates <dir>
//       one astra.games.ingest-result/1 per lease in $LEASES that has a
//       candidate in <dir> (lib/candidates.mjs: either layout download-artifact
//       writes), matched by its request.lease_id; fails the job
//       (after posting the rest) on a refused post or MALFORMED > 0
//   node bin/service.mjs sign-work --out <dir>
//       GET bot/games/work into <dir>/acts.json and <dir>/health.json, and
//       counts the triggering Ingest run's candidates ($INGEST_RUN_ID); writes
//       `acts`, `health`, `candidates` and `todo` (true when there is anything
//       to sign) to $GITHUB_OUTPUT
//   node bin/service.mjs sign-report --report <sign-report.json>
//       POST bot/games/sign-results (astra.games.sign-result/1, with
//       $DATA_SHA), then POST games/signed-wake with no credential; fails the
//       job AFTER both when an act was refused
//
// Environment: GAMES_SERVICE_URL, GAMES_SERVICE_AUDIENCE (repository
// variables, optional), GAMES_REGISTER_POLLED (repository variable; "true"
// makes ingest-work's register name the repositories it polled, see
// lib/service.mjs registerBody), GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT, and the
// runner's ACTIONS_ID_TOKEN_REQUEST_URL/_TOKEN (the job's `id-token: write`).

import fs from "node:fs";
import path from "node:path";

import { githubApi } from "../lib/github.mjs";
import { readCandidates } from "../lib/candidates.mjs";
import { LEASE_ID } from "../lib/ingest.mjs";
import {
  ingestResultBody, isUnavailable, leaseRequests, MAX_LEASES, pollReleases, readLeases, readWork, registerBody, serviceClient, ServiceRefused, signResultBody, signUnnamed,
} from "../lib/service.mjs";
import { loadPolicy, writeJson } from "../lib/state.mjs";
import { ROOT } from "../lib/vendored.mjs";

/**
 * The most leases one run ingests; a lease past it expires and is leased
 * again. ingest.yml's matrix runs at max-parallel 5, so 10 is two waves --
 * inside the lease's 30-minute life. 20 was four waves, and a wave's own
 * ingest + checkout + upload time could run the fourth wave's leases past
 * the 30 minutes they were leased for, expiring before they are ever acted
 * on.
 */
export const MAX_RUN_LEASES = 10;

const output = (env, pairs) => {
  if (!env.GITHUB_OUTPUT) return;
  fs.appendFileSync(env.GITHUB_OUTPUT, Object.entries(pairs).map(([k, v]) => `${k}=${v}\n`).join(""));
};

/**
 * `unavailable` (a door shut, a maintenance restart, the rare post-retry
 * race) is not a failure: the retry already exists by design (an unreported
 * lease expires and is re-leased). This is the only line the job prints for
 * it, so a red Actions run and an owner email do not follow a condition the
 * service's own alarms already cover.
 */
const unavailableWarning = (e) => `::warning::${e.door} answered unavailable; nothing settled, the lease expires and is re-leased (the retry)`;

export async function ingestWork({ out, env = process.env, client = serviceClient({ env }), github = githubApi(), log = console }) {
  const runId = Number(env.GITHUB_RUN_ID);
  const runAttempt = Number(env.GITHUB_RUN_ATTEMPT ?? 1);
  if (!Number.isSafeInteger(runId) || runId < 1) throw new Error("GITHUB_RUN_ID is not a run id");
  try {
    const answer = readLeases(await client.leases({ run_id: runId, run_attempt: runAttempt, max: MAX_LEASES }));
    const leased = leaseRequests(answer.items);
    let created = { requests: [], malformed: [] };
    if (answer.poll.length) {
      const firstParty = loadPolicy(ROOT).firstParty;
      const firstPartyIds = new Set((firstParty?.repos ?? []).map((r) => Number(r.repository_id)));
      const polled = await pollReleases({ repoIds: answer.poll, github, firstPartyIds });
      for (const id of polled.unanswered) log.warn(`poll: GitHub did not answer for repository ${id}; asked again next run`);
      // Off (the default) the body is exactly {run_id, found}: today's service
      // refuses a member it does not know. See registerBody for when it goes.
      const register = registerBody({ runId, found: polled.found, polled: polled.polled, namePolled: env.GAMES_REGISTER_POLLED === "true" });
      for (const f of register.dropped) log.log(`::warning::poll: ${f.repo_id} ${f.tag} was found in a repository this run did not poll; left out of the register`);
      const reg = await client.releases(register.body);
      created = leaseRequests(Array.isArray(reg?.created) ? reg.created : []);
    }
    const seen = new Set();
    const requests = [...leased.requests, ...created.requests].filter((r) => !seen.has(r.lease_id) && seen.add(r.lease_id));
    const malformed = [...leased.malformed, ...created.malformed];
    for (const m of malformed) log.log(`::error::a lease was dropped, not written: ${m}`);
    const now = requests.slice(0, MAX_RUN_LEASES);
    for (const r of requests.slice(MAX_RUN_LEASES)) log.warn(`lease ${r.lease_id} is past this run's ${MAX_RUN_LEASES}; it expires and is leased again`);
    fs.mkdirSync(out, { recursive: true });
    for (const r of now) writeJson(path.join(out, `games-request-${r.lease_id}.json`), r);
    output(env, { leases: JSON.stringify(now.map((r) => r.lease_id)), malformed: malformed.length });
    log.log(`leased ${now.length} (${leased.requests.length} queued, ${created.requests.length} from a poll of ${answer.poll.length}); ${malformed.length} malformed`);
    return { leases: now.map((r) => r.lease_id), malformed };
  } catch (e) {
    if (!isUnavailable(e)) throw e;
    log.log(unavailableWarning(e));
    output(env, { leases: "[]", malformed: 0 });
    return { leases: [], malformed: [] };
  }
}

export async function ingestReport({ candidates, env = process.env, client = serviceClient({ env }), log = console }) {
  let leases;
  try {
    leases = JSON.parse(env.LEASES || "[]");
  } catch {
    throw new Error("LEASES is not a JSON list");
  }
  if (!Array.isArray(leases) || !leases.every((l) => typeof l === "string" && LEASE_ID.test(l))) throw new Error("LEASES is not a list of lease ids");
  const failed = [];
  const posted = [];
  // by the lease each candidate names: a run with ONE candidate artifact gets
  // it as <dir>/candidate.json, with no games-candidate-<lease>/ around it
  const byLease = new Map();
  for (const candidate of readCandidates(candidates)) {
    const named = candidate?.request?.lease_id;
    if (typeof named !== "string" || !leases.includes(named)) {
      failed.push(`a candidate names lease ${JSON.stringify(named)}, which this run did not lease`);
    } else if (byLease.has(named)) {
      failed.push(`${named}: more than one candidate names this lease`);
      byLease.set(named, null);
    } else {
      byLease.set(named, candidate);
    }
  }
  for (const lease of leases) {
    const candidate = byLease.get(lease);
    if (candidate === undefined) {
      log.warn(`lease ${lease}: no candidate (its ingest job broke); the lease expires and is leased again`);
      continue;
    }
    if (candidate === null) continue;
    try {
      await client.ingestResult(ingestResultBody(lease, candidate));
      posted.push(lease);
      log.log(`lease ${lease}: ${candidate.verdict} reported`);
    } catch (e) {
      if (isUnavailable(e)) {
        log.log(unavailableWarning(e));
      } else if (e instanceof ServiceRefused && ["lease_not_held", "conflict"].includes(e.token)) {
        // the lease ran out or the release moved on: the service has a newer answer
        log.warn(`lease ${lease}: ${e.message}`);
      } else {
        failed.push(`${lease}: ${e.message}`);
      }
    }
  }
  const malformed = Number(env.MALFORMED || 0);
  if (malformed > 0) failed.push(`${malformed} lease(s) were malformed and dropped by the work job (see its log)`);
  return { posted, failed };
}

const CANDIDATE_ARTIFACT = /^games-candidate-[A-Za-z0-9_-]{1,64}$/;

/**
 * signable.json is `{read_at, leases}`: WHEN the service was asked, beside its answer. The signer
 * (bin/sign.mjs readWorkFiles) refuses a list older than SIGNABLE_MAX_AGE_MS, so "Re-run failed jobs"
 * hours later -- which reuses this job's artifact without asking again -- signs no new candidate from
 * a stale list (Opus review of minice-71s, 2026-11-17, S2).
 */
export function signableFile(leases, nowMs) {
  return { read_at: new Date(nowMs).toISOString(), leases };
}

export async function signWork({ out, env = process.env, client = serviceClient({ env }), github = githubApi(), log = console, now = () => Date.now() }) {
  // Stamped BEFORE the service is asked: the list's age is never understated by the door's latency.
  const readAt = now();
  let work;
  try {
    work = readWork(await client.work());
  } catch (e) {
    if (!isUnavailable(e)) throw e;
    log.log(unavailableWarning(e));
    fs.mkdirSync(out, { recursive: true });
    writeJson(path.join(out, "acts.json"), []);
    writeJson(path.join(out, "health.json"), null);
    writeJson(path.join(out, "signable.json"), signableFile(null, readAt));
    output(env, { acts: 0, health: "0", candidates: 0, todo: "false" });
    log.log("work: unavailable; nothing to sign (resign.yml keeps the daily re-sign)");
    return { acts: 0, health: false, candidates: 0, todo: false };
  }
  const { acts, health, signable, signableProblem } = work;
  // Fail closed (lib/service.mjs checkSignable): null signs no new candidate; acts and health still apply.
  if (signable === null) log.log(`::warning::${signableProblem}; no new candidate is signed this run (acts, health and the re-sign go on)`);
  let candidates = 0;
  if (env.INGEST_RUN_ID) {
    const r = await github.runArtifacts(env.GITHUB_REPOSITORY, env.INGEST_RUN_ID);
    // an unanswered listing must not skip a run that has candidates: assume some
    if (r.status !== "found") log.warn(`GitHub did not list Ingest run ${env.INGEST_RUN_ID}'s artifacts (${r.reason}); signing as if it left candidates`);
    candidates = r.status === "found" ? r.names.filter((n) => CANDIDATE_ARTIFACT.test(n)).length : 1;
  }
  fs.mkdirSync(out, { recursive: true });
  writeJson(path.join(out, "acts.json"), acts);
  writeJson(path.join(out, "health.json"), health);
  writeJson(path.join(out, "signable.json"), signableFile(signable, readAt));
  const todo = acts.length > 0 || health !== null || candidates > 0;
  output(env, { acts: acts.length, health: health === null ? "0" : "1", candidates, todo: String(todo) });
  log.log(`work: ${acts.length} act(s), ${health === null ? "no" : "new"} health, ${candidates} candidate(s); ${todo ? "signing" : "nothing to sign (resign.yml keeps the daily re-sign)"}`);
  return { acts: acts.length, health: health !== null, candidates, todo };
}

export async function signReport({ reportFile, env = process.env, client = serviceClient({ env }), log = console }) {
  const report = JSON.parse(fs.readFileSync(reportFile, "utf8"));
  if (!/^[0-9a-f]{40}$/.test(String(env.DATA_SHA))) throw new Error("DATA_SHA is not the data commit");
  const failed = [];
  try {
    const unnamed = signUnnamed(report);
    if (unnamed) log.warn(`${unnamed} accepted item(s) name no lease (an unreadable candidate); left out, their leases expire and are re-leased`);
    // The sign gate (plugins 0144): candidates the service would not settle were never accepted, so they are in
    // no accepted[] item; they are named here and nowhere on the wire.
    const leftOut = report.leftOut ?? [];
    if (leftOut.length) log.warn(`${leftOut.length} candidate(s) left out as not signable: ${leftOut.map((l) => l.lease_id ?? "(no lease)").join(", ")}`);
    await client.signResults(signResultBody({ runId: env.GITHUB_RUN_ID, dataSha: env.DATA_SHA, report }));
    log.log(`sign result reported: ${report.accepted.length} candidate(s), ${report.acts.length} applied, ${(report.duplicateActs ?? []).length} already applied, ${report.refusedActs.length} refused`);
  } catch (e) {
    // NOT a retry, unlike the other doors: the sign job already signed and pushed the data commit, and the lease is
    // settled ONLY by this result (games_accepted is written by no other door). A swallowed `unavailable` left the job
    // green with the settlement lost, and the service then treated the candidate as never signed (plugins 0144 review,
    // S1). Fail the job, loudly, with the way out: the report job re-runs from its artifact.
    if (isUnavailable(e)) {
      log.log(`::warning::${e.door} answered unavailable; the sign result was NOT recorded (the report job fails; re-run it)`);
      failed.push(`sign-results: ${e.door} answered unavailable; the data commit is already signed and the service has NOT recorded the result. Re-run this report job ("Re-run failed jobs" on the sign run; it reads the run's games-sign-report artifact) until it succeeds`);
    } else failed.push(`sign-results: ${e.message}`);
  }
  try {
    log.log(`signed wake: HTTP ${await client.signedWake()}`);
  } catch (e) {
    // a failed wake is not a failed signing: the service also polls the data branch
    log.warn(`signed wake skipped: ${e.message}`);
  }
  if (report.refusedActs.length) failed.push(`${report.refusedActs.length} moderator act(s) refused: ${report.refusedActs.map((r) => r.ref ?? r.type).join(", ")}`);
  return { failed };
}

async function main(argv) {
  const [cmd, ...args] = argv;
  const opt = (n) => (args.indexOf(n) >= 0 ? args[args.indexOf(n) + 1] : null);
  if (cmd === "ingest-work") {
    if (!opt("--out")) throw new Error("usage: bin/service.mjs ingest-work --out <dir>");
    await ingestWork({ out: opt("--out") });
    return 0;
  }
  if (cmd === "ingest-report") {
    if (!opt("--candidates")) throw new Error("usage: bin/service.mjs ingest-report --candidates <dir>");
    const r = await ingestReport({ candidates: opt("--candidates") });
    for (const f of r.failed) console.error(`report failed: ${f}`);
    return r.failed.length ? 1 : 0;
  }
  if (cmd === "sign-work") {
    if (!opt("--out")) throw new Error("usage: bin/service.mjs sign-work --out <dir>");
    await signWork({ out: opt("--out") });
    return 0;
  }
  if (cmd === "sign-report") {
    if (!opt("--report")) throw new Error("usage: bin/service.mjs sign-report --report <sign-report.json>");
    const r = await signReport({ reportFile: opt("--report") });
    for (const f of r.failed) console.error(`report failed: ${f}`);
    return r.failed.length ? 1 : 0;
  }
  throw new Error(`unknown command ${JSON.stringify(cmd)}; one of ingest-work, ingest-report, sign-work, sign-report`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      console.error(`service: ${e.message}`);
      process.exit(1);
    },
  );
}
