// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The workflows, read as text and held to the rules of A§5.1 and the lane
// brief, so a later edit that breaks one fails the build:
//
//   - the ingest job holds NO secret: no `secrets.`, no environment, no write
//     permission, no push;
//   - the pull model (lane C design §1.9): no workflow takes
//     repository_dispatch, and the secret-less `games-service` environment is
//     entered only by the `work` and `report` jobs, never beside a secret;
//   - the signing secrets are named only in sign.yml and resign.yml, only
//     inside the job that declares `environment: publish-games`;
//   - every action is pinned by the commit in .github/action-pins.json (the
//     PEELED commit of its tag);
//   - deny-by-default permissions at the top, a minimal set per job;
//   - no `${{ … }}` expression inside any `run:` script — values reach a
//     script through `env:`, so nothing a dispatcher, a fork or a release
//     author wrote can become shell.

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { ROOT } from "./helpers.mjs";

const DIR = path.join(ROOT, ".github", "workflows");
const PINS = JSON.parse(fs.readFileSync(path.join(ROOT, ".github", "action-pins.json"), "utf8"));
const files = fs.readdirSync(DIR).filter((f) => f.endsWith(".yml"));
const read = (f) => fs.readFileSync(path.join(DIR, f), "utf8");
const SIGNING = ["GAMES_SIGNING_KEY_CURRENT", "GAMES_SIGNING_KEY_NEXT"];

const indentOf = (l) => l.length - l.trimStart().length;
const code = (l) => l.replace(/\s+#.*$/, "");

/** The jobs of a workflow: {name: lines[]}, by the two-space keys under `jobs:`. */
function jobs(text) {
  const lines = text.split("\n");
  const start = lines.findIndex((l) => l === "jobs:");
  const out = {};
  let cur = null;
  for (const l of lines.slice(start + 1)) {
    const m = /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(l);
    if (m) {
      cur = m[1];
      out[cur] = [];
    } else if (cur) out[cur].push(l);
  }
  return out;
}

/** `permissions:` of one job, as {scope: level}. */
function jobPermissions(lines) {
  const i = lines.findIndex((l) => /^ {4}permissions:/.test(l));
  if (i < 0) return null;
  const inline = /^ {4}permissions:\s*(\{.*\})\s*$/.exec(code(lines[i]));
  if (inline) return inline[1] === "{}" ? {} : { inline: inline[1] };
  const out = {};
  for (const l of lines.slice(i + 1)) {
    if (indentOf(l) <= 4 && l.trim()) break;
    const m = /^\s+([a-z-]+):\s*([a-z]+)/.exec(code(l));
    if (m) out[m[1]] = m[2];
  }
  return out;
}

/** Every `run:` script's lines. */
function runScripts(text) {
  const lines = text.split("\n");
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const m = /^(\s*)(?:- )?run:\s*(.*)$/.exec(lines[i]);
    if (!m) continue;
    const keyIndent = m[1].length;
    if (m[2] === "|" || m[2] === ">" || m[2] === "|-" || m[2] === ">-") {
      const block = [];
      for (let j = i + 1; j < lines.length && (lines[j].trim() === "" || indentOf(lines[j]) > keyIndent); j++) block.push(lines[j]);
      out.push(block.join("\n"));
    } else out.push(m[2]);
  }
  return out;
}

test("the four A§5.1 workflows exist, plus ci", () => {
  assert.deepEqual(files.sort(), ["ci.yml", "ingest.yml", "promote.yml", "resign.yml", "sign.yml"]);
});

test("ingest.yml holds no secret at all and cannot write; the ingest job enters no environment and can only read", () => {
  const t = read("ingest.yml");
  const body = t.split("\n").filter((l) => !l.trimStart().startsWith("#")).join("\n");
  assert.doesNotMatch(body, /secrets\./, "ingest.yml references a secret");
  for (const s of SIGNING) assert.ok(!body.includes(s), `ingest.yml names ${s}`);
  assert.doesNotMatch(body, /git push|contents:\s*write|actions:\s*write|packages:\s*write/, "ingest.yml can write");
  const ingest = jobs(t).ingest;
  assert.ok(ingest, "ingest.yml has an ingest job");
  assert.ok(!ingest.some((l) => /^\s+environment:/.test(code(l))), "the ingest job enters an environment");
  assert.deepEqual(jobPermissions(ingest), { contents: "read" }, "the ingest job's permissions");
  assert.ok(!ingest.some((l) => /id-token/.test(code(l))), "the ingest job can mint an OIDC token");
});

test("ingest.yml takes no inputs: the waker sends {ref: main} only (INV-33); the work comes from the lease files", () => {
  const t = read("ingest.yml");
  const on = t.slice(t.indexOf("\non:\n"), t.indexOf("\npermissions:"));
  assert.match(on, /\n {2}workflow_dispatch:\s*\n/, "workflow_dispatch, with nothing under it");
  assert.doesNotMatch(on, /inputs:/);
  assert.match(on, /\n {2}schedule:\n/, "a schedule fallback when the waker is down");
  assert.doesNotMatch(t, /github\.event\.(inputs|client_payload)|inputs\./, "nothing reads an event payload");
  const ingest = jobs(t).ingest.join("\n");
  assert.match(ingest, /--request "\$RUNNER_TEMP\/requests\/games-request-\$LEASE\.json"/);
  assert.match(ingest, /name: games-candidate-\$\{\{ matrix\.lease \}\}/);
});

test("the signing secrets are named only in sign.yml and resign.yml, inside the publish-games job", () => {
  for (const f of files) {
    const t = read(f);
    const named = SIGNING.filter((s) => t.split("\n").some((l) => !l.trimStart().startsWith("#") && l.includes(s)));
    if (f === "sign.yml" || f === "resign.yml") {
      assert.deepEqual(named, SIGNING, `${f} should pass both`);
      for (const [name, lines] of Object.entries(jobs(t))) {
        const uses = lines.some((l) => SIGNING.some((s) => l.includes(`secrets.${s}`)));
        if (uses) assert.ok(lines.some((l) => /^ {4}environment:\s*publish-games\s*$/.test(code(l))), `${f} job ${name} uses the signing secrets outside publish-games`);
        else assert.ok(!lines.some((l) => /environment:\s*publish-games/.test(l)), `${f} job ${name} enters publish-games without needing it`);
      }
      for (const s of SIGNING) {
        for (const l of t.split("\n").filter((x) => x.includes(s) && !x.trimStart().startsWith("#"))) {
          assert.match(l.trim(), new RegExp(`^${s}: \\$\\{\\{ secrets\\.${s} \\}\\}$`), `${f}: ${s} is referenced by name only, into env`);
        }
      }
    } else {
      assert.deepEqual(named, [], `${f} names a signing secret`);
    }
  }
});

test("every action is pinned to the peeled commit recorded in action-pins.json", () => {
  for (const f of files) {
    for (const l of read(f).split("\n")) {
      const m = /^\s*(?:- )?uses:\s*([^\s#]+)/.exec(l);
      if (!m) continue;
      const ref = /^([\w.-]+\/[\w.-]+)@([0-9a-f]{40})$/.exec(m[1]);
      assert.ok(ref, `${f}: ${m[1]} is not pinned by a commit SHA`);
      assert.ok(PINS[ref[1]], `${f}: ${ref[1]} is not in action-pins.json`);
      assert.equal(ref[2], PINS[ref[1]].sha, `${f}: ${ref[1]} is not pinned to ${PINS[ref[1]].tag}'s commit`);
      assert.match(l, new RegExp(`# ${PINS[ref[1]].tag.replace(/\./g, "\\.")}\\s*$`), `${f}: ${ref[1]}'s pin carries its tag as a comment`);
    }
  }
});

test("permissions are deny-by-default at the top and minimal per job", () => {
  const allowed = {
    "ingest.yml": { work: { contents: "read", "id-token": "write" }, ingest: { contents: "read" }, report: { contents: "read", "id-token": "write" } },
    "sign.yml": { work: { contents: "read", actions: "read", "id-token": "write" }, sign: { contents: "write", actions: "read" }, report: { contents: "read", "id-token": "write" } },
    "resign.yml": { resign: { contents: "write" } },
    "promote.yml": { promote: { contents: "read" } },
    "ci.yml": { tests: { contents: "read" }, vendored: { contents: "read" } },
  };
  for (const f of files) {
    const t = read(f);
    assert.ok(t.split("\n").includes("permissions: {}"), `${f} has no top-level permissions: {}`);
    const js = jobs(t);
    assert.deepEqual(Object.keys(js).sort(), Object.keys(allowed[f]).sort(), `${f} jobs`);
    for (const [name, lines] of Object.entries(js)) assert.deepEqual(jobPermissions(lines), allowed[f][name], `${f} job ${name}`);
  }
});

test("no `${{ }}` expression inside any run: script, and no pull_request_target", () => {
  for (const f of files) {
    const t = read(f);
    for (const s of runScripts(t)) assert.ok(!s.includes("${{"), `${f}: a run: script interpolates an expression:\n${s}`);
    assert.doesNotMatch(t, /pull_request_target/, `${f} uses pull_request_target`);
  }
});

test("sign.yml pulls its work: no event payload, a skip when there is nothing to sign, candidates by pattern, only from main's ingest.yml", () => {
  const t = read("sign.yml");
  const js = jobs(t);
  assert.doesNotMatch(t, /github\.event\.(inputs|client_payload)|--from-event|GITHUB_EVENT_PATH/, "nothing reads an event payload");
  const work = js.work.join("\n");
  assert.match(work, /node bin\/service\.mjs sign-work --out "\$RUNNER_TEMP\/work"/);
  for (const cond of ["head_branch == 'main'", "path == '.github/workflows/ingest.yml'", "head_repository.full_name == github.repository"]) {
    assert.ok(work.includes(`github.event.workflow_run.${cond}`), `the work job checks workflow_run.${cond}`);
  }
  const sign = js.sign.join("\n");
  assert.match(sign, /^ {4}if: needs\.work\.outputs\.todo == 'true'$/m, "the signing job is skipped when there is nothing to sign");
  assert.match(sign, /pattern: games-candidate-\*/);
  assert.match(sign, /--acts "\$RUNNER_TEMP\/work\/acts\.json" --health "\$RUNNER_TEMP\/work\/health\.json"/);
  assert.match(js.report.join("\n"), /node bin\/service\.mjs sign-report --report/);
  assert.match(read("resign.yml"), /\n {2}schedule:\n/, "resign.yml keeps the daily re-sign");
});

test("games-service: only the work and report jobs enter it, never beside a secret, and every one of them does", () => {
  const SERVICE_JOBS = { "ingest.yml": ["work", "report"], "sign.yml": ["work", "report"] };
  for (const f of files) {
    for (const [name, lines] of Object.entries(jobs(read(f)))) {
      const live = lines.map(code).filter((l) => !l.trimStart().startsWith("#"));
      const inService = live.some((l) => /games-service/.test(l));
      const expected = (SERVICE_JOBS[f] ?? []).includes(name);
      assert.equal(inService, expected, `${f} job ${name} ${expected ? "must" : "must not"} enter games-service`);
      if (!inService) continue;
      assert.ok(live.some((l) => /^ {4}environment:\s*games-service\s*$/.test(l)), `${f} job ${name}: games-service is its environment, by name`);
      assert.ok(!live.some((l) => /secrets[.:]/.test(l)), `${f} job ${name} references a secret beside games-service`);
      assert.equal(jobPermissions(lines)["id-token"], "write", `${f} job ${name} authenticates by OIDC`);
    }
  }
});

test("no workflow takes repository_dispatch: the service holds no credential to send one (OD-12, INV-33)", () => {
  for (const f of files) {
    const live = read(f).split("\n").filter((l) => !l.trimStart().startsWith("#")).join("\n");
    assert.doesNotMatch(live, /repository_dispatch/, `${f} listens for repository_dispatch`);
  }
});

test("the signer and the re-signer share one concurrency group; nothing cancels a signing run", () => {
  for (const f of ["sign.yml", "resign.yml"]) {
    const t = read(f);
    assert.match(t, /concurrency:\n\s+group: publish-games\n\s+cancel-in-progress: false/);
  }
});
