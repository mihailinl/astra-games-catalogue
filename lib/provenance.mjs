// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Where a release came from (A§4.1 as amended by merged §5.1).
//
// COMMUNITY releases carry GitHub's build attestation. The certificate is
// read and checked by the plugin registry's own code, vendored unchanged
// (lib/vendor/astra-registry/bot/lib/{attestation,certificate}.mjs, canary
// K9): `extractSignerFacts` reads the ten Fulcio fields out of the
// certificate (never the predicate), `checkCertificateRows` holds presence,
// `.11` github-hosted, `.14` refs/tags/<tag> and `.20`, and
// `classifyGhFailure` tells "no attestation" from "could not ask". This file
// adds only what differs for games:
//
//   * the signer workflow is the AUTHOR's (a copied template, not a reusable
//     workflow in AstraPlugins), so there is no workflow-SHA allowlist and
//     `.9` is held only to its shape; it is recorded as `workflow_path`;
//   * `.20` may also be `release` (A§4.1's table; the plugin bot accepts
//     `push` only). The vendored row check is asked about `push` in that one
//     case and the value is then held to {push, release} here;
//   * `.13` must equal the tag's PEELED commit, `.15` the repository id and
//     `.17` the repository's current owner id. A certificate owner that is
//     not the current owner is refused; a current owner that is not the
//     BOUND owner is a transfer, and that is a hold for a person
//     (ingest.mjs), not a refusal.
//
// FIRST-PARTY releases are admitted by digest pin from first-party.json in
// place of an attestation (merged §5.1 (c)).

import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { classifyGhFailure, extractSignerFacts } from "./vendor/astra-registry/bot/lib/attestation.mjs";
import { checkCertificateRows, repoFromUri } from "./vendor/astra-registry/bot/lib/certificate.mjs";
import { CODES, finding } from "./codes.mjs";

const execFileAsync = promisify(execFile);

export const ACCEPTED_EVENTS = Object.freeze(["push", "release"]);

/** The production `gh` runner: an argument array, never a shell string. */
export async function runGh(args) {
  return execFileAsync("gh", args, { maxBuffer: 16 * 1024 * 1024, timeout: 120_000 });
}

/** `https://github.com/o/r/.github/workflows/x.yml@ref` → {repo: "o/r", path: ".github/workflows/x.yml"}. */
export function splitWorkflowRef(uri) {
  const m = /^https:\/\/github\.com\/([A-Za-z0-9._-]+\/[A-Za-z0-9._-]+)\/(.+?)@(.+)$/.exec(String(uri ?? ""));
  return m ? { repo: m[1], path: m[2], ref: m[3] } : null;
}

/**
 * @param {{file: string, repo: string, repoId: number, currentOwnerId: number,
 *          tag: string, tagCommit: string, sha256: string,
 *          gh?: (args: string[]) => Promise<{stdout: string}>}} o
 * @returns {Promise<{findings: object[], facts: null | {commit: string, workflow_path: string, event: string, run: string|null}}>}
 */
export async function verifyCommunityAttestation(o) {
  const gh = o.gh ?? runGh;
  const findings = [];
  const args = ["attestation", "verify", o.file, "--repo", o.repo, "--format", "json"];

  let parsed;
  try {
    const { stdout } = await gh(args);
    parsed = JSON.parse(stdout);
  } catch (e) {
    const c = classifyGhFailure(e, [o.file, o.repo]);
    const first = `${e.stderr ?? ""}${e.message ?? ""}`.trim().split("\n")[0] || "failed";
    const code = c.missing ? CODES.E_ATTESTATION_MISSING : c.unavailable ? CODES.W_ATTESTATION_UNCHECKED : CODES.E_ATTESTATION_INVALID;
    findings.push(finding(code, `gh attestation verify --repo ${o.repo}: ${first}`));
    return { findings, facts: null };
  }

  const facts = extractSignerFacts(parsed, o.sha256);
  for (const p of facts.problems) findings.push(finding(CODES.E_ATTESTATION_INVALID, p.message));

  // Strictly the attestation that names THESE bytes: a subjectless result is
  // a hand-written shape the plugin registry tolerates and this one does not.
  if (!facts.matched) {
    findings.push(finding(
      CODES.E_ATTESTATION_SUBJECT_MISMATCH,
      `no attestation covers sha256:${o.sha256}` + (facts.subjectDigests.length ? ` (it covers ${facts.subjectDigests.join(", ")})` : ""),
    ));
    return { findings, facts: null };
  }

  const f = facts.fields;
  const wf = splitWorkflowRef(f.job_workflow_ref);
  const signerWorkflow = wf ? `${wf.repo}/${wf.path}` : "unknown/unknown";
  const event = f.event_name;
  const rowsFields = event === "release" ? { ...f, event_name: "push" } : f;
  findings.push(...checkCertificateRows({ fields: rowsFields, tag: o.tag, signerWorkflow }).map((x) => finding(x.code, x.message)));
  if (f.job_workflow_ref !== null && !wf) {
    findings.push(finding(CODES.E_ATTESTATION_INVALID, `job_workflow_ref (.9) ${JSON.stringify(f.job_workflow_ref)} is not https://github.com/<owner>/<repo>/<path>@<ref>`));
  }

  if (f.sha !== null && f.sha !== o.tagCommit) {
    findings.push(finding(CODES.E_ATTESTATION_SHA_MISMATCH, `sha (.13) is ${f.sha} and tag ${o.tag} is commit ${o.tagCommit}: these bytes were not built from the tag being listed`));
  }
  if (f.repository_id !== null && f.repository_id !== String(o.repoId)) {
    findings.push(finding(CODES.E_ATTESTATION_ID_MISMATCH, `repository_id (.15) is ${f.repository_id}, not ${o.repoId}`));
  }
  if (f.repository_owner_id !== null && f.repository_owner_id !== String(o.currentOwnerId)) {
    findings.push(finding(CODES.E_ATTESTATION_OWNER_MISMATCH, `repository_owner_id (.17) is ${f.repository_owner_id} and the repository's owner is ${o.currentOwnerId}: the build ran under another owner`));
  }
  const certRepo = repoFromUri(f.source_repository_uri);
  if (certRepo && certRepo.toLowerCase() !== o.repo.toLowerCase() && f.repository_id !== String(o.repoId)) {
    findings.push(finding(CODES.E_ATTESTATION_REPO_MISMATCH, `the attestation names ${certRepo}, not ${o.repo}`));
  }
  if (wf && wf.repo.toLowerCase() !== (certRepo ?? o.repo).toLowerCase()) {
    findings.push(finding(CODES.F_WORKFLOW_ELSEWHERE, `the build ran ${wf.repo}/${wf.path}, a workflow outside the repository`));
  }

  return {
    findings,
    facts: {
      commit: f.sha,
      workflow_path: wf ? (wf.repo.toLowerCase() === (certRepo ?? o.repo).toLowerCase() ? wf.path : `${wf.repo}/${wf.path}`) : "",
      event,
      run: f.run,
    },
  };
}

// ── first-party (merged §5.1 (c)) ─────────────────────────────────────────

/** The first-party.json row for this repository, by id AND owner id, or null. */
export function firstPartyRepo(firstParty, repoId) {
  return (firstParty?.repos ?? []).find((r) => Number(r.repository_id) === Number(repoId)) ?? null;
}

/**
 * The digest-pin rule: a pin names repository_id + tag + asset and the
 * SHA-256 the owner vouched for. No pin holds (when the rule requires one);
 * a different digest refuses.
 */
export function firstPartyPinFindings({ firstParty, repoId, tag, asset, sha256 }) {
  const pins = (firstParty?.pins ?? []).filter(
    (p) => Number(p.repository_id) === Number(repoId) && p.tag === tag && p.asset === asset,
  );
  if (pins.length === 0) {
    if (firstParty?.rule?.require_pin === false) return [];
    return [finding(CODES.H_FIRST_PARTY_UNPINNED, `first-party ${tag}/${asset} has no pin in first-party.json; the owner's release script adds {repository_id, tag, asset, sha256}`)];
  }
  if (pins.some((p) => String(p.sha256).toLowerCase() !== sha256)) {
    return [finding(CODES.E_PIN_MISMATCH, `first-party.json pins ${tag}/${asset} to ${pins.map((p) => p.sha256).join(", ")} and the asset hashes to ${sha256}`)];
  }
  return [];
}

/** The `source` facts a digest-pinned release records in place of a certificate's. */
export const FIRST_PARTY_SOURCE = Object.freeze({ workflow_path: "first-party.json", event: "release" });
