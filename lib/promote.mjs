// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The GitHub side of first-party promotion (A§5.1 promote.yml; A§4.4 M7).
//
// A first-party release is uploaded as a PRERELEASE, ingested, and listed
// only when an M_PROMOTE act says so (lib/acts.mjs) — that act re-signs the
// index with the release in it. This module then makes GitHub agree with
// what the signed documents say, AFTER they were signed:
//
//   promote  a first-party release the signed index lists, still a
//            prerelease on GitHub → stable (so 0.2.7-era clients, which read
//            GitHub's latest stable, see it only once the catalogue has
//            signed it);
//   demote   a first-party release a signed `revoke` row covers, stable on
//            GitHub → back to prerelease (M7).
//
// It reads the SIGNED documents, never the state, so it can only ever do
// what a signature already said. The token is a GitHub App's, scoped to
// contents:write on the first-party repositories only (promote.yml); it
// signs nothing and the signing secrets are not in its environment.

import { satisfies } from "./semver.mjs";

/**
 * @param {{index: object, withdrawn: object, firstParty: object}} o signed bodies
 * @returns {{repo: string, repo_id: number, tag: string, want_prerelease: boolean, why: string}[]}
 */
export function planReleases({ index, withdrawn, firstParty }) {
  const fp = new Set((firstParty?.repos ?? []).map((r) => Number(r.repository_id)));
  const plan = [];
  for (const e of index.entries ?? []) {
    const repoId = Number(e.source.repo_id);
    if (!fp.has(repoId)) continue;
    const revoked = (withdrawn.rows ?? []).some(
      (r) => r.act === "revoke" && Number(r.repo_id) === repoId && (!r.entry_id || r.entry_id === e.id) && satisfies(e.version, r.versions),
    );
    plan.push({
      repo: e.source.repo,
      repo_id: repoId,
      tag: e.source.release_tag,
      want_prerelease: revoked,
      why: revoked ? "revoked: demote (M7)" : "listed in the signed index: promote",
    });
  }
  return plan;
}

/**
 * Make GitHub agree with the plan. `api` is {getRelease(repoId, tag), setPrerelease(repoId, releaseId, bool)}.
 * @returns {Promise<{tag: string, repo: string, changed: boolean, to?: string, error?: string}[]>}
 */
export async function applyPlan(plan, api) {
  const out = [];
  for (const p of plan) {
    try {
      const rel = await api.getRelease(p.repo_id, p.tag);
      if (!rel) {
        out.push({ repo: p.repo, tag: p.tag, changed: false, error: "no such release" });
        continue;
      }
      if (rel.prerelease === p.want_prerelease) {
        out.push({ repo: p.repo, tag: p.tag, changed: false });
        continue;
      }
      await api.setPrerelease(p.repo_id, rel.id, p.want_prerelease);
      out.push({ repo: p.repo, tag: p.tag, changed: true, to: p.want_prerelease ? "prerelease" : "stable" });
    } catch (e) {
      out.push({ repo: p.repo, tag: p.tag, changed: false, error: e.message });
    }
  }
  return out;
}

/** The production API, by repository id, with the App token from the environment. */
export function releasesApi({ token, fetchImpl = fetch }) {
  const headers = { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "astra-games-catalogue", Authorization: `Bearer ${token}` };
  return {
    async getRelease(repoId, tag) {
      const res = await fetchImpl(`https://api.github.com/repositories/${repoId}/releases/tags/${encodeURIComponent(tag)}`, { headers });
      if (res.status === 404) return null;
      if (!res.ok) throw new Error(`HTTP ${res.status} reading ${repoId} ${tag}`);
      return res.json();
    },
    async setPrerelease(repoId, releaseId, prerelease) {
      const res = await fetchImpl(`https://api.github.com/repositories/${repoId}/releases/${releaseId}`, {
        method: "PATCH",
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({ prerelease, make_latest: prerelease ? "false" : "true" }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status} setting prerelease=${prerelease} on ${repoId}/${releaseId}`);
    },
  };
}
