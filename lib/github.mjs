// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The GitHub reads ingest makes, every one BY REPOSITORY ID so a rename or a
// freed login cannot redirect it, and every one answering in the vendored
// registry's three readings: found, not found, or not answered (a wait,
// never an absence). Asset bytes and the owner file go through the vendored
// helpers unchanged (lib/vendor/astra-registry/bot/lib/github.mjs).
//
// ingest.mjs takes this object as a dependency; the tests hand in a fake
// built from fixtures/staging/.

import { downloadAsset, fileAtCommit, GitHubUnanswered } from "./vendor/astra-registry/bot/lib/github.mjs";

const API = "https://api.github.com";

function headers() {
  const h = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "astra-games-catalogue",
  };
  if (process.env.GITHUB_TOKEN) h.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  return h;
}

/** GET a JSON document; 404 → {status: "not_found"}; anything unanswered → {status: "transient"}. */
async function getJson(url, fetchImpl) {
  let res;
  try {
    res = await fetchImpl(url, { headers: headers() });
  } catch (e) {
    return { status: "transient", reason: `the request did not complete: ${e.message}` };
  }
  if (res.status === 404) return { status: "not_found", reason: "HTTP 404" };
  if (!res.ok) return { status: "transient", reason: `HTTP ${res.status}` };
  try {
    return { status: "found", body: await res.json() };
  } catch (e) {
    return { status: "transient", reason: `HTTP 200 with a body that is not JSON: ${e.message}` };
  }
}

/** Peel a tag ref to its commit: an annotated tag's object is a tag object, never the commit. */
async function peelTag(repoId, tag, fetchImpl) {
  const ref = await getJson(`${API}/repositories/${repoId}/git/ref/tags/${encodeURIComponent(tag)}`, fetchImpl);
  if (ref.status !== "found") return ref;
  let obj = ref.body?.object;
  for (let hops = 0; obj?.type === "tag" && hops < 4; hops++) {
    const t = await getJson(`${API}/repositories/${repoId}/git/tags/${obj.sha}`, fetchImpl);
    if (t.status !== "found") return t.status === "not_found" ? { status: "transient", reason: `tag object ${obj.sha} vanished` } : t;
    obj = t.body?.object;
  }
  if (obj?.type !== "commit" || !/^[0-9a-f]{40}$/.test(String(obj.sha))) {
    return { status: "transient", reason: `tag ${tag} does not peel to a commit (${JSON.stringify(obj)})` };
  }
  return { status: "found", commit: obj.sha };
}

/**
 * @returns the dependency object ingest.mjs reads GitHub through
 */
export function githubApi({ fetchImpl = fetch } = {}) {
  return {
    /** {status, repo?: {id, full_name, owner_id, owner_login, private, default_branch}} */
    async repoById(repoId) {
      const r = await getJson(`${API}/repositories/${Number(repoId)}`, fetchImpl);
      if (r.status !== "found") return r;
      const b = r.body;
      return {
        status: "found",
        repo: { id: b.id, full_name: b.full_name, owner_id: b.owner?.id, owner_login: b.owner?.login, private: b.private === true || (b.visibility !== undefined && b.visibility !== "public"), default_branch: b.default_branch },
      };
    },
    /** {status, release?: {tag_name, draft, prerelease, published_at, assets: [{name, size, digest}]}} */
    async releaseByTag(repoId, tag) {
      const r = await getJson(`${API}/repositories/${Number(repoId)}/releases/tags/${encodeURIComponent(tag)}`, fetchImpl);
      if (r.status !== "found") return r;
      return { status: "found", release: r.body };
    },
    /** The newest releases, newest first (ingest.yml's poll): {status, releases?: [{tag_name, draft, prerelease}]} */
    async releases(repoId, perPage = 10) {
      const r = await getJson(`${API}/repositories/${Number(repoId)}/releases?per_page=${Math.min(100, Math.max(1, Number(perPage) || 10))}`, fetchImpl);
      if (r.status !== "found") return r;
      return Array.isArray(r.body) ? { status: "found", releases: r.body } : { status: "transient", reason: "the releases answer is not a list" };
    },
    /** The latest stable release (Check now names no tag): {status, release?} as releaseByTag. */
    async latestRelease(repoId) {
      const r = await getJson(`${API}/repositories/${Number(repoId)}/releases/latest`, fetchImpl);
      if (r.status !== "found") return r;
      return { status: "found", release: r.body };
    },
    async tagCommit(repoId, tag) {
      return peelTag(Number(repoId), tag, fetchImpl);
    },
    /** Is `sha` reachable from the default branch? {status, reachable?} */
    async onDefaultBranch(repoId, defaultBranch, sha) {
      const r = await getJson(`${API}/repositories/${Number(repoId)}/compare/${encodeURIComponent(defaultBranch)}...${sha}`, fetchImpl);
      if (r.status !== "found") return r;
      return { status: "found", reachable: r.body?.status === "behind" || r.body?.status === "identical" };
    },
    /** GitHub's licence detection at a commit: {status: found|not_found|transient, spdx_id?} */
    async licenseAt(repoId, sha) {
      const r = await getJson(`${API}/repositories/${Number(repoId)}/license?ref=${encodeURIComponent(sha)}`, fetchImpl);
      if (r.status !== "found") return r;
      return { status: "found", spdx_id: r.body?.license?.spdx_id ?? null };
    },
    /** The owner file at a commit, by id (vendored). {status, content} */
    async fileAtCommit(repoId, sha, filePath) {
      return fileAtCommit(String(repoId), sha, filePath, { fetchImpl });
    },
    /** Capped download of the canonical asset URL (vendored). Throws; GitHubUnanswered is a wait. */
    async download(url, maxBytes) {
      return downloadAsset(url, maxBytes, fetchImpl);
    },
  };
}

export { GitHubUnanswered };
