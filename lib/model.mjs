// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Questions about the catalogue's state that ingest, sign and the acts all
// ask, answered once.

import crypto from "node:crypto";

import { jcs } from "./vendor/astra-registry/tools/lib/canonical.mjs";
import { compare, isVersion } from "./semver.mjs";

export const sha256Hex = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

/** engine-descriptor-v1.md §1: the digest is sha256(JCS(parsed)). jcs refuses floats. */
export function descriptorDigest(descriptor) {
  return sha256Hex(Buffer.from(jcs(descriptor), "utf8"));
}

/** loaders[]: the seed on main, plus and minus what moderator acts changed. Rows are {name, sha256, default_enabled}. */
export function effectiveLoaders(seed, moderation) {
  const removed = new Set((moderation?.loaders?.remove ?? []).map((s) => String(s).toLowerCase()));
  const out = new Map();
  for (const row of [...(seed?.loaders ?? []), ...(moderation?.loaders?.add ?? [])]) {
    const sha = String(row.sha256).toLowerCase();
    if (removed.has(sha)) continue;
    out.set(sha, { name: row.name, sha256: sha, default_enabled: false });
  }
  return [...out.values()].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : a.sha256 < b.sha256 ? -1 : 1));
}

/** Every stored release of one entry id, oldest version first. */
export function versionsOf(entries, entryId) {
  return entries
    .filter((e) => e.entry.id === entryId && isVersion(e.entry.version))
    .sort((a, b) => compare(a.entry.version, b.entry.version));
}

export function latestListed(entries, entryId) {
  const v = versionsOf(entries, entryId).filter((e) => e.meta.status === "listed");
  return v.length ? v[v.length - 1] : null;
}

/** The entry ids hosted by a repository (R43: withdrawals must then name entry_id). */
export function entryIdsInRepo(entries, repoId) {
  return [...new Set(entries.filter((e) => Number(e.entry.source.repo_id) === Number(repoId)).map((e) => e.entry.id))];
}

const CODE_EXT = /\.(dll|exe|so|dylib|pdb|lua|luac|js|mjs|py|pyc|jar|class|asi|wasm|sys)$/i;

/**
 * code_changed when gi-probe could not compare with a previous zip: true when
 * any file that can execute was added or changed against the previous listed
 * version's file digests. No previous version means nothing changed.
 */
export function codeChangedFromFiles(previousFiles, files) {
  if (!previousFiles) return false;
  for (const [p, d] of Object.entries(files ?? {})) {
    if (!CODE_EXT.test(p)) continue;
    if (previousFiles[p] !== d) return true;
  }
  return false;
}

/**
 * built_on (merged R13; A§4.4 M3): computed from digests, never from the
 * claim alone. `verified` only when the named foundation's FULL file set is
 * inside this bundle (every digest present). When more than one listed
 * foundation release matches in full, the earliest publication wins and a
 * tie is unverified.
 *
 * @param {{claim: {id, version, engine}|null, files: Record<string,string>, entries: {entry, meta}[]}} o
 * @returns {{entry: string, version: string, verified: boolean}|null}
 */
export function computeBuiltOn({ claim, files, entries }) {
  if (!claim) return null;
  const have = new Set(Object.values(files ?? {}));
  const candidates = entries.filter(
    (e) => e.entry.kind === "foundation" && e.meta.manifest_id === claim.id && e.entry.version === claim.version,
  );
  const full = candidates.filter((e) => {
    const need = Object.values(e.meta.files ?? {});
    return need.length > 0 && need.every((d) => have.has(d));
  });
  if (full.length === 0) {
    const named = candidates[0];
    return { entry: named ? named.entry.id : claim.id, version: claim.version, verified: false };
  }
  full.sort((a, b) => (a.meta.released_at ?? 0) - (b.meta.released_at ?? 0));
  const tie = full.length > 1 && full[0].meta.released_at === full[1].meta.released_at;
  return { entry: full[0].entry.id, version: claim.version, verified: !tie };
}
