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

// Every extension gi-probe's own `is_code` counts (astra-game-launcher v0.5.0
// src/bin/gi-probe/check.rs l.89-100: `.pyd` and a versioned `.so.N` too), and more.
const CODE_EXT = /\.(dll|exe|so|dylib|pdb|lua|luac|js|mjs|py|pyc|pyd|jar|class|asi|wasm|sys)$|\.so\./i;

/**
 * code_changed, which ingest computes itself (it passes gi-probe no
 * --previous, having no previous zip on disk): true when
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

const GAME = "${game}/";

/**
 * `changes.game_files` (games-index-v1.md §2.1): each [[game_files]] rule as
 * the catalogue reads the zip — the path below the game folder, the digest of
 * the file it places — labelled with the loader class gi-probe check gave it
 * (`loaders.files`, one row per game file in manifest order; check.rs
 * l.443-515). Every way the two readings differ is a problem: the release is
 * then refused E_PROBE_DISAGREES, never listed with one reading's label on the
 * other's file.
 * @param {object} manifest
 * @param {Record<string, string>} files the catalogue's own {path in zip: sha256}
 * @param {{dest: string, sha256: string|null, class: string}[]} rows gi-probe's
 * @returns {{gameFiles: {path, sha256, loader}[], problems: string[]}}
 */
export function gameFilesOf(manifest, files, rows) {
  const rules = Array.isArray(manifest?.game_files) ? manifest.game_files : [];
  const problems = [];
  if (rows.length !== rules.length) problems.push(`the manifest has ${rules.length} [[game_files]] and gi-probe classified ${rows.length}`);
  const gameFiles = rules.map((g, i) => {
    const to = String(g?.to ?? "");
    const rel = to.startsWith(GAME) ? to.slice(GAME.length) : to;
    const sha256 = Object.hasOwn(files, String(g?.from)) ? files[String(g.from)] : null;
    const row = rows[i];
    if (sha256 === null) problems.push(`[[game_files]] ${JSON.stringify(g?.from)} is not a file of the zip the catalogue read`);
    if (!to.startsWith(GAME)) problems.push(`[[game_files]] to ${JSON.stringify(to)} is not below \${game}/`);
    if (row && String(row.dest).toLowerCase() !== (GAME + rel).toLowerCase()) problems.push(`gi-probe's game file ${i + 1} is ${row.dest}, and the manifest's is ${to}`);
    else if (row && sha256 !== null && row.sha256 !== sha256) problems.push(`gi-probe hashes ${row.dest} to ${row.sha256}, and the catalogue to ${sha256}`);
    return { path: rel, sha256, loader: row?.class ?? null };
  });
  return { gameFiles, problems };
}

/**
 * The entry's `link` summary and `schema_digests` (games-index-v1.md §2.1),
 * from [integration.link] and the catalogue's own digests of the files it
 * names: the skill, each tool's `params` and each trigger's and event's
 * `data` schema. The summary's `digest` (the consent digest of the canonical
 * link block, marketplace plan M4) is left out: its canonical form is the
 * daemon's (`updates.rs`), and no specification or gi-probe 0.5.0 defines it.
 * A file the manifest names that the zip does not hold is a problem.
 * @param {object} manifest
 * @param {Record<string, string>} files
 * @returns {{link: {context: boolean, shares_other_players: boolean, skill_digest: string|null}|null, schemaDigests: Record<string, string>, problems: string[]}}
 */
export function linkOf(manifest, files) {
  const l = manifest?.integration?.link;
  if (!l || typeof l !== "object") return { link: null, schemaDigests: {}, problems: [] };
  const problems = [];
  const digest = (p, what) => {
    if (Object.hasOwn(files, p)) return files[p];
    problems.push(`[integration.link] ${what} ${JSON.stringify(p)} is not a file of the zip the catalogue read`);
    return null;
  };
  const skill = typeof l.skill === "string" ? digest(l.skill, "skill") : null;
  const schemaDigests = {};
  const named = [
    ...(Array.isArray(l.tools) ? l.tools : []).map((t) => [t?.params, "tool params"]),
    ...(Array.isArray(l.triggers) ? l.triggers : []).map((t) => [t?.data, "trigger data"]),
    ...(Array.isArray(l.events) ? l.events : []).map((e) => [e?.data, "event data"]),
  ];
  for (const [p, what] of named) {
    if (typeof p !== "string") continue;
    const d = digest(p, what);
    if (d) schemaDigests[p] = d;
  }
  return {
    link: { context: l.context === true, shares_other_players: l.shares_other_players === true, skill_digest: skill },
    schemaDigests,
    problems,
  };
}
