// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// One release in, one UNSIGNED candidate out (A§5.2, as amended by the
// merged plan §2 and §5.1).
//
// This is the code the ingest job runs, and the ingest job holds no secret:
// it reads strangers' releases, so it gets a read-only token and nothing that
// signs (A§5.1; asserted by test/workflows.test.mjs). Its output is a JSON
// file; sign.yml re-validates it against the schema and the catalogue's
// state before a key ever touches it.
//
// Every dependency that reaches outside this process is injected, so the
// tests drive the whole thing from fixtures:
//
//   github   lib/github.mjs: repo, release, tag → commit, owner file, bytes
//   gh       `gh attestation verify` (lib/provenance.mjs runGh)
//   probe    gi-probe (lib/probe.mjs binaryProbe: `run(subcommand, argv)`); a
//            probe that does not answer → W_PROBE_UNAVAILABLE, never a pass
//   steam    lib/steam.mjs storeApi
//
// The steps, in A§5.2's order: the repository and its binding (1), the asset
// (2), provenance (3; first-party by pin), the licence (4), the manifest,
// descriptor and gi-probe (5), the game (6), ids (7), and the verdict (8).
// A step that cannot be completed stops the run with what it knows; a step
// that refuses still lets the later independent steps report, so an author
// sees every problem with a release at once.
//
// The request is one LEASE from the plugins service's `bot/games/leases`
// door (lane C design §1.3), pulled by ingest.yml's `work` job: the service
// holds no GitHub credential and so cannot push a payload here (contract
// OD-12, INV-33). A lease carries no account, no plaintext token and no
// subject (BOT-10): the binding is proven by `binding_token_sha256` against
// the owner file, the publisher is named by the repository owner's GitHub
// login (ID-1: no Minice account reaches git or a public page), and the
// rights gate reads `confirmed[]` — the parts the author confirmed on the
// site under the current text version (§1.6).

import fs from "node:fs";
import path from "node:path";

import { checkContent } from "./content.mjs";
import { parseBindingFile } from "./vendor/astra-registry/bot/lib/binding.mjs";
import { CODES, finding, verdictOf, classOf } from "./codes.mjs";
import { codeChangedFromFiles, computeBuiltOn, descriptorDigest, gameFilesOf, latestListed, linkOf, sha256Hex, versionsOf } from "./model.mjs";
import { ProbeUnavailable, compatSourceFor, probeRelease } from "./probe.mjs";
import { FIRST_PARTY_SOURCE, firstPartyPinFindings, firstPartyRepo, verifyCommunityAttestation } from "./provenance.mjs";
import {
  descriptorCodes, descriptorOf, engineCodeFindings, entryIdFor, idFindings, manifestFindings,
} from "./rules.mjs";
import { readManifestFromZip, validateEntries, validateMany, zipFiles } from "./schemas.mjs";
import { readSignals, SteamUnanswered } from "./steam.mjs";

export const ASSET_NAME = "astra-gi.zip";
export const ASSET_CAP = 256 * 1024 * 1024;
export const GI_OWNER_FILE = ".well-known/astra-gi-owner";
export const CANDIDATE_SCHEMA = "astra.games.candidate/1";

function spdxAllowlist() {
  const file = new URL("./vendor/astra-registry/policy/spdx-allowlist.json", import.meta.url);
  const doc = JSON.parse(fs.readFileSync(file, "utf8"));
  return new Set([...(doc.allowed ?? []), ...(doc.allowed_expressions ?? [])]);
}

/** Per-locale notes: the manifest's [integration.notes] table, else the release body as `en`. */
function notesOf(manifest, release) {
  const n = manifest?.integration?.notes;
  if (n && typeof n === "object" && !Array.isArray(n)) {
    return Object.fromEntries(Object.entries(n).filter(([k, v]) => /^[a-z]{2}(-[A-Z]{2})?$/.test(k) && typeof v === "string").map(([k, v]) => [k, clip(v)]));
  }
  const body = typeof release?.body === "string" ? release.body.trim() : "";
  return body ? { en: clip(body) } : {};
}

/** At most 2,000 code points, cut between code points so no surrogate is split. */
function clip(s) {
  return Array.from(s).slice(0, 2000).join("");
}

export const LEASE_ID = /^[A-Za-z0-9_-]{1,64}$/;
const HEX64 = /^[0-9a-f]{64}$/;
/** games-index-v1's content_confirmed propertyNames: dot-separated segments (market.rights.art), each a key segment the schema admits. */
const TEXT_ID = /^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$/;
const MAX_CONFIRMED = 4096;
export const FORBIDDEN_LEASE_MEMBERS = Object.freeze(["account", "binding_token", "subject", "sub"]);

/** The SHA-256 of the binding token the owner file's line carries (UTF-8), as the service stores it. */
export function bindingTokenSha256(token) {
  return sha256Hex(Buffer.from(String(token), "utf8"));
}

/**
 * One lease item (astra.games.leases/1 `items[]`) as an ingest request.
 * Strict: a lease that breaks its shape is a bug between the service and the
 * catalogue, and ingest stops rather than guess. Unknown members are ignored
 * (a reader is permissive), and none of them is ever read.
 *
 * @returns {{lease_id: string, repo_id: number, tag: string|null, binding_token_sha256: string|null,
 *            confirmed: {path: string, sha256: string, text_id: string, text_version: number}[]}}
 */
export function parseRequest(doc) {
  const p = doc && typeof doc === "object" && !Array.isArray(doc) ? doc : {};
  const bad = [];
  const req = {
    lease_id: typeof p.lease_id === "string" ? p.lease_id : "",
    repo_id: Number(p.repo_id),
    tag: p.tag === null || p.tag === undefined ? null : String(p.tag),
    binding_token_sha256: p.binding_token_sha256 === null || p.binding_token_sha256 === undefined ? null : String(p.binding_token_sha256),
    confirmed: [],
  };
  // BOT-10: a lease carries no account, plaintext token or subject. The lease
  // file travels between jobs as an artifact of a PUBLIC repository, so one
  // that carries any of them is refused here rather than read past.
  for (const k of FORBIDDEN_LEASE_MEMBERS) if (k in p) bad.push(`${k} is a member no lease may carry (BOT-10)`);
  if (!LEASE_ID.test(req.lease_id)) bad.push("lease_id is not a lease id");
  if (!Number.isSafeInteger(req.repo_id) || req.repo_id < 1) bad.push("repo_id is not a positive integer");
  if (req.tag !== null && !/^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/.test(req.tag)) bad.push("tag is not a plain tag name");
  if (req.binding_token_sha256 !== null && !HEX64.test(req.binding_token_sha256)) bad.push("binding_token_sha256 is not 64 lowercase hex");
  const confirmed = p.confirmed ?? [];
  if (!Array.isArray(confirmed) || confirmed.length > MAX_CONFIRMED) bad.push(`confirmed is not a list of at most ${MAX_CONFIRMED}`);
  else {
    const versions = new Map();
    confirmed.forEach((c, i) => {
      const ok = c && typeof c === "object" &&
        typeof c.path === "string" && c.path.length > 0 && c.path.length <= 1024 &&
        HEX64.test(String(c.sha256)) && TEXT_ID.test(String(c.text_id)) &&
        Number.isSafeInteger(c.text_version) && c.text_version >= 1;
      if (!ok) return bad.push(`confirmed[${i}] is not {path, sha256, text_id, text_version}`);
      if (versions.has(c.text_id) && versions.get(c.text_id) !== c.text_version) {
        bad.push(`confirmed names ${c.text_id} at versions ${versions.get(c.text_id)} and ${c.text_version}; a lease carries the CURRENT version only`);
      }
      versions.set(c.text_id, c.text_version);
      req.confirmed.push({ path: c.path, sha256: c.sha256, text_id: c.text_id, text_version: c.text_version });
    });
  }
  if (bad.length) throw new Error(`the ingest request is malformed: ${bad.join("; ")}`);
  return req;
}

/**
 * The rights gate (lane C design §1.6). A part is one file, its path plus its
 * sha256; it is covered only by a `confirmed` entry with the SAME path and
 * the SAME sha256, so a changed file is asked about again and an unchanged
 * one carries over. Returns the uncovered parts and, on full coverage, the
 * {text_id: text_version} the covered parts were confirmed under.
 */
export function rightsGate(content, confirmed) {
  const key = (x) => `${x.path}\u0000${x.sha256}`;
  const byPart = new Map((confirmed ?? []).map((c) => [key(c), c]));
  const unconfirmed = content.filter((p) => !byPart.has(key(p)));
  if (unconfirmed.length || !content.length) return { unconfirmed, contentConfirmed: null };
  const contentConfirmed = {};
  for (const p of content) {
    const c = byPart.get(key(p));
    contentConfirmed[c.text_id] = c.text_version;
  }
  return { unconfirmed, contentConfirmed };
}

/**
 * @param {{
 *   request: {lease_id?: string, repo_id: number, tag: string|null, binding_token_sha256?: string|null,
 *             confirmed?: {path: string, sha256: string, text_id: string, text_version: number}[]},
 *   policy: {firstParty: object, loaders: {name: string, sha256: string, default_enabled: boolean}[]},
 *     loaders: the effective loaders[] (lib/model.mjs effectiveLoaders), handed to gi-probe check
 *   state: object, reserved: object,
 *   deps: {github: object, gh?: Function, probe: object, steam: object, workdir: string, now?: () => number},
 * }} o
 */
export async function ingestRelease(o) {
  const { request, policy, state, reserved, deps } = o;
  const now = deps.now ?? (() => Math.floor(Date.now() / 1000));
  const findings = [];
  const repoId = Number(request.repo_id);
  // null is Check now: the repository's latest stable release, resolved below
  let tag = request.tag === null || request.tag === undefined ? null : String(request.tag);
  // the content parts, once the content check ran: the result door stores
  // them and asks the author about the unconfirmed ones (§1.6 step 3)
  let parts = null;
  const out = (extra = {}) => {
    const verdict = verdictOf(findings);
    return {
      schema: CANDIDATE_SCHEMA,
      request: { ...(request.lease_id ? { lease_id: String(request.lease_id) } : {}), repo_id: repoId, tag },
      verdict,
      findings,
      flags: findings.filter((f) => classOf(f.code) === "flag").map((f) => f.code),
      ingested_at: now(),
      ...(parts ? { parts } : {}),
      ...extra,
    };
  };
  const unanswered = (what, r) => findings.push(finding(CODES.W_GITHUB_UNANSWERED, `GitHub did not answer ${what}: ${r.reason}`));

  // ── 1. the repository, and who it is bound to ───────────────────────────
  const r = await deps.github.repoById(repoId);
  if (r.status === "not_found") {
    findings.push(finding(CODES.E_REPO_NOT_FOUND, `no repository has id ${repoId}`));
    return out();
  }
  if (r.status !== "found") {
    unanswered(`repository ${repoId}`, r);
    return out();
  }
  const repo = r.repo;
  if (repo.private) findings.push(finding(CODES.E_REPO_NOT_PUBLIC, `${repo.full_name} is not public; the catalogue lists public source only (A§4.1)`));

  const fpRow = firstPartyRepo(policy.firstParty, repoId);
  const firstParty = fpRow !== null;

  const rel = tag === null ? await deps.github.latestRelease(repoId) : await deps.github.releaseByTag(repoId, tag);
  if (rel.status === "not_found") {
    findings.push(finding(CODES.E_RELEASE_NOT_FOUND, tag === null ? `${repo.full_name} has no published stable release to check` : `${repo.full_name} has no release tagged ${tag}`));
    return out();
  }
  if (rel.status !== "found") {
    unanswered(tag === null ? `the latest release of ${repo.full_name}` : `release ${tag}`, rel);
    return out();
  }
  const release = rel.release;
  if (tag === null) {
    tag = String(release?.tag_name ?? "");
    if (!/^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/.test(tag)) {
      findings.push(finding(CODES.E_RELEASE_NOT_FOUND, `${repo.full_name}'s latest release has no plain tag name`));
      tag = null;
      return out();
    }
  }
  if (release.draft) findings.push(finding(CODES.E_RELEASE_DRAFT, `${tag} is a draft`));
  if (release.prerelease && !firstParty) {
    findings.push(finding(CODES.E_PRERELEASE, `${tag} is a prerelease; community releases are listed from stable releases only, and a prerelease is tested with Install from address (A§5.2 step 8)`));
  }

  const tc = await deps.github.tagCommit(repoId, tag);
  if (tc.status === "not_found") {
    findings.push(finding(CODES.E_TAG_NOT_FOUND, `tag ${tag} does not exist in ${repo.full_name}`));
    return out();
  }
  if (tc.status !== "found") {
    unanswered(`tag ${tag}`, tc);
    return out();
  }
  const tagCommit = tc.commit;

  let identity;
  let bindingToken = null;
  const bound = state.bindings?.[String(repoId)] ?? null;
  if (firstParty) {
    identity = { account: policy.firstParty.publisher_account, repo_id: repoId, repo_owner_id: Number(fpRow.repository_owner_id) };
    if (Number(repo.owner_id) !== identity.repo_owner_id) {
      findings.push(finding(CODES.R_IDENTITY_CHANGED, `${repo.full_name} is now owned by ${repo.owner_id}, and first-party.json binds it to ${identity.repo_owner_id}: the repository changed hands`));
    }
  } else {
    const file = await deps.github.fileAtCommit(repoId, tagCommit, GI_OWNER_FILE);
    if (file.status === "transient") {
      unanswered(`${GI_OWNER_FILE} at ${tagCommit}`, file);
      return out();
    }
    const parsed = file.status === "not_found" ? { outcome: "none" } : parseBindingFile(file.content ?? "");
    if (parsed.outcome === "malformed") {
      findings.push(finding(CODES.E_BINDING_MALFORMED, `${GI_OWNER_FILE}: ${parsed.reason}`));
    } else if (parsed.outcome !== "one") {
      findings.push(finding(CODES.E_UNBOUND, `${repo.full_name} has no astra-binding line in ${GI_OWNER_FILE} at ${tag}; publish from the site and commit the line it gives you`));
    } else {
      bindingToken = parsed.token;
    }
    // The service's binding, as the only thing it may say about it: the
    // SHA-256 of the token it minted (it never holds the plaintext). The
    // line at THIS tag either carries that token or it does not, and a tag's
    // file never changes, so a mismatch is final for the tag.
    const leased = request.binding_token_sha256 ?? null;
    const lineIsLeased = bindingToken !== null && leased !== null && bindingTokenSha256(bindingToken) === leased;
    if (bindingToken !== null && leased !== null && !lineIsLeased) {
      findings.push(finding(CODES.E_UNBOUND, `${GI_OWNER_FILE} at ${tag} carries a binding line the site did not mint for this repository's current binding; commit the line the site's publish page gives you, and release again`));
    }
    if (bound) {
      identity = { account: bound.account, repo_id: repoId, repo_owner_id: Number(bound.repo_owner_id) };
      if (Number(repo.owner_id) !== identity.repo_owner_id) {
        findings.push(finding(CODES.R_IDENTITY_CHANGED, `${repo.full_name} is now owned by ${repo.owner_id}, and it was bound under owner ${identity.repo_owner_id}: the repository changed hands, so a person decides (R_IDENTITY_CHANGED)`));
      }
      if (bindingToken !== null && bindingToken !== bound.binding_token) {
        findings.push(finding(CODES.R_BINDING_CHANGED, `${GI_OWNER_FILE} now carries another binding line than the one ${repo.full_name} was listed under`));
      }
    } else {
      // ID-1, BOT-10: the publisher is named by the repository owner's GitHub
      // login at first binding — never by the Minice account, which stays
      // private in the service. bindings.json keeps it from then on.
      const login = typeof repo.owner_login === "string" && /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(repo.owner_login) ? repo.owner_login : null;
      identity = { account: login, repo_id: repoId, repo_owner_id: Number(repo.owner_id) };
      if (login === null) {
        unanswered(`the owner login of ${repo.full_name}`, { reason: `the repository's owner has no readable login (${JSON.stringify(repo.owner_login ?? null)})` });
        return out();
      }
      if (leased === null) {
        findings.push(finding(CODES.E_UNBOUND, `${repo.full_name} has never been bound; its first release arrives from the site's publish page, which mints the binding`));
      }
    }
  }

  // ── 2. the asset ───────────────────────────────────────────────────────
  const asset = (release.assets ?? []).find((a) => a.name === ASSET_NAME);
  if (!asset) {
    findings.push(finding(CODES.E_ASSET_MISSING, `${tag} has no ${ASSET_NAME}`));
    return out();
  }
  if (Number(asset.size) > ASSET_CAP) {
    findings.push(finding(CODES.E_ASSET_TOO_LARGE, `${ASSET_NAME} is ${asset.size} bytes, over ${ASSET_CAP}`));
    return out();
  }
  const url = `https://github.com/${repo.full_name}/releases/download/${encodeURIComponent(tag)}/${ASSET_NAME}`;
  let bytes;
  try {
    bytes = await deps.github.download(url, ASSET_CAP);
  } catch (e) {
    if (e?.transient) unanswered(url, { reason: e.message });
    else findings.push(finding(CODES.E_ASSET_MISSING, `${url}: ${e.message}`));
    return out();
  }
  const sha256 = sha256Hex(bytes);
  const ghDigest = String(asset.digest ?? "");
  if (ghDigest !== `sha256:${sha256}`) {
    findings.push(finding(CODES.E_ASSET_DIGEST_MISMATCH, `the downloaded ${ASSET_NAME} hashes to sha256:${sha256} and GitHub reports ${ghDigest || "no digest"}`));
    return out();
  }
  fs.mkdirSync(deps.workdir, { recursive: true });
  const zipPath = path.join(deps.workdir, ASSET_NAME);
  fs.writeFileSync(zipPath, bytes);

  // ── 3. provenance ──────────────────────────────────────────────────────
  let source = { commit: tagCommit, ...FIRST_PARTY_SOURCE };
  if (firstParty) {
    findings.push(...firstPartyPinFindings({ firstParty: policy.firstParty, repoId, tag, asset: ASSET_NAME, sha256 }));
  } else {
    const att = await verifyCommunityAttestation({
      file: zipPath, repo: repo.full_name, repoId, currentOwnerId: Number(repo.owner_id), tag, tagCommit, sha256, gh: deps.gh,
    });
    findings.push(...att.findings);
    if (att.facts) source = { commit: att.facts.commit ?? tagCommit, workflow_path: att.facts.workflow_path || "unknown", event: att.facts.event };
  }
  const reach = await deps.github.onDefaultBranch(repoId, repo.default_branch, tagCommit);
  if (reach.status === "found" && !reach.reachable) {
    findings.push(finding(CODES.F_TAG_NOT_ON_DEFAULT_BRANCH, `${tag} (${tagCommit}) is not reachable from ${repo.default_branch}; moderators read the source at the tag`));
  }

  // ── 5. manifest and descriptor, against the S schemas ──────────────────
  const m = readManifestFromZip(zipPath);
  if (!m.ok) {
    findings.push(finding(CODES.E_MANIFEST_INVALID, m.error));
    return out();
  }
  const manifest = m.manifest;
  const descriptor = descriptorOf(manifest);
  const checks = validateMany([
    { schema: "manifest", doc: manifest },
    ...(descriptor ? [{ schema: "engine-descriptor-v1", doc: descriptor }] : []),
  ]);
  if (!checks[0].ok) findings.push(finding(CODES.E_MANIFEST_INVALID, `manifest.schema.json: ${checks[0].error}`));
  if (descriptor && !checks[1].ok) findings.push(finding(CODES.E_DESCRIPTOR_INVALID, `engine-descriptor-v1.schema.json: ${checks[1].error}`));
  findings.push(...manifestFindings(manifest, { reserved, firstParty, tag }));
  const repoUrl = `https://github.com/${repo.full_name}`;
  if (manifest?.integration?.repo && String(manifest.integration.repo).replace(/\/$/, "").toLowerCase() !== repoUrl.toLowerCase()) {
    findings.push(finding(CODES.F_REPO_URL_MISMATCH, `[integration] repo is ${manifest.integration.repo}, and the release is in ${repoUrl}`));
  }

  // ── 5c. content check (manifest.md §2.7, merged plan §5.4) ─────────────
  // Runs on the real zip, after the manifest parsed and schema-validated,
  // and before gi-probe (manifest.md §2.7.1's ingest order): a release
  // whose own content declarations do not match its own zip is refused
  // before its code is even inspected.
  const contentResult = checkContent({ zipPath, manifest });
  findings.push(...contentResult.findings);
  parts = contentResult.content;

  // ── 5d. the per-part rights gate (lane C design §1.6) ──────────────────
  // Every part must be covered by the author's confirmation, made on the
  // site under the current text and carried by the lease. An uncovered part
  // is a WAIT, never a refusal: the result door asks the author, the author
  // ticks the box, and the release is leased again with a full confirmed[].
  // A wait is never listed (codes.mjs; accept.mjs re-checks).
  const gate = rightsGate(parts, request.confirmed ?? []);
  if (gate.unconfirmed.length) {
    const shown = gate.unconfirmed.slice(0, 8).map((p) => p.path).join(", ");
    const more = gate.unconfirmed.length > 8 ? ` and ${gate.unconfirmed.length - 8} more` : "";
    findings.push(finding(CODES.W_CONTENT_UNCONFIRMED, `${gate.unconfirmed.length} content part(s) wait for your rights confirmation on the site's release page: ${shown}${more}`));
  }

  // ── 4. the licence ─────────────────────────────────────────────────────
  const licence = String(manifest?.integration?.license ?? "");
  if (!spdxAllowlist().has(licence)) {
    findings.push(finding(CODES.E_LICENCE_NOT_ALLOWED, `[integration] license ${JSON.stringify(licence)} is not on the SPDX allowlist (the registry's policy/spdx-allowlist.json)`));
  }
  const lic = await deps.github.licenseAt(repoId, tagCommit);
  if (lic.status === "not_found") findings.push(finding(CODES.E_LICENCE_MISSING, `${repo.full_name} has no LICENSE file at ${tag}`));
  else if (lic.status !== "found") unanswered(`the licence of ${repo.full_name}`, lic);

  // engine codes (merged §2.1)
  const codes = descriptor ? descriptorCodes(descriptor) : [];
  let descriptorSha = null;
  if (descriptor) {
    try {
      descriptorSha = descriptorDigest(descriptor);
    } catch (e) {
      findings.push(finding(CODES.E_DESCRIPTOR_INVALID, `the descriptor has no canonical form: ${e.message}`));
    }
  }
  if (identity?.account) findings.push(...engineCodeFindings({ codes, identity, engineCodes: state.engineCodes, reserved }));

  // ── 7. ids ─────────────────────────────────────────────────────────────
  const manifestId = String(manifest?.integration?.id ?? "");
  const entryId = identity?.account ? entryIdFor(identity.account, manifestId) : null;
  if (entryId) {
    findings.push(...idFindings({ entryId, identity, entries: state.entries }));
    const same = versionsOf(state.entries, entryId).find((e) => e.entry.version === String(manifest?.integration?.version));
    if (same) findings.push(finding(CODES.E_VERSION_EXISTS, `${entryId} ${same.entry.version} is already in the catalogue; a listed version never changes bytes`));
  }

  // ── 6. the game ────────────────────────────────────────────────────────
  const appid = manifest?.target?.steam_appid ?? null;
  const kind = appid ? "integration" : "foundation";
  let online = [];
  if (appid) {
    const row = (state.moderation?.games ?? []).find((g) => g.store === "steam" && Number(g.id) === Number(appid));
    if (row?.refuse) findings.push(finding(CODES.E_GAME_REFUSED, `steam ${appid}: ${row.refuse.reason}`));
    try {
      const sig = readSignals(await deps.steam.appDetails(appid));
      if (!sig.exists) findings.push(finding(CODES.E_GAME_UNKNOWN, `Steam has no app ${appid}`));
      if (sig.vac) findings.push(finding(CODES.E_GAME_VAC, `Steam lists Valve Anti-Cheat for ${appid}; no integration is listed for a VAC game`));
      online = sig.online;
      if (online.length && !row?.allow_foundations) {
        findings.push(finding(CODES.F_ONLINE_GAME, `Steam lists ${appid} as ${online.join(", ")}: a moderator looks before players do`));
      }
    } catch (e) {
      if (e instanceof SteamUnanswered) findings.push(finding(CODES.W_STEAM_UNANSWERED, e.message));
      else throw e;
    }
  }

  // ── 5b. gi-probe (lib/probe.mjs's table: check; validate-descriptor for a
  //        descriptor; compat for a first-party 0.2.7 source) ─────────────────
  if (!Array.isArray(policy.loaders)) throw new Error("ingestRelease: policy.loaders is the effective loaders[] array");
  // gi-probe's --loaders is a bare JSON array of {name, sha256, default_enabled}
  // (check.rs l.111-135, deny_unknown_fields); anything else is its exit 2
  const loadersFile = path.join(deps.workdir, "gi-probe-loaders.json");
  fs.writeFileSync(loadersFile, JSON.stringify(policy.loaders.map((l) => ({ name: String(l.name), sha256: String(l.sha256), default_enabled: l.default_enabled === true }))));
  let manifestFile = null;
  if (descriptor) {
    manifestFile = path.join(deps.workdir, "astra-gi.toml");
    fs.writeFileSync(manifestFile, m.text);
  }
  const compatSource = compatSourceFor({ firstParty, manifestId, repoId, asset: ASSET_NAME });
  let reports = null;
  try {
    reports = await probeRelease({
      probe: deps.probe, zip: zipPath, zipSha256: sha256, firstParty, loaders: loadersFile, manifestFile,
      compat: compatSource ? { source: compatSource, tag, asset: ASSET_NAME, prerelease: release.prerelease === true } : null,
    });
  } catch (e) {
    if (e instanceof ProbeUnavailable) findings.push(finding(CODES.W_PROBE_UNAVAILABLE, e.message));
    else throw e;
  }
  // the catalogue's own reading of what gi-probe 0.5.0 does not report
  let own = null;
  if (reports) {
    const seen = new Set();
    for (const [sub, r] of Object.entries(reports)) {
      for (const f of r.findings) {
        // validate-descriptor repeats check's descriptor findings: say each once
        const key = `${f.code}\u0000${f.field ?? ""}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push(finding(CODES.E_PROBE, `gi-probe ${sub} ${f.code}${f.field ? ` (${f.field})` : ""}: ${f.detail}`, { probe_code: f.code }));
      }
    }
    const version = String(manifest?.integration?.version);
    for (const [sub, r] of Object.entries(reports)) {
      const i = r.integration;
      if (i && (i.id !== manifestId || i.version !== version)) {
        findings.push(finding(CODES.E_PROBE_DISAGREES, `gi-probe ${sub} read ${i.id} ${i.version} and tomllib read ${manifestId} ${version}`));
      }
      if (sub === "compat") continue;
      // a descriptor gi-probe refused is its finding already; one it read, or
      // a pass without one, must be the catalogue's digest
      const theirs = r.descriptor?.sha256 ?? null;
      if ((r.descriptor || r.verdict === "pass") && theirs !== descriptorSha) {
        findings.push(finding(CODES.E_PROBE_DISAGREES, `gi-probe ${sub}'s descriptor digest is ${theirs} and the catalogue's is ${descriptorSha}`));
      }
    }
    if (reports.check.verdict === "pass") {
      const read = zipFiles(zipPath);
      if (!read.ok) {
        findings.push(finding(CODES.E_PROBE_DISAGREES, `gi-probe opened the zip and the catalogue cannot read it whole: ${read.error}`));
      } else {
        const g = gameFilesOf(manifest, read.files, reports.check.loaders.files);
        const l = linkOf(manifest, read.files, reports.check.link?.digest ?? null);
        for (const p of [...g.problems, ...l.problems]) findings.push(finding(CODES.E_PROBE_DISAGREES, p));
        for (const f of g.gameFiles) {
          if (f.loader === "other") findings.push(finding(CODES.F_LOADER_OTHER, `${f.path} is a loader that is not on loaders[]: the install sheet shows it in red`));
        }
        own = { files: read.files, gameFiles: g.gameFiles, link: l.link, schemaDigests: l.schemaDigests };
      }
    }
  }

  const verdict = verdictOf(findings);
  if (verdict === "refuse" || verdict === "wait" || !reports || !own || !identity?.account) return out();

  // ── 8. the unsigned candidate entry ────────────────────────────────────
  const claim = manifest?.integration?.foundation ?? null;
  const previous = latestListed(state.entries, entryId);
  const target = kind === "integration"
    ? { store: "steam", id: Number(appid), exe: String(manifest.target.exe) }
    : { exe: String(manifest.target.exe) };
  if (manifest?.target?.engine) target.engine = String(manifest.target.engine);
  const link = manifest?.integration?.link ?? null;
  const entry = {
    id: entryId,
    kind,
    publisher: { account: identity.account, repo_id: identity.repo_id, repo_owner_id: identity.repo_owner_id },
    source: {
      host: "github.com",
      repo: repo.full_name,
      repo_id: repoId,
      repo_owner_id: Number(repo.owner_id),
      release_tag: tag,
      asset: ASSET_NAME,
      sha256,
      size: bytes.length,
      commit: source.commit,
      workflow_path: source.workflow_path,
      event: source.event,
    },
    version: String(manifest.integration.version),
    schema: 1,
    min_astra: String(manifest?.integration?.min_astra ?? "0.2.8"),
    target,
    descriptor: descriptor ?? null,
    descriptor_sha256: descriptorSha,
    sdk: manifest?.integration?.sdk ?? null,
    foundation: claim ? { id: String(claim.id), version: String(claim.version), engine: String(claim.engine) } : null,
    built_on: computeBuiltOn({ claim, files: own.files, entries: state.entries }),
    engine_versions: manifest?.integration?.engine_versions ?? null,
    link: own.link,
    schema_digests: own.schemaDigests,
    capabilities: (manifest?.integration?.capabilities?.companion ?? []).map((c) => `companion.${c}`),
    shares_other_players: link?.shares_other_players === true,
    changes: {
      profile_files: (manifest.files ?? []).length > 0,
      game_files: own.gameFiles,
      launch: !!manifest.launch && Object.keys(manifest.launch).length > 0,
      config_writes: (manifest.config_writes ?? []).length > 0,
    },
    code_changed: codeChangedFromFiles(previous?.meta.files ?? null, own.files),
    licence,
    review: "unchecked",
    supersedes: [],
    flags: [...new Set(findings.filter((f) => classOf(f.code) === "flag").map((f) => f.code))],
    notes: notesOf(manifest, release),
    content: contentResult.content,
    ...(gate.contentConfirmed ? { content_confirmed: gate.contentConfirmed } : {}),
  };
  const changedHands = findings.some((f) => f.code === CODES.R_IDENTITY_CHANGED || f.code === CODES.R_BINDING_CHANGED);
  const meta = {
    status: release.prerelease ? "prerelease" : "listed",
    first_party: firstParty,
    manifest_id: manifestId,
    released_at: release.published_at ? Math.floor(Date.parse(release.published_at) / 1000) : now(),
    files: own.files,
    binding: { ...identity, binding_token: bindingToken },
    // who the repository and its owner file name NOW: the current owner's
    // login and the line at this tag. Differs from `binding` only on a hold,
    // and is what a person's M_RELEASE_HOLD rebinds to
    claimant: { account: changedHands && repo.owner_login ? String(repo.owner_login) : identity.account, binding_token: bindingToken },
    online,
    // which build judged it, what it ran, and what it noticed (never a finding)
    probe: {
      name: "gi-probe",
      version: reports.check.tool.version,
      source_tree_sha256: reports.check.tool.source_tree_sha256 ?? null,
      ran: Object.keys(reports),
      notices: Object.entries(reports).flatMap(([sub, r]) => r.notices.map((n) => `${sub}:${n.code}`)),
    },
  };
  const [shape] = validateEntries([entry]);
  if (!shape.ok) {
    findings.push(finding(CODES.E_CANDIDATE_INVALID, `the candidate entry does not match games-index-v1.schema.json: ${shape.error}`));
    return out();
  }
  return out({ entry, meta });
}
