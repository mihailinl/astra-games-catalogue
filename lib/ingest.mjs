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
//   probe    gi-probe (lib/probe.mjs); absent → W_PROBE_UNAVAILABLE, never a pass
//   steam    lib/steam.mjs storeApi
//
// The steps, in A§5.2's order: the repository and its binding (1), the asset
// (2), provenance (3; first-party by pin), the licence (4), the manifest,
// descriptor and gi-probe (5), the game (6), ids (7), and the verdict (8).
// A step that cannot be completed stops the run with what it knows; a step
// that refuses still lets the later independent steps report, so an author
// sees every problem with a release at once.

import fs from "node:fs";
import path from "node:path";

import { checkContent } from "./content.mjs";
import { parseBindingFile } from "./vendor/astra-registry/bot/lib/binding.mjs";
import { CODES, finding, verdictOf, classOf } from "./codes.mjs";
import { codeChangedFromFiles, computeBuiltOn, descriptorDigest, latestListed, sha256Hex, versionsOf } from "./model.mjs";
import { ProbeUnavailable, checkReport } from "./probe.mjs";
import { FIRST_PARTY_SOURCE, firstPartyPinFindings, firstPartyRepo, verifyCommunityAttestation } from "./provenance.mjs";
import {
  descriptorCodes, descriptorOf, engineCodeFindings, entryIdFor, idFindings, manifestFindings,
} from "./rules.mjs";
import { readManifestFromZip, validateEntries, validateMany } from "./schemas.mjs";
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

/**
 * @param {{
 *   request: {repo_id: number, tag: string, account?: string, binding_token?: string},
 *   policy: {firstParty: object, loadersFile: string, loaders: object[]},
 *   state: object, reserved: object,
 *   deps: {github: object, gh?: Function, probe: object, steam: object, workdir: string, now?: () => number},
 * }} o
 */
export async function ingestRelease(o) {
  const { request, policy, state, reserved, deps } = o;
  const now = deps.now ?? (() => Math.floor(Date.now() / 1000));
  const findings = [];
  const out = (extra = {}) => {
    const verdict = verdictOf(findings);
    return {
      schema: CANDIDATE_SCHEMA,
      request: { repo_id: Number(request.repo_id), tag: String(request.tag) },
      verdict,
      findings,
      flags: findings.filter((f) => classOf(f.code) === "flag").map((f) => f.code),
      ingested_at: now(),
      ...extra,
    };
  };
  const unanswered = (what, r) => findings.push(finding(CODES.W_GITHUB_UNANSWERED, `GitHub did not answer ${what}: ${r.reason}`));

  // ── 1. the repository, and who it is bound to ───────────────────────────
  const repoId = Number(request.repo_id);
  const tag = String(request.tag);
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

  const rel = await deps.github.releaseByTag(repoId, tag);
  if (rel.status === "not_found") {
    findings.push(finding(CODES.E_RELEASE_NOT_FOUND, `${repo.full_name} has no release tagged ${tag}`));
    return out();
  }
  if (rel.status !== "found") {
    unanswered(`release ${tag}`, rel);
    return out();
  }
  const release = rel.release;
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
    if (bound) {
      identity = { account: bound.account, repo_id: repoId, repo_owner_id: Number(bound.repo_owner_id) };
      if (Number(repo.owner_id) !== identity.repo_owner_id) {
        findings.push(finding(CODES.R_IDENTITY_CHANGED, `${repo.full_name} is now owned by ${repo.owner_id}, and it was bound under owner ${identity.repo_owner_id}: the repository changed hands, so a person decides (R_IDENTITY_CHANGED)`));
      }
      const accountMoved = request.account && String(request.account).toLowerCase() !== String(bound.account).toLowerCase();
      if (bindingToken !== null && (bindingToken !== bound.binding_token || accountMoved)) {
        findings.push(finding(CODES.R_BINDING_CHANGED, `${GI_OWNER_FILE} now binds ${repo.full_name} to another account than ${bound.account}`));
      }
    } else {
      identity = { account: request.account ?? null, repo_id: repoId, repo_owner_id: Number(repo.owner_id) };
      if (!request.account || !request.binding_token) {
        findings.push(finding(CODES.E_UNBOUND, `${repo.full_name} has never been bound; its first release arrives from the site's publish page, which names the account`));
      } else if (bindingToken !== null && bindingToken !== request.binding_token) {
        findings.push(finding(CODES.E_UNBOUND, `${GI_OWNER_FILE} carries a binding line that ${request.account} did not mint`));
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

  // ── 5b. gi-probe ───────────────────────────────────────────────────────
  let report = null;
  try {
    report = await deps.probe.ingest({ zip: zipPath, loaders: policy.loadersFile, previous: null, firstParty });
  } catch (e) {
    if (e instanceof ProbeUnavailable) findings.push(finding(CODES.W_PROBE_UNAVAILABLE, e.message));
    else throw e;
  }
  if (report) {
    const bad = checkReport(report);
    if (bad.length) {
      findings.push(finding(CODES.E_PROBE, `gi-probe's report cannot be read: ${bad.join("; ")}`));
      report = null;
    }
  }
  if (report) {
    for (const f of report.findings) {
      findings.push(finding(f.level === "error" ? CODES.E_PROBE : CODES.F_PROBE, `gi-probe ${f.code}: ${f.message ?? ""}`.trim(), { probe_code: f.code }));
    }
    if (report.manifest_id !== manifestId || report.manifest_version !== String(manifest?.integration?.version)) {
      findings.push(finding(CODES.E_PROBE_DISAGREES, `gi-probe read ${report.manifest_id} ${report.manifest_version} and tomllib read ${manifestId} ${manifest?.integration?.version}`));
    }
    if ((report.descriptor_sha256 ?? null) !== descriptorSha) {
      findings.push(finding(CODES.E_PROBE_DISAGREES, `gi-probe's descriptor digest is ${report.descriptor_sha256} and the catalogue's is ${descriptorSha}`));
    }
    if (firstParty && report.compat && !report.compat.ok) {
      findings.push(finding(CODES.E_PROBE, `gi-probe compat: ${(report.compat.findings ?? []).map((x) => x.code ?? x).join(", ") || "failed"}`));
    }
    for (const g of report.game_files) {
      if (g.loader === "other") findings.push(finding(CODES.F_LOADER_OTHER, `${g.path} is a loader that is not on loaders[]: the install sheet shows it in red`));
    }
  }

  const verdict = verdictOf(findings);
  if (verdict === "refuse" || verdict === "wait" || !report || !identity?.account) return out();

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
    built_on: computeBuiltOn({ claim, files: report.files, entries: state.entries }),
    engine_versions: manifest?.integration?.engine_versions ?? null,
    link: report.link ?? null,
    schema_digests: report.schema_digests ?? {},
    capabilities: (manifest?.integration?.capabilities?.companion ?? []).map((c) => `companion.${c}`),
    shares_other_players: link?.shares_other_players === true,
    changes: {
      profile_files: (manifest.files ?? []).length > 0,
      game_files: report.game_files.map((g) => ({ path: g.path, sha256: g.sha256, loader: g.loader })),
      launch: !!manifest.launch && Object.keys(manifest.launch).length > 0,
      config_writes: (manifest.config_writes ?? []).length > 0,
    },
    code_changed: typeof report.code_changed === "boolean" ? report.code_changed : codeChangedFromFiles(previous?.meta.files ?? null, report.files),
    licence,
    review: "unchecked",
    supersedes: [],
    flags: [...new Set(findings.filter((f) => classOf(f.code) === "flag").map((f) => f.code))],
    notes: notesOf(manifest, release),
    content: contentResult.content,
  };
  const meta = {
    status: release.prerelease ? "prerelease" : "listed",
    first_party: firstParty,
    manifest_id: manifestId,
    released_at: release.published_at ? Math.floor(Date.parse(release.published_at) / 1000) : now(),
    files: report.files,
    binding: { ...identity, binding_token: bindingToken },
    // who the request and the owner file name NOW; differs from `binding` only
    // on a hold, and is what a person's M_RELEASE_HOLD rebinds to
    claimant: { account: request.account ?? identity.account, binding_token: bindingToken },
    online,
    probe: { name: report.probe ?? "gi-probe", version: report.version ?? null },
  };
  const [shape] = validateEntries([entry]);
  if (!shape.ok) {
    findings.push(finding(CODES.E_CANDIDATE_INVALID, `the candidate entry does not match games-index-v1.schema.json: ${shape.error}`));
    return out();
  }
  return out({ entry, meta });
}
