// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Finding codes, and the one rule that turns a list of findings into a
// verdict.
//
// The prefix is the class, so the class cannot drift from the code:
//
//   E_  refuse   final for this tag; the author ships a new release
//   W_  wait     nothing was decided: a read did not happen (GitHub, Sigstore,
//                Steam, gi-probe absent). Retried; never listed meanwhile
//   H_  hold     a person decides (a changed binding or owner, an unpinned
//                first-party release). Released by a moderator act
//   F_  flag     shown to moderators; never blocks (A§5.2 step 8: only a
//                change of hands waits)
//
// A refusal outranks a wait: a release whose manifest is broken is broken
// whatever Sigstore says later. A wait outranks a hold: a hold is a question
// for a person, and a person should not be asked about a release that has not
// finished being checked.

export const VERDICTS = Object.freeze(["accept", "hold", "wait", "refuse"]);

export function classOf(code) {
  const p = String(code).slice(0, 2);
  if (p === "E_") return "refuse";
  if (p === "W_") return "wait";
  if (p === "H_" || p === "R_") return "hold";
  if (p === "F_") return "flag";
  throw new Error(`finding code ${code} has no class prefix`);
}

export function verdictOf(findings) {
  const classes = new Set(findings.map((f) => classOf(f.code)));
  if (classes.has("refuse")) return "refuse";
  if (classes.has("wait")) return "wait";
  if (classes.has("hold")) return "hold";
  return "accept";
}

export function finding(code, message, extra = {}) {
  classOf(code); // throws on an unclassed code
  return { code, message, ...extra };
}

/** The codes this repository emits, so a test can ask that each is reachable and spelled once. */
export const CODES = Object.freeze({
  // source and binding (A§4.1, A§5.2 step 1)
  E_REPO_NOT_PUBLIC: "E_REPO_NOT_PUBLIC",
  E_REPO_NOT_FOUND: "E_REPO_NOT_FOUND",
  E_UNBOUND: "E_UNBOUND",
  E_BINDING_MALFORMED: "E_BINDING_MALFORMED",
  R_BINDING_CHANGED: "R_BINDING_CHANGED",
  R_IDENTITY_CHANGED: "R_IDENTITY_CHANGED",
  // release and asset (A§4.1 "The asset")
  E_RELEASE_NOT_FOUND: "E_RELEASE_NOT_FOUND",
  E_RELEASE_DRAFT: "E_RELEASE_DRAFT",
  E_PRERELEASE: "E_PRERELEASE",
  E_ASSET_MISSING: "E_ASSET_MISSING",
  E_ASSET_TOO_LARGE: "E_ASSET_TOO_LARGE",
  E_ASSET_DIGEST_MISMATCH: "E_ASSET_DIGEST_MISMATCH",
  // Zip Cloaking: the asset's local headers disagree with its own central directory
  E_ZIP_HEADERS_INCONSISTENT: "E_ZIP_HEADERS_INCONSISTENT",
  E_TAG_NOT_FOUND: "E_TAG_NOT_FOUND",
  // attestation (A§4.1 table, through the vendored certificate code)
  E_ATTESTATION_MISSING: "E_ATTESTATION_MISSING",
  E_ATTESTATION_INVALID: "E_ATTESTATION_INVALID",
  E_ATTESTATION_SUBJECT_MISMATCH: "E_ATTESTATION_SUBJECT_MISMATCH",
  E_ATTESTATION_REPO_MISMATCH: "E_ATTESTATION_REPO_MISMATCH",
  E_ATTESTATION_SHA_MISMATCH: "E_ATTESTATION_SHA_MISMATCH",
  E_ATTESTATION_ID_MISMATCH: "E_ATTESTATION_ID_MISMATCH",
  E_ATTESTATION_OWNER_MISMATCH: "E_ATTESTATION_OWNER_MISMATCH",
  W_ATTESTATION_UNCHECKED: "W_ATTESTATION_UNCHECKED",
  // first-party digest pin (merged §5.1)
  H_FIRST_PARTY_UNPINNED: "H_FIRST_PARTY_UNPINNED",
  E_PIN_MISMATCH: "E_PIN_MISMATCH",
  // manifest and descriptor (S schemas, manifest.md §2-§3)
  E_MANIFEST_INVALID: "E_MANIFEST_INVALID",
  E_DESCRIPTOR_INVALID: "E_DESCRIPTOR_INVALID",
  E_ENGINE_UNDECLARED: "E_ENGINE_UNDECLARED",
  E_LOADER_POLICY_CONFLICT: "E_LOADER_POLICY_CONFLICT",
  E_CAPABILITY_UNDECLARED: "E_CAPABILITY_UNDECLARED",
  E_RESERVED_ID: "E_RESERVED_ID",
  E_RESERVED_NAME: "E_RESERVED_NAME",
  E_VERSION_TAG_MISMATCH: "E_VERSION_TAG_MISMATCH",
  E_ENGINE_CODE_RESERVED: "E_ENGINE_CODE_RESERVED",
  E_ENGINE_CODE_TAKEN: "E_ENGINE_CODE_TAKEN",
  E_SCHEMA_2_FOUNDATION: "E_SCHEMA_2_FOUNDATION",
  // content parts (manifest.md §2.7, merged plan §5.4): provenance -> manifest schema -> content check -> gi-probe
  E_CONTENT_UNDECLARED: "E_CONTENT_UNDECLARED",
  E_CONTENT_MISSING: "E_CONTENT_MISSING",
  E_CONTENT_DUPLICATE: "E_CONTENT_DUPLICATE",
  E_CONTENT_LICENCE_REFUSED: "E_CONTENT_LICENCE_REFUSED",
  // O-2: a VRM whose 0.x and 1.0 metas disagree (the content contract's own code)
  E_CONTENT_LICENCE_CONFLICT: "E_CONTENT_LICENCE_CONFLICT",
  // AstraPlugins 4976d60: a GLB that is not whole, glTF JSON that does not
  // parse or names a member twice, or an external image/buffer uri -- held
  // BEFORE classification, on every GLB and .gltf, in any part. #129 adds:
  // content judged by bytes (a GLB, text glTF or bundle under another name),
  // a % ? # or \ in a uri, the 16 MiB / depth-128 / 32 MiB caps, a BOM on a .gltf
  E_CONTENT_FORMAT: "E_CONTENT_FORMAT",
  // AstraPlugins #146 (53ab739): an avatar-classified GLB/.gltf (0.x VRM or
  // 1.0 VRMC_vrm) in ANY part that is not a character's or model's own part
  // -- animations, art, audio or command alike -- refuses outright, checked
  // BEFORE the verdict itself, whatever that verdict would have been
  // (manifest.md §2.7.3; ingest-v1.md §3 step 11/§4.3). A pack part's only
  // rights source is its declaration, never a file that merely carries an
  // avatar extension. A file in NO part at all is E_CONTENT_FILE_OUTSIDE_PARTS
  // instead, never this code.
  E_CONTENT_AVATAR_IN_PACK: "E_CONTENT_AVATAR_IN_PACK",
  // legal DRAFT-v3.md Part 6 G5: every covered part needs a licence from somewhere
  E_CONTENT_LICENCE_UNDECLARED: "E_CONTENT_LICENCE_UNDECLARED",
  F_CONTENT_VRM_META_UNKNOWN: "F_CONTENT_VRM_META_UNKNOWN",
  // AstraPlugins #146 (53ab739, G5/W1): a pack part inside an embedded bundle
  // whose rights come from a declared licence (common-v1.md §3.1.1), never
  // VRM meta -- a DIFFERENT flag from F_CONTENT_VRM_META_UNKNOWN, named for
  // what it actually is, but the SAME consequence: never a refusal, held for
  // a moderator, published flagged (manifest.md §2.7.3). The same embedded
  // bundle can carry BOTH flags at once (golden bundle-two-flags) -- neither
  // is ever dropped in favour of the other.
  F_CONTENT_LICENCE_DECLARED: "F_CONTENT_LICENCE_DECLARED",
  // AstraPlugins #129 f3e2bd0: a game's own archive (a .jar, a mod .zip) this
  // gate could not open one level deep -- over 65,536 entries or 512 MiB,
  // zip64, an unknown method, an encrypted or linked entry, a name content's
  // rules refuse, a ratio over 100, or an archive inside an archive. Shown to
  // moderators; publishes, so large modpacks still work. Cloaking is refused.
  F_CONTENT_ARCHIVE_UNSCANNED: "F_CONTENT_ARCHIVE_UNSCANNED",
  // AstraPlugins #129: an embedded .astrachar/.astrapack is judged by the
  // content contract's own ingest_bundle (spec/content/ingest-v1.md §3), and a
  // refusal keeps that contract's code. These are the ones its bundle path
  // raises besides the content codes above and E_ZIP_HEADERS_INCONSISTENT;
  // step 9's E_CONTENT_BLOCKED and step 12's E_CONTENT_PARTS_MISMATCH have
  // nothing to run on here. (F_CONTENT_ASTRACHAR_UNREADABLE, the old "gap"
  // for a bundle this catalogue could not read, is gone: such a bundle is
  // now refused with content's code.)
  E_ZIP_END_RECORD: "E_ZIP_END_RECORD",
  E_ARCHIVE_TOO_MANY_ENTRIES: "E_ARCHIVE_TOO_MANY_ENTRIES",
  E_ARCHIVE_ENCRYPTED: "E_ARCHIVE_ENCRYPTED",
  E_ARCHIVE_METHOD: "E_ARCHIVE_METHOD",
  E_ARCHIVE_LINK: "E_ARCHIVE_LINK",
  E_ARCHIVE_NAME_UNSAFE: "E_ARCHIVE_NAME_UNSAFE",
  E_ARCHIVE_TOO_LARGE: "E_ARCHIVE_TOO_LARGE",
  E_ARCHIVE_RATIO: "E_ARCHIVE_RATIO",
  E_ARCHIVE_MUST_BE_STORED: "E_ARCHIVE_MUST_BE_STORED",
  E_BUNDLE_MANIFEST: "E_BUNDLE_MANIFEST",
  E_BUNDLE_FILE_UNLISTED: "E_BUNDLE_FILE_UNLISTED",
  E_BUNDLE_FILE_DIGEST: "E_BUNDLE_FILE_DIGEST",
  E_CONTENT_TOO_LARGE: "E_CONTENT_TOO_LARGE",
  E_CONTENT_FILE_OUTSIDE_PARTS: "E_CONTENT_FILE_OUTSIDE_PARTS",
  // reserved by AstraPlugins manifest.md §2.7.3 for the plugins service's CSAM
  // scan of every image (ops lane C design §1.6a); this catalogue's public
  // Actions never scan and never emit them
  // W_CONTENT_CSAM_PENDING, F_CONTENT_CSAM_UNSCANNED
  // the per-part rights gate (lane C design §1.6): a part the author has not
  // confirmed under the current text waits; a person ticks it on the site
  W_CONTENT_UNCONFIRMED: "W_CONTENT_UNCONFIRMED",
  // the licence (A§5.2 step 4)
  E_LICENCE_NOT_ALLOWED: "E_LICENCE_NOT_ALLOWED",
  E_LICENCE_MISSING: "E_LICENCE_MISSING",
  // ids (A§5.2 step 7)
  E_ID_TAKEN: "E_ID_TAKEN",
  E_ID_CONFUSABLE: "E_ID_CONFUSABLE",
  E_VERSION_EXISTS: "E_VERSION_EXISTS",
  // the game (A§5.2 step 6, merged §2.4)
  E_ANTI_CHEAT: "E_ANTI_CHEAT",
  E_GAME_VAC: "E_GAME_VAC",
  E_GAME_UNKNOWN: "E_GAME_UNKNOWN",
  E_GAME_REFUSED: "E_GAME_REFUSED",
  W_STEAM_UNANSWERED: "W_STEAM_UNANSWERED",
  F_ONLINE_GAME: "F_ONLINE_GAME",
  // gi-probe (A§5.2 step 5)
  E_PROBE: "E_PROBE",
  E_PROBE_DISAGREES: "E_PROBE_DISAGREES",
  W_PROBE_UNAVAILABLE: "W_PROBE_UNAVAILABLE",
  F_PROBE: "F_PROBE",
  // the candidate this run built does not match the published schema (a bug here, never listed)
  E_CANDIDATE_INVALID: "E_CANDIDATE_INVALID",
  // GitHub did not answer
  W_GITHUB_UNANSWERED: "W_GITHUB_UNANSWERED",
  // moderator information (A§4.1)
  F_TAG_NOT_ON_DEFAULT_BRANCH: "F_TAG_NOT_ON_DEFAULT_BRANCH",
  F_REPO_URL_MISMATCH: "F_REPO_URL_MISMATCH",
  F_LOADER_OTHER: "F_LOADER_OTHER",
  F_WORKFLOW_ELSEWHERE: "F_WORKFLOW_ELSEWHERE",
});
