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
  F_CONTENT_ASTRACHAR_UNREADABLE: "F_CONTENT_ASTRACHAR_UNREADABLE",
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
