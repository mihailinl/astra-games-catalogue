// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The sign side of a candidate: what the signing job does with ingest's
// output before a key touches it.
//
// A§5.1: sign.yml "re-validates schema only, never parses a zip". It also
// re-runs the checks that depend on the catalogue's STATE, because the state
// can move between an ingest and its sign — two foundations claiming one new
// engine code can both pass ingest against a state where neither owns it,
// and only the first to be signed may win. Nothing here trusts the
// candidate's own verdict beyond "accept" or "hold": a candidate is data
// from a job that read a stranger's release.

import { CANDIDATE_SCHEMA } from "./ingest.mjs";
import { versionsOf } from "./model.mjs";
import { descriptorCodes, engineCodeFindings, foldCode, idFindings, identityOf, sameIdentity } from "./rules.mjs";
import { validateEntries } from "./schemas.mjs";

export function holdIdOf(c) {
  return `${c.request.repo_id}@${c.request.tag}`;
}

/**
 * @returns {{result: "listed"|"prerelease"|"held"|"refused"|"skipped", reason: string}}
 */
export function acceptCandidate(candidate, state, { reserved, now, releasedBy = null, shape = null }) {
  if (candidate?.schema !== CANDIDATE_SCHEMA) return { result: "refused", reason: `not an ${CANDIDATE_SCHEMA} document` };
  if (candidate.verdict !== "accept" && candidate.verdict !== "hold") {
    return { result: "skipped", reason: `ingest's verdict is ${candidate.verdict}` };
  }
  const { entry, meta } = candidate;
  if (!entry || !meta) return { result: "refused", reason: "the candidate carries no entry" };
  const checked = shape ?? validateEntries([entry])[0];
  if (!checked.ok) return { result: "refused", reason: `games-index-v1.schema.json: ${checked.error}` };
  // The verdict is the candidate's word; its findings say whether that word
  // can be true. A wait (an unconfirmed part, an unanswered read) or a
  // refusal among them is never listed, whatever `verdict` claims.
  const blocking = (candidate.findings ?? []).map((f) => String(f?.code ?? "")).filter((c) => /^(E|W)_/.test(c));
  if (blocking.length) return { result: "refused", reason: `the candidate says ${candidate.verdict} over ${[...new Set(blocking)].join(", ")}` };
  // The rights gate's second half (lane C design §1.6): a listed part was
  // confirmed under a text, and the entry says which.
  if ((entry.content ?? []).length && !Object.keys(entry.content_confirmed ?? {}).length) {
    return { result: "refused", reason: `${entry.id} ${entry.version} carries content parts and no content_confirmed` };
  }

  const repoKey = String(entry.source.repo_id);
  const identity = identityOf(entry.publisher);
  const problems = [];
  if (versionsOf(state.entries, entry.id).some((e) => e.entry.version === entry.version)) problems.push(`${entry.id} ${entry.version} is already in the catalogue`);
  // After a person accepted a change of hands, the listing's older versions
  // still carry the previous identity of the SAME repository: that is the
  // listing moving, not another publisher's id.
  const others = releasedBy ? state.entries.filter((e) => Number(e.entry.source.repo_id) !== Number(entry.source.repo_id)) : state.entries;
  problems.push(...idFindings({ entryId: entry.id, identity, entries: others }).map((f) => f.message));
  const codes = entry.descriptor ? descriptorCodes(entry.descriptor) : [];
  problems.push(...engineCodeFindings({ codes, identity, engineCodes: state.engineCodes, reserved }).map((f) => f.message));
  if (problems.length) return { result: "refused", reason: problems.join("; ") };

  const bound = state.bindings[repoKey] ?? null;
  const bindingMoved = bound && !meta.first_party && !sameIdentity(bound, identity);
  if (candidate.verdict === "hold" || bindingMoved) {
    const hold_id = holdIdOf(candidate);
    state.holds = state.holds.filter((h) => h.hold_id !== hold_id);
    const codesHeld = candidate.findings.filter((f) => /^(H_|R_)/.test(f.code)).map((f) => f.code);
    state.holds.push({ hold_id, codes: bindingMoved && !codesHeld.length ? ["R_BINDING_CHANGED"] : codesHeld, candidate, at: now });
    return { result: "held", reason: `held for a person: ${codesHeld.join(", ") || "R_BINDING_CHANGED"}` };
  }

  if (!bound && !meta.first_party) {
    state.bindings[repoKey] = { ...identity, binding_token: meta.binding?.binding_token ?? null, bound_at: now };
  }
  for (const c of codes) {
    if (!Object.keys(state.engineCodes).some((k) => foldCode(k) === foldCode(c))) state.engineCodes[c] = identity;
  }
  const status = meta.status === "prerelease" ? "prerelease" : "listed";
  state.entries.push({
    entry,
    meta: {
      status,
      first_party: meta.first_party === true,
      manifest_id: meta.manifest_id,
      released_at: meta.released_at,
      accepted_at: now,
      files: meta.files ?? {},
      online: meta.online ?? [],
      probe: meta.probe ?? null,
      ...(releasedBy ? { released_by: releasedBy } : {}),
    },
  });
  return { result: status, reason: status === "prerelease" ? "first-party prerelease: listed once promoted" : "listed" };
}
