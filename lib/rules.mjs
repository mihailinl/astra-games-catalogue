// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The rules a JSON Schema cannot express, over a parsed manifest and the
// catalogue's state: the manifest's cross-field rules (manifest.md §2-§3,
// the same five check-games-goldens.py runs), engine-code ownership (merged
// §2.1), ids (A§5.2 step 7) and the publisher identity (R10).
//
// Each manifest rule here is named for the golden that proves it
// (testdata/games/manifests/invalid/<rule>.toml, vendored), and
// test/rules.test.mjs runs every one of those goldens through it.

import { CODES, finding } from "./codes.mjs";

// ── identity (R10, A§5.2 step 1) ──────────────────────────────────────────

/** `{account, repo_id, repo_owner_id}`, the bound publisher. */
export function identityOf(x) {
  return { account: x.account, repo_id: x.repo_id, repo_owner_id: x.repo_owner_id };
}

export function sameIdentity(a, b) {
  return (
    !!a && !!b &&
    String(a.account).toLowerCase() === String(b.account).toLowerCase() &&
    Number(a.repo_id) === Number(b.repo_id) &&
    Number(a.repo_owner_id) === Number(b.repo_owner_id)
  );
}

// ── folding: one skeleton for ids, names and codes ─────────────────────────

// Latin look-alikes a reader cannot tell apart at a glance, plus the Cyrillic
// and Greek letters that render as Latin ones. Not a full UTS #39 table: the
// catalogue's ids are `^[A-Za-z0-9._-]+$` (manifest.schema.json), so the only
// confusions left inside that alphabet are the digit/letter pairs and the
// separators, and the non-Latin rows exist for display names.
const CONFUSABLE = new Map(Object.entries({
  "0": "o", "1": "l", "i": "l", "|": "l", "5": "s", "2": "z", "8": "b", "6": "b", "9": "g", "3": "e", "4": "a", "7": "t",
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "к": "k", "м": "m", "т": "t", "в": "b", "н": "h",
  "і": "l", "ј": "j", "ѕ": "s", "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t", "κ": "k", "ι": "l",
}));

export function skeleton(s) {
  let t = String(s).normalize("NFKC").toLowerCase();
  t = t.replace(/rn/g, "m").replace(/vv/g, "w").replace(/cl/g, "d");
  let out = "";
  for (const ch of t) {
    if (ch === "-" || ch === "_" || ch === "." || ch === " ") continue;
    out += CONFUSABLE.get(ch) ?? ch;
  }
  return out;
}

/** engine-descriptor-v1.md §2.1: `_` folds to `-`, then the confusables fold. */
export function foldCode(code) {
  return skeleton(String(code).replace(/_/g, "-"));
}

// ── entry ids ─────────────────────────────────────────────────────────────

/**
 * The catalogue id of a release: `<publisher account>/<slug>`, where the slug
 * is the manifest's `[integration] id` with a leading `<account>.` removed
 * and the remaining dots written as dashes — `someone.peak-astra` published by
 * `someone` is `someone/peak-astra`, and first-party `astra.unity` is
 * `mihailinl/astra-unity`, the spellings games-index-v1.md's examples use.
 * An id survives a repository rename or transfer (the repo is not in it), and
 * a repository that hosts several integrations gets one id per integration
 * (R43).
 */
export function entryIdFor(account, manifestId) {
  const acct = String(account);
  let slug = String(manifestId);
  if (slug.toLowerCase().startsWith(`${acct.toLowerCase()}.`)) slug = slug.slice(acct.length + 1);
  return `${acct}/${slug.replace(/\./g, "-")}`;
}

// ── the manifest's own rules ───────────────────────────────────────────────

export function descriptorOf(manifest) {
  return manifest?.integration?.engine ?? null;
}

export function descriptorCodes(descriptor) {
  return Object.keys(descriptor?.engine?.codes ?? {});
}

/** manifest.md §2.1: a manifest carrying [integration.engine] sets [target].engine to one of its codes. */
export function ruleEngineUndeclared(manifest) {
  const d = descriptorOf(manifest);
  if (!d) return true;
  return descriptorCodes(d).includes(manifest?.target?.engine);
}

/** manifest.md §2.2: proxies and keep_if_present are disjoint. */
export function ruleLoaderPolicyConflict(manifest) {
  const l = manifest?.integration?.loader ?? {};
  const keep = new Set(l.keep_if_present ?? []);
  return !(l.proxies ?? []).some((p) => keep.has(p));
}

/** manifest.md §2.3: ${bridge_token} in a config write needs companion.presentation. */
export function ruleCapabilityUndeclared(manifest) {
  const uses = (manifest?.config_writes ?? []).some((cw) =>
    Object.values(cw?.set ?? {}).some((v) => String(v).includes("${bridge_token}")),
  );
  if (!uses) return true;
  return (manifest?.integration?.capabilities?.companion ?? []).includes("presentation");
}

export function ruleReservedId(manifest, reserved) {
  const id = String(manifest?.integration?.id ?? "");
  return !reserved.integration_id_reserved_prefixes.some((p) => id.startsWith(p));
}

export function ruleReservedName(manifest, reserved) {
  const name = String(manifest?.integration?.name ?? "").toLowerCase();
  return !reserved.integration_name_reserved_substrings.some((s) => name.includes(s.toLowerCase()));
}

/** engine-code-reserved: a descriptor may not claim a built-in or the `unknown` sentinel. */
export function reservedCodesClaimed(codes, reserved) {
  const r = new Set(reserved.engine_codes.map(foldCode));
  return codes.filter((c) => r.has(foldCode(c)));
}

/**
 * The manifest's cross-field rules, as findings.
 *
 * `firstParty` lifts only the two reserved-namespace rules: `astra.`/`minice.`
 * ids and the Minice/Official names are reserved FOR the first-party
 * publisher (reserved.yaml), not from it.
 */
export function manifestFindings(manifest, { reserved, firstParty = false, tag = null }) {
  const out = [];
  if (manifest?.schema !== 1) {
    out.push(finding(CODES.E_SCHEMA_2_FOUNDATION, `schema = ${JSON.stringify(manifest?.schema)}: game integrations are schema 1 (merged R12); schema 2 is reserved for new placement modes`));
  }
  if (!ruleEngineUndeclared(manifest)) {
    out.push(finding(CODES.E_ENGINE_UNDECLARED, "engine-undeclared: [integration.engine] is present and [target] engine does not name one of its codes (manifest.md §2.1)"));
  }
  if (!ruleLoaderPolicyConflict(manifest)) {
    out.push(finding(CODES.E_LOADER_POLICY_CONFLICT, "loader-policy-conflict: a name is in both [integration.loader] proxies and keep_if_present (manifest.md §2.2)"));
  }
  if (!ruleCapabilityUndeclared(manifest)) {
    out.push(finding(CODES.E_CAPABILITY_UNDECLARED, "capability-undeclared: a config write uses ${bridge_token} and [integration.capabilities] companion does not list \"presentation\" (manifest.md §2.3)"));
  }
  if (!firstParty && !ruleReservedId(manifest, reserved)) {
    out.push(finding(CODES.E_RESERVED_ID, `reserved-id: ${manifest?.integration?.id} starts with a prefix reserved to the first-party publisher`));
  }
  if (!firstParty && !ruleReservedName(manifest, reserved)) {
    out.push(finding(CODES.E_RESERVED_NAME, `reserved-name: "${manifest?.integration?.name}" contains a name reserved to the first-party publisher`));
  }
  const claimed = reservedCodesClaimed(descriptorCodes(descriptorOf(manifest)), reserved);
  if (claimed.length) {
    out.push(finding(CODES.E_ENGINE_CODE_RESERVED, `engine-code-reserved: the descriptor claims ${claimed.join(", ")}, which only the launcher's compiled built-ins may (reserved.yaml)`));
  }
  if (tag !== null) {
    const want = String(tag).replace(/^v/, "");
    if (String(manifest?.integration?.version) !== want) {
      out.push(finding(CODES.E_VERSION_TAG_MISMATCH, `[integration] version is ${JSON.stringify(manifest?.integration?.version)} and the release tag ${tag} says ${want}; a listed version is the tag it was built from`));
    }
  }
  const anti = manifest?.target?.anti_cheat;
  if (anti !== undefined && anti !== "none") {
    out.push(finding(CODES.E_ANTI_CHEAT, `[target] anti_cheat = ${JSON.stringify(anti)}: no integration is listed for a game with anti-cheat (A§5.2 step 6)`));
  }
  return out;
}

// ── engine codes (merged §2.1) ────────────────────────────────────────────

/**
 * engine-code-taken: a code already owned by a DIFFERENT publisher identity
 * (compared after the code fold, so `source_2` cannot take `source-2`).
 * The owner's own next release passes.
 */
export function engineCodeFindings({ codes, identity, engineCodes, reserved }) {
  const out = [];
  const owners = new Map(Object.entries(engineCodes ?? {}).map(([c, who]) => [foldCode(c), { code: c, who }]));
  const reservedSet = new Set(reserved.engine_codes.map(foldCode));
  for (const code of codes) {
    if (reservedSet.has(foldCode(code))) continue; // reported as engine-code-reserved
    const owner = owners.get(foldCode(code));
    if (owner && !sameIdentity(owner.who, identity)) {
      out.push(finding(
        CODES.E_ENGINE_CODE_TAKEN,
        `engine-code-taken: "${code}" belongs to ${owner.who.account} (repository ${owner.who.repo_id})` +
          (owner.code !== code ? ` as "${owner.code}"` : "") +
          ". Build on it with [target] engine = \"" + owner.code + "\" and no [integration.engine] table; a squatted code moves only by a moderator act",
        { engine_code: code },
      ));
    }
  }
  return out;
}

// ── ids (A§5.2 step 7) ────────────────────────────────────────────────────

/**
 * An id another publisher already lists is taken; an id whose skeleton
 * equals another publisher's is confusable. The same publisher may list ids
 * that look alike: it can only confuse users about itself.
 *
 * @param {{entryId: string, identity: object, entries: {entry: object}[]}} opts
 */
export function idFindings({ entryId, identity, entries }) {
  const out = [];
  const sk = skeleton(entryId);
  const seen = new Set();
  for (const { entry } of entries) {
    if (seen.has(entry.id)) continue;
    seen.add(entry.id);
    if (sameIdentity(entry.publisher, identity)) continue;
    if (entry.id === entryId) {
      out.push(finding(CODES.E_ID_TAKEN, `${entryId} is listed by ${entry.publisher.account} (repository ${entry.publisher.repo_id})`));
    } else if (skeleton(entry.id) === sk) {
      out.push(finding(CODES.E_ID_CONFUSABLE, `${entryId} reads the same as ${entry.id}, which ${entry.publisher.account} lists`));
    }
  }
  return out;
}
