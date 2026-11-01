// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// A throwaway catalogue for the signing and act tests: a policy root, a
// trust.json fixture shaped like the published one (kind_keys for games AND
// for commands, plus an index key) signed by a throwaway ROOT that the tests
// hand in as the root set, an empty `data` directory, and candidates built
// directly (ingest's own tests cover how they are made). Every key here is a
// throwaway generated for this run.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { privateKeyFromSeed, publicKeyFromBase64, signEnvelope, TRUST_SCHEMA } from "../lib/vendor/astra-registry/bot/lib/sign.mjs";
import { descriptorDigest } from "../lib/model.mjs";
import { runSign } from "../lib/pipeline.mjs";
import { CANDIDATE_SCHEMA } from "../lib/ingest.mjs";
import { loadTrust } from "../lib/trust.mjs";
import { ROOT, throwawayKey, tmpdir } from "./helpers.mjs";

export const T0 = 1793448000; // 2026-10-31T12:00:00Z
export const NOT_BEFORE = "2026-10-01T00:00:00Z";

export function kindKeyRow(kind, role, key_id, key, not_before = NOT_BEFORE) {
  return { kind, role, key_id, alg: "ed25519", public_key: key.publicB64, not_before };
}

/**
 * A trust.json as the root ceremony publishes it, signed by `rootKey`.
 * @param {{rootKey: object, kindKeys: object[], indexKeys?: object[], expiresAt?: string, mutate?: (signed: object) => void}} o
 */
export function makeTrust({ rootKey, kindKeys, indexKeys = [], expiresAt = "2027-10-18T00:00:00Z", mutate = null }) {
  const signed = {
    schema: TRUST_SCHEMA,
    serial: 5,
    issued_at: "2026-10-20T00:00:00Z",
    expires_at: expiresAt,
    index_keys: indexKeys,
    reusable_workflow_shas: [],
    kind_keys: kindKeys,
  };
  if (mutate) mutate(signed);
  const env = signEnvelope({ domain: TRUST_SCHEMA, signed, signers: [{ key_id: "test-root", privateKey: privateKeyFromSeed(Buffer.from(rootKey.seedB64, "base64")) }] });
  return { $comment: "TEST trust.json, throwaway root", ...env };
}

export const rootsOf = (rootKey) => ({ status: "test", keys: [{ key_id: "test-root", publicKey: publicKeyFromBase64(rootKey.publicB64) }] });

export function makeCatalogue({ withNext = false } = {}) {
  const root = tmpdir("agc-root-");
  for (const f of ["first-party.json", "loaders.json"]) fs.copyFileSync(path.join(ROOT, f), path.join(root, f));
  const rootKey = throwawayKey();
  const current = throwawayKey();
  const next = throwawayKey();
  const commandsCurrent = throwawayKey();
  const commandsNext = throwawayKey();
  const indexKey = throwawayKey();
  const trust = makeTrust({
    rootKey,
    kindKeys: [
      kindKeyRow("games", "current", "astra-games-2026a", current),
      kindKeyRow("games", "next", "astra-games-2026b", next),
      kindKeyRow("commands", "current", "astra-commands-2026a", commandsCurrent),
      kindKeyRow("commands", "next", "astra-commands-2026b", commandsNext),
    ],
    indexKeys: [{ key_id: "astra-index-2026a", public_key: indexKey.publicB64, not_before: "2026-08-19T11:00:49Z", not_after: "2027-10-18T00:00:00Z" }],
  });
  const trustFile = path.join(root, "trust.json");
  fs.writeFileSync(trustFile, JSON.stringify(trust));
  const roots = rootsOf(rootKey);
  const { kindKeys } = loadTrust({ file: trustFile, now: T0, roots });
  const data = tmpdir("agc-data-");
  const env = { GAMES_SIGNING_KEY_CURRENT: current.seedB64, ...(withNext ? { GAMES_SIGNING_KEY_NEXT: next.seedB64 } : {}) };
  const sign = (opts = {}) => runSign({ dataDir: data, root, env, now: T0, trustFile, roots, ...opts });
  const dist = (f) => JSON.parse(fs.readFileSync(path.join(data, "dist", f), "utf8"));
  const state = (f) => JSON.parse(fs.readFileSync(path.join(data, f), "utf8"));
  return { root, data, env, kindKeys, trustFile, roots, rootKey, current, next, commandsCurrent, commandsNext, indexKey, sign, dist, state };
}

const hex = (s) => crypto.createHash("sha256").update(String(s)).digest("hex");

export const FOO_DESCRIPTOR = {
  schema: "astra.engine/1",
  engine: { codes: { "foo-engine": "Foo Engine" } },
  rule: [{ tier: "strong", programs: { ext: ["exe"] }, require: [{ listed: "foo_runtime.dll", kind: "file" }], code: "foo-engine", confidence: "high", binary: "windows", evidence: "{project}" }],
};

let nextRepo = 910000000;

/**
 * One accepted release as ingest would hand it to the signer.
 * @param {{account?: string, slug?: string, repo_id?: number, owner_id?: number, version?: string,
 *          kind?: "integration"|"foundation", appid?: number, engine?: string, descriptor?: object|null,
 *          foundation?: object|null, manifest_id?: string, status?: string, first_party?: boolean, released_at?: number}} o
 */
export function candidate(o = {}) {
  const account = o.account ?? "author";
  const slug = o.slug ?? `gi-${nextRepo}`;
  const repo_id = o.repo_id ?? nextRepo++;
  const owner_id = o.owner_id ?? 800000001;
  const version = o.version ?? "1.0.0";
  const kind = o.kind ?? "integration";
  const target = kind === "integration" ? { store: "steam", id: o.appid ?? 4000001, exe: "Game.exe" } : { exe: "*" };
  if (o.engine) target.engine = o.engine;
  const sha = hex(`${repo_id}/${version}`);
  const entry = {
    id: `${account}/${slug}`,
    kind,
    publisher: { account, repo_id, repo_owner_id: owner_id },
    source: {
      host: "github.com", repo: `${account}/${slug}`, repo_id, repo_owner_id: owner_id,
      release_tag: `v${version}`, asset: "astra-gi.zip", sha256: sha, size: 1024,
      commit: sha.slice(0, 40), workflow_path: ".github/workflows/gi-release.yml", event: "push",
    },
    version, schema: 1, min_astra: "0.2.8",
    target,
    descriptor: o.descriptor ?? null,
    descriptor_sha256: o.descriptor ? descriptorDigest(o.descriptor) : null,
    sdk: null,
    foundation: o.foundation ?? null,
    built_on: null,
    engine_versions: null,
    link: null,
    schema_digests: {},
    capabilities: [],
    shares_other_players: false,
    changes: { profile_files: true, game_files: [], launch: false, config_writes: false },
    code_changed: false,
    licence: "MIT",
    review: "unchecked",
    supersedes: [],
    flags: [],
    notes: {},
  };
  return {
    schema: CANDIDATE_SCHEMA,
    request: { repo_id, tag: `v${version}` },
    verdict: o.verdict ?? "accept",
    findings: o.findings ?? [],
    flags: [],
    entry,
    meta: {
      status: o.status ?? "listed",
      first_party: o.first_party ?? false,
      manifest_id: o.manifest_id ?? `${account}.${slug}`,
      released_at: o.released_at ?? T0 - 3600,
      files: o.files ?? { [`${slug}.dll`]: sha },
      binding: { account, repo_id, repo_owner_id: owner_id, binding_token: `token_${repo_id}_abcdefgh` },
      online: [],
    },
  };
}

/** An act as the site sends it after the moderator's console 2FA. */
let nextRef = 1;
export function act(type, payload = {}, at = T0) {
  // every act is its own confirmation, as the service's act_id makes it
  return { schema: "astra.games.act/1", type, at, by: { account: "mod-1" }, confirmation: { kind: "console-2fa", ref: `act-${nextRef++}` }, ...payload };
}
