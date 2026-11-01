// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Lane C's "done when", on the staging fixtures: a non-owner account
// publishes a C# test GI and a foo-engine foundation, ingest turns both into
// candidates with no key anywhere near it, and ONE signing run lists both;
// then a revoke is in the withdrawn document in that same run.

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { act, makeCatalogue, T0 } from "./catalogue.mjs";
import { INDEX_SCHEMA, verifyDocuments, WITHDRAWN_SCHEMA } from "../lib/documents.mjs";
import { ingestRelease } from "../lib/ingest.mjs";
import { descriptorDigest } from "../lib/model.mjs";
import { loadReserved, readTomlFile } from "../lib/schemas.mjs";
import { emptyModeration } from "../lib/state.mjs";
import { ROOT, fakeGh, fakeGithub, fakeSteam, fixture, fixtureText, makeZip, sha256, stubProbe, tmpdir } from "./helpers.mjs";

const reserved = loadReserved();
const firstParty = JSON.parse(fs.readFileSync(path.join(ROOT, "first-party.json"), "utf8"));
const state0 = () => ({ entries: [], bindings: {}, engineCodes: {}, moderation: emptyModeration(), withdrawn: { rows: [], held: [] }, holds: [], health: {}, floors: {} });

async function ingest({ zip, repo, tag, manifestId, version, descriptorSha = null, certificate = {} }) {
  const release = { ...fixture("release.json"), tag_name: tag };
  return ingestRelease({
    request: { repo_id: repo.id, tag, account: "astra-staging-author", binding_token: "stagingBindingToken_0123456789abcdef" },
    policy: { firstParty, loadersFile: path.join(ROOT, "loaders.json") },
    state: state0(),
    reserved,
    deps: {
      github: fakeGithub({ zip, repo, release }),
      gh: fakeGh({ sha: sha256(zip), certificate }),
      probe: stubProbe({ manifestId, version, descriptorSha }),
      steam: fakeSteam(),
      workdir: tmpdir(),
      now: () => T0,
    },
  });
}

test("a non-owner publishes a C# GI and a foo-engine foundation; one run signs both; a revoke lands in the same run", async () => {
  const giZip = makeZip({ "astra-gi.toml": fixtureText("astra-gi.toml"), "BepInEx/plugins/Staging.dll": "x" });
  const gi = await ingest({ zip: giZip, repo: fixture("repo.json"), tag: "v1.0.0", manifestId: "astra-staging-author.staging-csharp-gi", version: "1.0.0" });
  assert.equal(gi.verdict, "accept", JSON.stringify(gi.findings));

  const fooText = fixtureText("foo-engine.toml");
  const fooZip = makeZip({ "astra-gi.toml": fooText, "foo/runtime.dll": "y" });
  const tomlFile = path.join(tmpdir(), "foo.toml");
  fs.writeFileSync(tomlFile, fooText);
  const descriptorSha = descriptorDigest(readTomlFile(tomlFile).manifest.integration.engine);
  const fooRepo = { ...fixture("repo.json"), id: 900000002, full_name: "astra-staging-author/staging-foo-engine" };
  const foo = await ingest({
    zip: fooZip, repo: fooRepo, tag: "v0.1.0", manifestId: "astra-staging-author.foo-engine", version: "0.1.0", descriptorSha,
    certificate: {
      sourceRepositoryRef: "refs/tags/v0.1.0", sourceRepositoryIdentifier: "900000002",
      sourceRepositoryURI: "https://github.com/astra-staging-author/staging-foo-engine",
      buildSignerURI: "https://github.com/astra-staging-author/staging-foo-engine/.github/workflows/gi-release.yml@refs/tags/v0.1.0",
    },
  });
  assert.equal(foo.verdict, "accept", JSON.stringify(foo.findings));

  const c = makeCatalogue();
  const r = c.sign({ candidates: [JSON.parse(JSON.stringify(gi)), JSON.parse(JSON.stringify(foo))] });
  assert.deepEqual(r.accepted.map((a) => a.result), ["listed", "listed"]);
  const index = c.dist("games-index.json");
  assert.deepEqual(index.signed.entries.map((e) => e.id).sort(), ["astra-staging-author/foo-engine", "astra-staging-author/staging-csharp-gi"]);
  assert.equal(index.signed.engine_codes["foo-engine"].repo_id, 900000002);
  assert.equal(index.signed.entries.find((e) => e.kind === "foundation").descriptor_sha256, descriptorSha);

  c.sign({ acts: [act("M_REVOKE", { repo_id: 900000001, versions: "1.0.0", reason_code: "security", reason_text: "staging drill" })] });
  const withdrawn = c.dist("games-withdrawn.json");
  assert.deepEqual(withdrawn.signed.rows.map((x) => [x.repo_id, x.act]), [[900000001, "revoke"]]);
  const problems = verifyDocuments([
    { envelope: c.dist("games-index.json"), domain: INDEX_SCHEMA },
    { envelope: withdrawn, domain: WITHDRAWN_SCHEMA, indexBody: c.dist("games-index.json").signed },
  ], { keys: c.keys, now: T0 });
  assert.deepEqual(problems, [[], []]);
});
