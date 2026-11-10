// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The vendored files, and the canary that keeps them honest (K9, and K12's
// schema half).
//
// Two upstreams are copied into lib/vendor/ at a pinned commit:
//
//   * astra-registry's provenance code (bot/lib certificate, attestation and
//     their import closure). A§5.1: the canary fails when the copy differs
//     from the pin, AND when upstream changed those files after the pin, so
//     a security fix to the plugin bot's certificate checks reaches the
//     games catalogue instead of silently staying behind.
//   * AstraPlugins' schemalite.py, the spec/games schemas, reserved.yaml and
//     the index/withdrawn goldens. Every document this repository produces is
//     validated by that exact validator against those exact schemas.
//
// Each text file carries a header naming its source path and commit, ended by
// HEADER_END; everything after that line must equal `git show <sha>:<path>`
// byte for byte. A JSON file cannot carry a comment, so it is compared whole.
// The import closure keeps upstream's relative layout (bot/lib/, tools/lib/)
// so the vendored modules' own `import` lines resolve unchanged.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const VENDOR = path.join(ROOT, "lib", "vendor");

export const HEADER_END = "END OF VENDOR HEADER";

export const PINS = Object.freeze({
  "astra-registry": {
    repo: "mihailinl/astra-registry",
    sha: "6a961d64c486033397e215d13bbde9b868e321e0",
    // astra-registry main after #498 (aca3eb7, merged as 6a961d6): policy/spdx-allowlist.json's allowed_expressions gains "MIT AND BSD-3-Clause AND CC0-1.0", the expression astra-reshade's and astra-in-death-stranding's manifests declare (our code, ReShade's own licence, CC0 parts); lib/ingest.mjs matches a whole expression, not its operands, so every release of both was refused E_LICENCE_NOT_ALLOWED. Of the nine files this pin vendors it is the only one whose content changed in a0672ac..6a961d6; the other eight are re-vendored for their header's commit alone. #496 and #497 (contract-tokens for 6.18.0 and 6.19.0) land in this range too and touch no file this pin vendors.
    // the branch the canary watches for upstream changes after the pin
    watch: "main",
    files: [
      "bot/lib/certificate.mjs",
      "bot/lib/attestation.mjs",
      "bot/lib/roots.mjs",
      "bot/lib/sign.mjs",
      "bot/lib/binding.mjs",
      "bot/lib/github.mjs",
      "bot/lib/ownership.mjs",
      "tools/lib/canonical.mjs",
      "policy/spdx-allowlist.json",
    ],
  },
  astraplugins: {
    repo: "mihailinl/AstraPlugins",
    sha: "ae035207bfaa3f05cc2ff4dda2fcfd14115798bd",
    // AstraPlugins master after #134 (e43ef33, manifest.md §2.6.1's link digest rule and vectors), #136 (c7ae74a, a kind key retires per document schema, not per kind), #144 (74224cf, spec/games-parts-bound: manifest.schema.json and games-index-v1.schema.json both gain maxItems 1024 on a GI's declared content parts, contract 6.13.0 §4.6), #146 (53ab739, the declared licence for a part with no VRM meta, G5/W1: F_CONTENT_LICENCE_DECLARED is its own flag with the same consequence as F_CONTENT_VRM_META_UNKNOWN, manifest.md §2.7.3; an avatar-classified file inside a pack part now refuses outright with E_CONTENT_AVATAR_IN_PACK; a bundle can carry both flags at once, golden bundle-two-flags), #154/#157/#158 (folded in at the 6dec4be re-pin: the command goldens' generator, the schema and content-golden checkers, and the bundle-avatar-in-pack golden), #160 (fceb8f5, capabilities-v1.md §1's command-step retry bound: a graph step's data.retry_count above 10 is E_COMMAND_FORMAT, check-content-goldens.py's derive_command enforces it and testdata/content/gen.py gains the retry-count-over-max command fixture), and #162 (8b24ab3, manifest.schema.json: an [integration] id is at most 100 characters, maxLength 100, so the catalogue's <login>/<slug> entry id never outgrows the plugins service's 100-character segment bound). #159 (a496f03, the bridge's signer-rotation step 3) and #161 (d3021cd, manifest.md §2.7's prose for the content-path control-character refusal this catalogue already enforces independently, lib/content.mjs since #17) land in this range too but touch no file this pin vendors. Then the lift (e7ff52a, 3d7685c and ae03520, the three commits of AstraPlugins #164; games-withdrawn-v1.md §2.2): games-withdrawn-v1.schema.json gains the optional top-level `lifts` (at most 256 of {repo_id, versions, entry_id?, lifts_at, at}), vectors.json gains fifteen withdrawn records and `withdrawn.scenarios`, and fifteen goldens are new, all listed below: a lift and no row, six near misses, no row and `lifts: []`, an entry_id read as a client reads it (accepted alone; refused beside its row, in ASCII and not), a cascade's banner and yank, two acts in one second, an unreadable entry_id in a row and in a lift, and four schema refusals. K12 holds this catalogue's own rules (lift-not-contradicted, one-act-per-second, entry-id-readable) to them. tools/check-games-goldens.py is not vendored. THIS PIN IS A BRANCH COMMIT until #164 is merged; it then moves to master's merge commit. #163 (36e307a, manifest.md §5.1's tag rule and the served paths) is in the range and touches no file this pin vendors.
    // The games content gate refuses what the content catalogue refuses by
    // calling the content contract's OWN reference code --
    // tools/check-content-goldens.py and tools/contentlite.py, vendored below
    // and imported by lib/schemacheck.py, never re-implemented: content by
    // bytes for every file, the uri rule (decoded once; raw %?#\ refused),
    // the 16 MiB / depth-128 / 32 MiB caps, an embedded .astrachar/.astrapack
    // judged by content's ingest_bundle, and a game's own archives opened one
    // level deep by content's walk_zip. The release goldens and both
    // generators are vendored so test/content.test.mjs runs every one of
    // them through this catalogue's own reading. AstraPlugins' default branch
    // is master, not main.
    watch: "master",
    files: [
      "tools/schemalite.py",
      "spec/games/reserved.yaml",
      "spec/games/schemas/games-index-v1.schema.json",
      "spec/games/schemas/games-withdrawn-v1.schema.json",
      "spec/games/schemas/manifest.schema.json",
      "spec/games/schemas/engine-descriptor-v1.schema.json",
      "testdata/games/vectors.json",
      "testdata/games/index/valid-index.json",
      "testdata/games/index/invalid-issued-at-too-far-ahead.json",
      "testdata/games/index/invalid-expiry-span-too-long.json",
      "testdata/games/index/invalid-missing-key-id.json",
      "testdata/games/index/invalid-withdrawn-moved-out.json",
      "testdata/games/index/invalid-entry-missing-kind.json",
      "testdata/games/index/invalid-anticheat-marker-bad-kind.json",
      "testdata/games/index/invalid-content-confirmed-bad-text-id.json",
      "testdata/games/withdrawn/valid-withdrawn.json",
      "testdata/games/withdrawn/invalid-security-not-revoke.json",
      "testdata/games/withdrawn/invalid-missing-repo-id.json",
      "testdata/games/withdrawn/invalid-bad-act-enum.json",
      "testdata/games/withdrawn/invalid-bad-reason-code-enum.json",
      "testdata/games/withdrawn/valid-lift-no-row.json",
      "testdata/games/withdrawn/valid-lift-near-miss.json",
      "testdata/games/withdrawn/valid-rows-dropped.json",
      "testdata/games/withdrawn/invalid-lift-contradicted.json",
      "testdata/games/withdrawn/invalid-lift-lifts-at-not-integer.json",
      "testdata/games/withdrawn/invalid-lift-missing-repo-id.json",
      "testdata/games/withdrawn/invalid-lift-missing-versions.json",
      "testdata/games/withdrawn/invalid-lift-unknown-member.json",
      "testdata/games/withdrawn/valid-lift-entry-id-as-a-client-reads-it.json",
      "testdata/games/withdrawn/valid-cascade-banner-and-yank.json",
      "testdata/games/withdrawn/invalid-lift-contradicted-entry-id-as-a-client-reads-it.json",
      "testdata/games/withdrawn/invalid-lift-contradicted-entry-id-unicode.json",
      "testdata/games/withdrawn/invalid-two-acts-one-second.json",
      "testdata/games/withdrawn/invalid-row-entry-id-unreadable.json",
      "testdata/games/withdrawn/invalid-lift-entry-id-unreadable.json",
      "testdata/games/manifests/valid/game-specific-link.toml",
      "testdata/games/link/digest/edge.toml",
      "testdata/games/link/digest/crlf.toml",
      "testdata/games/link/digest/crlf-as-lf.toml",
      "testdata/games/manifests/valid/foundation-owns-engine.toml",
      "testdata/games/manifests/valid/foundation-shares-engine.toml",
      "testdata/games/manifests/valid/foundation-dependency-claim.toml",
      "testdata/games/manifests/valid/runner-builtin.toml",
      "testdata/games/manifests/valid/content-parts.toml",
      "testdata/games/manifests/invalid/engine-undeclared.toml",
      "testdata/games/manifests/invalid/engine-undeclared-mismatch.toml",
      "testdata/games/manifests/invalid/engine-code-reserved.toml",
      "testdata/games/manifests/invalid/loader-policy-conflict.toml",
      "testdata/games/manifests/invalid/capability-undeclared.toml",
      "testdata/games/manifests/invalid/reserved-id.toml",
      "testdata/games/manifests/invalid/reserved-name.toml",
      "testdata/games/manifests/invalid/target-anti-cheat-missing.toml",
      "testdata/games/manifests/invalid/link-too-many-tools.toml",
      "testdata/games/manifests/invalid/unknown-top-level-key.toml",
      "testdata/games/manifests/invalid/content-kind-not-allowed.toml",
      "testdata/games/manifests/invalid/content-path-traversal.toml",
      "testdata/games/manifests/invalid/integration-uses-reserved.toml",
      "testdata/games/manifests/invalid/content-parts-over-1024.toml",
      "testdata/games/descriptors/hostile/hijack-updates-code-squatting.toml",
      "testdata/games/descriptors/hostile/take-recognised-game.toml",
      // the content contract's own code (spec/content/ingest-v1.md §3-§4), which
      // lib/schemacheck.py imports for every rule the two catalogues share
      "tools/contentlite.py",
      "tools/check-content-goldens.py",
      // every games content release golden, and the generator of the ones too
      // large to commit (synth), run by test/content.test.mjs
      "testdata/games/content/vrm/gen.py",
      "testdata/content/gen.py",
      // AstraPlugins #146 review item B1: a decoy avatar (real, allowed VRM
      // meta) hidden inside an animations pack -- content's own hostile
      // archive golden, reused directly as a games release's pack content
      // (a .astrapack is judged the same by ingest_bundle whichever test
      // suite's fixture it started as), to prove E_CONTENT_AVATAR_IN_PACK
      // reaches this catalogue's candidate as a refusing finding.
      "testdata/content/archives/hostile/decoy-allowed-vrm-in-animset.astrapack",
      "testdata/games/content/releases/allowed/art/cover.png",
      "testdata/games/content/releases/allowed/astra-gi.toml",
      "testdata/games/content/releases/allowed/character/avatar.vrm",
      "testdata/games/content/releases/animation-duplicate-key/anim/wave.glb",
      "testdata/games/content/releases/animation-duplicate-key/astra-gi.toml",
      "testdata/games/content/releases/bundle-animset-wave/astra-gi.toml",
      "testdata/games/content/releases/bundle-animset-wave/packs/wave.astrapack",
      "testdata/games/content/releases/bundle-avatar-in-pack/astra-gi.toml",
      "testdata/games/content/releases/bundle-avatar-in-pack/packs/decoy.astrapack",
      "testdata/games/content/releases/bundle-two-flags/astra-gi.toml",
      "testdata/games/content/releases/bundle-two-flags/packs/char.astrachar",
      "testdata/games/content/releases/bundle-audio-licence-undeclared/astra-gi.toml",
      "testdata/games/content/releases/bundle-audio-licence-undeclared/characters/scout.astrachar",
      "testdata/games/content/releases/bundle-gap-between-entries/astra-gi.toml",
      "testdata/games/content/releases/bundle-gap-between-entries/characters/scout.astrachar",
      "testdata/games/content/releases/bundle-glb-prohibited-beside-allowed-body/astra-gi.toml",
      "testdata/games/content/releases/bundle-glb-prohibited-beside-allowed-body/characters/scout.astrachar",
      "testdata/games/content/releases/bundle-gltf-total-over-32mib/astra-gi.toml",
      "testdata/games/content/releases/bundle-model-aiko/astra-gi.toml",
      "testdata/games/content/releases/bundle-model-aiko/characters/aiko.astrachar",
      "testdata/games/content/releases/bundle-renamed/astra-gi.toml",
      "testdata/games/content/releases/bundle-renamed/packs/wave.zip",
      "testdata/games/content/releases/bundle-vrm-metas-disagree/astra-gi.toml",
      "testdata/games/content/releases/bundle-vrm-metas-disagree/characters/scout.astrachar",
      "testdata/games/content/releases/bundle-vrm-redistribution-prohibited/astra-gi.toml",
      "testdata/games/content/releases/bundle-vrm-redistribution-prohibited/characters/scout.astrachar",
      "testdata/games/content/releases/bundle-vrm0-licence-other/astra-gi.toml",
      "testdata/games/content/releases/bundle-vrm0-licence-other/characters/scout.astrachar",
      "testdata/games/content/releases/duplicate/animations/climb.fbx",
      "testdata/games/content/releases/duplicate/astra-gi.toml",
      "testdata/games/content/releases/glb-json-over-16mib/astra-gi.toml",
      "testdata/games/content/releases/glb-named-bin/astra-gi.toml",
      "testdata/games/content/releases/glb-named-bin/data/avatar.bin",
      "testdata/games/content/releases/gltf-depth-128/astra-gi.toml",
      "testdata/games/content/releases/gltf-depth-128/models/prop.gltf",
      "testdata/games/content/releases/gltf-million-deep/astra-gi.toml",
      "testdata/games/content/releases/gltf-named-json-utf16/astra-gi.toml",
      "testdata/games/content/releases/gltf-named-json-utf16/data/avatar.json",
      "testdata/games/content/releases/gltf-named-json/astra-gi.toml",
      "testdata/games/content/releases/gltf-named-json/data/avatar.json",
      "testdata/games/content/releases/gltf-over-16mib/astra-gi.toml",
      "testdata/games/content/releases/gltf-relative-uri/astra-gi.toml",
      "testdata/games/content/releases/gltf-relative-uri/models/prop.bin",
      "testdata/games/content/releases/gltf-relative-uri/models/prop.gltf",
      "testdata/games/content/releases/gltf-too-deep/astra-gi.toml",
      "testdata/games/content/releases/gltf-too-deep/models/prop.gltf",
      "testdata/games/content/releases/gltf-total-over-32mib/astra-gi.toml",
      "testdata/games/content/releases/gltf-uri-double-encoded/astra-gi.toml",
      "testdata/games/content/releases/gltf-uri-double-encoded/models/%2e%2e/secret.bin",
      "testdata/games/content/releases/gltf-uri-double-encoded/models/prop.gltf",
      "testdata/games/content/releases/gltf-uri-escape/astra-gi.toml",
      "testdata/games/content/releases/gltf-uri-escape/models/prop.gltf",
      "testdata/games/content/releases/gltf-uri-percent/astra-gi.toml",
      "testdata/games/content/releases/gltf-uri-percent/models/..%2f..%2f..%2f..%2fetc%2fpasswd",
      "testdata/games/content/releases/gltf-uri-percent/models/prop.gltf",
      "testdata/games/content/releases/gltf-uri-space-encoded/astra-gi.toml",
      "testdata/games/content/releases/gltf-uri-space-encoded/models/data/Base Color.bin",
      "testdata/games/content/releases/gltf-uri-space-encoded/models/prop.gltf",
      "testdata/games/content/releases/gltf-utf16/astra-gi.toml",
      "testdata/games/content/releases/gltf-utf16/models/prop.gltf",
      "testdata/games/content/releases/gltf-with-bom/astra-gi.toml",
      "testdata/games/content/releases/gltf-with-bom/models/prop.gltf",
      "testdata/games/content/releases/jar-5000-entries/astra-gi.toml",
      "testdata/games/content/releases/jar-cloaked/astra-gi.toml",
      "testdata/games/content/releases/jar-cloaked/mods/avatar.jar",
      "testdata/games/content/releases/jar-glb-named-bin/astra-gi.toml",
      "testdata/games/content/releases/jar-glb-named-bin/mods/avatar.jar",
      "testdata/games/content/releases/jar-in-jar/astra-gi.toml",
      "testdata/games/content/releases/jar-in-jar/mods/outer.jar",
      "testdata/games/content/releases/jar-vrm-declared/astra-gi.toml",
      "testdata/games/content/releases/jar-vrm-declared/mods/avatar.jar",
      "testdata/games/content/releases/jar-vrm-prohibited/astra-gi.toml",
      "testdata/games/content/releases/jar-vrm-prohibited/mods/avatar.jar",
      "testdata/games/content/releases/jar-vrm-undeclared/astra-gi.toml",
      "testdata/games/content/releases/jar-vrm-undeclared/mods/avatar.jar",
      "testdata/games/content/releases/jar-zip64/astra-gi.toml",
      "testdata/games/content/releases/jar-zip64/mods/big.jar",
      "testdata/games/content/releases/json-asset-string/astra-gi.toml",
      "testdata/games/content/releases/json-asset-string/data/hero.json",
      "testdata/games/content/releases/json-many-keys-no-asset/astra-gi.toml",
      "testdata/games/content/releases/json-nested-asset/astra-gi.toml",
      "testdata/games/content/releases/json-nested-asset/data/config.json",
      "testdata/games/content/releases/json-over-16mib-nested-asset/astra-gi.toml",
      "testdata/games/content/releases/json-over-16mib-plain/astra-gi.toml",
      "testdata/games/content/releases/licence-undeclared/astra-gi.toml",
      "testdata/games/content/releases/licence-undeclared/audio/theme.ogg",
      "testdata/games/content/releases/localisation-utf16/astra-gi.toml",
      "testdata/games/content/releases/localisation-utf16/lang/credits.txt",
      "testdata/games/content/releases/localisation-utf16/lang/strings.json",
      "testdata/games/content/releases/missing/astra-gi.toml",
      "testdata/games/content/releases/pak-utf16-bom/astra-gi.toml",
      "testdata/games/content/releases/undeclared/art/cover.png",
      "testdata/games/content/releases/undeclared/astra-gi.toml",
      "testdata/games/content/releases/undeclared/audio/theme.ogg",
      "testdata/games/content/releases/vrm-named-manifest-nested/astra-gi.toml",
      "testdata/games/content/releases/vrm-named-manifest-nested/models/astra-gi.toml",
      "testdata/games/content/releases/vrm-unknown-but-declared/astra-gi.toml",
      "testdata/games/content/releases/vrm-unknown-but-declared/character/avatar.vrm",
    ],
  },
});

function commentPrefix(file) {
  if (file.endsWith(".py") || file.endsWith(".yaml") || file.endsWith(".toml")) return "# ";
  if (file.endsWith(".mjs") || file.endsWith(".js")) return "// ";
  return null; // JSON: no header possible
}

export function headerFor(upstream, file) {
  const pin = PINS[upstream];
  const p = commentPrefix(file);
  if (!p) return "";
  return [
    `${p}VENDORED from ${pin.repo} at ${pin.sha}, path ${file}.`,
    `${p}Do not edit. lib/vendored.mjs (canary K9/K12) compares everything below the next line with that commit.`,
    `${p}${HEADER_END}`,
    "",
  ].join("\n");
}

export function vendoredPath(upstream, file) {
  return path.join(VENDOR, upstream, file);
}

/** The vendored bytes with the header removed, or null when the header is wrong. */
export function stripHeader(upstream, file, bytes) {
  const header = Buffer.from(headerFor(upstream, file), "utf8");
  if (header.length === 0) return bytes;
  if (!bytes.subarray(0, header.length).equals(header)) return null;
  return bytes.subarray(header.length);
}

function gitShow(checkout, sha, file) {
  return execFileSync("git", ["-C", checkout, "show", `${sha}:${file}`], { maxBuffer: 64 * 1024 * 1024 });
}

/** Write the vendored copies from a local checkout of the upstream (used once per re-pin). */
export function vendorFrom(upstream, checkout) {
  const pin = PINS[upstream];
  for (const file of pin.files) {
    const dest = vendoredPath(upstream, file);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, Buffer.concat([Buffer.from(headerFor(upstream, file), "utf8"), gitShow(checkout, pin.sha, file)]));
  }
}

/**
 * K9 / K12: every vendored file equals the pin, and (when `upstreamRef` is
 * given) upstream has not changed any of them since.
 *
 * @param {{upstream: string, checkout?: string|null, upstreamRef?: string|null}} opts
 *   `checkout` is a local clone of the upstream holding the pinned commit.
 *   Without it only the headers and the presence of every file are checked.
 * @returns {string[]} problems; empty means the canary is green
 */
export function checkVendored({ upstream, checkout = null, upstreamRef = null }) {
  const pin = PINS[upstream];
  const problems = [];
  for (const file of pin.files) {
    const p = vendoredPath(upstream, file);
    if (!fs.existsSync(p)) {
      problems.push(`${upstream}: ${file} is not vendored`);
      continue;
    }
    const body = stripHeader(upstream, file, fs.readFileSync(p));
    if (body === null) {
      problems.push(`${upstream}: ${file} has no header naming ${pin.repo}@${pin.sha}`);
      continue;
    }
    if (checkout) {
      let want;
      try {
        want = gitShow(checkout, pin.sha, file);
      } catch (e) {
        problems.push(`${upstream}: ${file} cannot be read at ${pin.sha} in ${checkout}: ${e.message.split("\n")[0]}`);
        continue;
      }
      if (!want.equals(body)) problems.push(`${upstream}: ${file} differs from ${pin.repo}@${pin.sha}`);
    }
  }
  if (checkout && upstreamRef) {
    let changed = "";
    try {
      changed = execFileSync("git", ["-C", checkout, "diff", "--name-only", pin.sha, upstreamRef, "--", ...pin.files], {
        encoding: "utf8",
      }).trim();
    } catch (e) {
      problems.push(`${upstream}: cannot compare ${pin.sha} with ${upstreamRef}: ${e.message.split("\n")[0]}`);
    }
    for (const f of changed ? changed.split("\n") : []) {
      problems.push(`${upstream}: ${f} changed upstream after the pin (${pin.sha}..${upstreamRef}); re-vendor and re-pin`);
    }
  }
  return problems;
}
