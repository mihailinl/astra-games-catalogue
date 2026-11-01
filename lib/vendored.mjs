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
    sha: "a0672ac9646f8552f299d383bd3ea9b5eaa6eb85",
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
    sha: "d46e44a089387589018f28cfc3403399f7c3b89d",
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
      "testdata/games/withdrawn/valid-withdrawn.json",
      "testdata/games/withdrawn/invalid-security-not-revoke.json",
      "testdata/games/withdrawn/invalid-missing-repo-id.json",
      "testdata/games/withdrawn/invalid-bad-act-enum.json",
      "testdata/games/withdrawn/invalid-bad-reason-code-enum.json",
      "testdata/games/manifests/valid/game-specific-link.toml",
      "testdata/games/manifests/valid/foundation-owns-engine.toml",
      "testdata/games/manifests/valid/foundation-shares-engine.toml",
      "testdata/games/manifests/valid/foundation-dependency-claim.toml",
      "testdata/games/manifests/valid/runner-builtin.toml",
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
      "testdata/games/descriptors/hostile/hijack-updates-code-squatting.toml",
      "testdata/games/descriptors/hostile/take-recognised-game.toml",
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
