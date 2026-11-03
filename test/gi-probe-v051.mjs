// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// gi-probe 0.5.1's interface, FROZEN from astra-game-launcher tag v0.5.1
// (ede231babfc101df6c57e4a56bd4e346d233efb7) by reading its source —
// `git show v0.5.1:<path>` — on 2026-11-02. No gi-probe binary was run to
// write this, and none is run by the tests: fixtures/gi-probe/fake-gi-probe.mjs
// answers in its place, and test/probe.test.mjs holds lib/probe.mjs's command
// lines to what this file says main.rs accepts.
//
// What changed from test/gi-probe-v050.mjs (diffed source, not run): the CLI
// surface below — every subcommand, its options, flags, positional count and
// `need`s — is BYTE IDENTICAL to 0.5.0's; only comments and doc text moved
// (main.rs grew by three lines: a `mod toml10;` and two doc-text words). What
// changed is what `check` and `validate-descriptor` now JUDGE, never what
// they ACCEPT on the command line:
//   - the manifest and a descriptor are held to TOML 1.0, as the
//     specification parses them: TOML 1.1 syntax (`\e`, `\xHH`, a multi-line
//     inline table, a trailing comma, a time without seconds) or a leading
//     byte-order mark is `manifest-invalid{reason=toml-1.0}` /
//     `descriptor-invalid{reason=toml-1.0}` (`src/bin/gi-probe/toml10.rs`),
//     and the report's digests (`link.digest`, `descriptor.sha256`) `null`;
//   - `[integration.link]`'s consent digest is reported as `link.digest`
//     (manifest.md §2.6.1); a table it cannot digest is `link-invalid{reason=
//     not-digestable}` and the digest `null`;
//   - a descriptor's `mods` (spec §7) is judged, not merely accepted:
//     anything wrong inside it is `mods-invalid{field, reason}` (§7.9's
//     reasons), and the descriptor is refused for it, as ingest refuses it; a
//     client that reads a descriptor with `mods` wrong drops only `mods`.
//     `descriptor.mods_loaders` names a valid `mods`'s loader ids in order
//     (`null` without `mods`, `[]` for one refused);
//   - content round 3 (AstraPlugins #129: a game's own archive opened one
//     level deep, an embedded `.astrachar`/`.astrapack` judged by the content
//     catalogue's own ingest_bundle codes) is now `check`'s own step 8
//     finding/notice, not only the catalogue's separate reading of the zip.
//
// A re-pin (gi-probe.json) re-reads the new tag and edits this file in the
// same pull request; with ASTRA_GAME_LAUNCHER_REPO set, probe.test.mjs
// re-parses main.rs at the pinned tag and fails on any difference.

export const TAG = "v0.5.1";

/** `tool` of every report (main.rs l.270-276): Cargo.toml's version, build.rs's tree hash. */
export const TOOL = Object.freeze({
  version: "0.5.1",
  // build.rs l.11-17's algorithm (unchanged from 0.5.0) over `git ls-tree -r
  // v0.5.1` (515 files), recomputed from source
  source_tree_sha256: "09a34a65ff200c9e313a8297efcdb5dc7c9db92c8deac0af3d671862d028ef46",
});

/** `spec.sha` (descriptor.rs l.60-63: tests/goldens/astraplugins/PIN at v0.5.1). */
export const SPEC_SHA = "c7ae74ab89c200f52318a08dcf4095cd436b181f";

/** main.rs l.49. */
export const REPORT_SCHEMA = "astra.gi-probe/1";

/**
 * Every subcommand main.rs's `run` dispatches (l.449-543), with the options
 * that take a value and the flags its `Args::parse` call names, how many
 * positional arguments it takes, and the options it `need`s. Byte identical
 * to 0.5.0's ACCEPTS (see the module doc): no subcommand gained, lost or
 * reshaped an option or a flag between 0.5.0 and 0.5.1.
 */
export const ACCEPTS = Object.freeze({
  // main.rs l.454-474: Args::parse(rest, &["zip", "source", "tag", "asset", "sha256", "previous", "notes"], &["prerelease"]); no_positional; need zip, source, tag
  compat: Object.freeze({ options: ["zip", "source", "tag", "asset", "sha256", "previous", "notes"], flags: ["prerelease"], positional: 0, required: ["zip", "source", "tag"] }),
  // main.rs l.475-500: Args::parse(rest, &["provenance", "foundation", "previous", "loaders"], &[]); one positional
  check: Object.freeze({ options: ["provenance", "foundation", "previous", "loaders"], flags: [], positional: 1, required: [] }),
  // main.rs l.501-511: Args::parse(rest, &["corpus"], &["first-party"]); one positional
  "validate-descriptor": Object.freeze({ options: ["corpus"], flags: ["first-party"], positional: 1, required: [] }),
  // main.rs l.512-531: Args::parse(rest, &["out", "label", "appid", "hint"], &[]); one positional; need out
  capture: Object.freeze({ options: ["out", "label", "appid", "hint"], flags: [], positional: 1, required: ["out"] }),
  // main.rs l.532-540: Args::parse(rest, &["source", "listing"], &["prerelease"]); no_positional; need source, listing
  pick: Object.freeze({ options: ["source", "listing"], flags: ["prerelease"], positional: 0, required: ["source", "listing"] }),
});

/** check's --provenance values (main.rs l.484-492); community is the default. */
export const PROVENANCE = Object.freeze(["first-party", "community"]);

/**
 * A command line as main.rs reads it: `Args::parse` (l.400-426) — `--name
 * value` for an option, `--flag`, anything else positional; an unknown
 * option, a missing value or an option given twice is a usage error — then
 * each subcommand's positional count, its `need`s and check's provenance.
 * @param {string[]} argv without the program name
 * @returns {{ok: true, sub: string, positional: string[], opts: Record<string, string>, flags: string[]} | {ok: false, detail: string}}
 */
export function parseLikeMain(argv) {
  if (!argv.length) return { ok: false, detail: "no subcommand" };
  const [sub, ...rest] = argv;
  const spec = Object.hasOwn(ACCEPTS, sub) ? ACCEPTS[sub] : null;
  if (!spec) return { ok: false, detail: `unknown subcommand ${JSON.stringify(sub)}` };
  const positional = [];
  const opts = {};
  const flags = [];
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    if (arg.startsWith("--")) {
      const name = arg.slice(2);
      if (spec.options.includes(name)) {
        if (i + 1 >= rest.length) return { ok: false, detail: `--${name} needs a value` };
        if (Object.hasOwn(opts, name)) return { ok: false, detail: `--${name} given twice` };
        opts[name] = rest[++i];
      } else if (spec.flags.includes(name)) {
        flags.push(name);
      } else {
        return { ok: false, detail: `unknown option --${name}` };
      }
    } else {
      positional.push(arg);
    }
  }
  if (positional.length !== spec.positional) {
    return { ok: false, detail: spec.positional === 0 ? `unexpected argument ${JSON.stringify(positional[0])}` : `${sub} takes one file` };
  }
  for (const name of spec.required) {
    if (!Object.hasOwn(opts, name)) return { ok: false, detail: `--${name} is required` };
  }
  if (sub === "check" && opts.provenance !== undefined && !PROVENANCE.includes(opts.provenance)) {
    return { ok: false, detail: `--provenance is first-party or community, not ${JSON.stringify(opts.provenance)}` };
  }
  if (sub === "capture" && opts.appid !== undefined && !/^\d+$/.test(opts.appid)) {
    return { ok: false, detail: `--appid is a number, not ${JSON.stringify(opts.appid)}` };
  }
  return { ok: true, sub, positional, opts, flags };
}

/**
 * src/bin/gi-probe/compat-0.2.7.json at v0.5.1 (sha256 81edbf0b…159c, byte
 * identical to 0.5.0's copy): the sources `compat --source` accepts
 * (compat.rs l.142-150 refuses any other id, exit 2; compat.rs itself has no
 * diff at all between 0.5.0 and 0.5.1), with what compat reports of each
 * (`source`, compat.rs l.152-165) and `against` (l.167-169).
 */
export const COMPAT_027 = Object.freeze({
  against: {
    astra: { tag: "v0.2.7", commit: "6fea01a01c1ca4209a967ff69d9afa065bdb22bb", file: "astra-rs/astra-daemon/src/games/pins.rs" },
    launcher: { version: "0.3.1", rev: "9aa7874b60f6b10bd67411b7aad40fcc968b78bc" },
  },
  sources: [
    { id: "astra.unity", repo: "mihailinl/astra-bepinex", repo_id: 1408152993, tag_prefix: "v", asset: "astra-gi.zip", target: { runner: { engine: "unity-mono" } } },
    { id: "astra.unity-il2cpp", repo: "mihailinl/astra-bepinex", repo_id: 1408152993, tag_prefix: "v", asset: "astra-gi-il2cpp.zip", target: { runner: { engine: "unity-il2cpp" } } },
    { id: "astra.unreal", repo: "mihailinl/astra-reshade", repo_id: 1412685270, tag_prefix: "v", asset: "astra-gi.zip", target: { runner: { engine: "unreal" } } },
    { id: "astra.unreal.gta3-definitive-edition", repo: "mihailinl/astra-reshade", repo_id: 1412685270, tag_prefix: "v", asset: "astra-gi-gta3.zip", target: { game: { appid: "1546970", exe: "Gameface/Binaries/Win64/LibertyCity.exe" } } },
    { id: "astra.lethal-company", repo: "mihailinl/astra-lethal", repo_id: 1409552539, tag_prefix: "v", asset: "astra-gi.zip", target: { game: { appid: "1966720", exe: null } } },
    { id: "astra.content-warning", repo: "mihailinl/astra-content-warning", repo_id: 1409552609, tag_prefix: "v", asset: "astra-gi.zip", target: { game: { appid: "2881650", exe: null } } },
    { id: "astra.peak", repo: "mihailinl/astra-peak", repo_id: 1409552680, tag_prefix: "v", asset: "astra-gi.zip", target: { game: { appid: "3527290", exe: null } } },
    { id: "astra.repo", repo: "mihailinl/astra-repo", repo_id: 1409552749, tag_prefix: "v", asset: "astra-gi.zip", target: { game: { appid: "3241660", exe: null } } },
    { id: "astra.death-stranding", repo: "mihailinl/astra-in-death-stranding", repo_id: 1405082830, tag_prefix: "v", asset: "astra-gi-ds1.zip", target: { game: { appid: "1850570", exe: "ds.exe" } } },
    { id: "astra.death-stranding-2", repo: "mihailinl/astra-in-death-stranding", repo_id: 1405082830, tag_prefix: "v", asset: "astra-gi-ds2.zip", target: { game: { appid: "3280350", exe: "DS2.exe" } } },
    { id: "astra.gta-trilogy.gta3", repo: "mihailinl/astra-gta-trilogy", repo_id: 1427110216, tag_prefix: "v", asset: "astra-gi-gta3.zip", target: { game: { appid: "1546970", exe: "Gameface/Binaries/Win64/LibertyCity.exe" } } },
    { id: "astra.gta-trilogy.vicecity", repo: "mihailinl/astra-gta-trilogy", repo_id: 1427110216, tag_prefix: "v", asset: "astra-gi-vicecity.zip", target: { game: { appid: "1546990", exe: "Gameface/Binaries/Win64/ViceCity.exe" } } },
    { id: "astra.gta-trilogy.sanandreas", repo: "mihailinl/astra-gta-trilogy", repo_id: 1427110216, tag_prefix: "v", asset: "astra-gi-sanandreas.zip", target: { game: { appid: "1547000", exe: "Gameface/Binaries/Win64/SanAndreas.exe" } } },
  ],
});

/** src/plan.rs l.269-298 at v0.5.1 (plan.rs has no diff at all from 0.5.0): the names mod loaders hijack-load by (check's `loaders.hijack_names`). */
export const HIJACK_NAMES = Object.freeze([
  "winhttp.dll", "version.dll", "dwmapi.dll", "dxgi.dll", "d3d11.dll", "dinput8.dll",
  "xinput1_1.dll", "xinput1_2.dll", "xinput1_3.dll", "xinput1_4.dll", "xinput9_1_0.dll", "xinputuap.dll",
  "winmm.dll",
  "dinput.dll", "dsound.dll", "d3d8.dll", "d3d9.dll", "d3d10.dll", "d3d12.dll", "ddraw.dll", "msacm32.dll", "msvfw32.dll", "wininet.dll", "xlive.dll",
  "opengl32.dll",
]);

/** check.rs l.90-99: check's steps (byte identical text to 0.5.0's; only its line number moved). */
export const CHECK_STEPS = Object.freeze([
  "the launcher opens the zip and parses its manifest",
  "identity, capabilities, what a community release may place and launch, Astra Link's limits, the foundation claim and the engine descriptor",
  "every file [integration.link] names is in the zip, within its size",
  "the engine descriptor claims none of the spec's negative folders",
  "built on the foundation: every file it places, placed alike",
  "code changed since the previous release",
  "the loader each game file is: none, allowlisted or other",
  "every animation, model, picture and sound is one declared part, whole, with a licence the VRM gate allows",
]);

/** compat.rs l.76-83: compat's steps (compat.rs has no diff at all from 0.5.0). */
export const COMPAT_STEPS = Object.freeze([
  "launcher 0.3.1 opens the zip and parses its manifest",
  "Astra 0.2.7's check_manifest, and pick's tag and asset rule, for the source",
  "0.3.1 plans the same with and without the [integration.*] tables",
  "0.3.1 installs, then prepares a launch with exactly {bridge_port, bridge_token}",
  "the files under every `**` are the previous release's, or named in the notes",
  "the consent sheet's inputs are the previous release's",
]);

/** descriptor.rs l.65-93: the spec's negative folders (`negative_folders[].folder`); unchanged from 0.5.0. */
export const NEGATIVE_FOLDERS = Object.freeze(["empty", "exe-only", "system-dlls", "steam-api-beside-exe"]);

/** main.rs l.295-317: the report's top-level keys in reading order; others follow sorted, `findings` last. */
export const KEY_ORDER = Object.freeze([
  "schema", "tool", "subcommand", "verdict", "error", "input", "source", "against", "spec", "integration",
  "descriptor", "negative_folders", "corpus", "recording", "link", "built_on", "code_changed", "release",
  "fallback", "steps", "notices",
]);
