// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// AstraPlugins manifest.md §2.7 / dev/game-integrations-plan-merged.md §5.4:
// an integration's own non-built-in animations, models, art and audio.
//
// Ingest order (manifest.md §2.7.1): provenance -> manifest schema ->
// CONTENT CHECK -> gi-probe. This runs after the manifest has parsed and
// schema-validated but before gi-probe, because gi-probe's report is about
// the GI's code, and a release whose content declarations do not match its
// own zip is refused before that code is even inspected.
//
// The heavy lifting (walking the zip, extension+magic classification, the
// GLB-chunk/VRM-meta parse) is schemacheck.py's `content` command -- the one
// place beyond astra-gi.toml itself that this repository reads zip bytes,
// reusing Python's battle-tested zipfile instead of a hand-rolled reader.
// This module turns that report into findings and the games-index-v1
// content[] shape.

import { CODES, finding } from "./codes.mjs";
import { contentReport } from "./schemas.mjs";

/** contentlite.py's path_refusal (part-digest-v1.md §2): a C0, DEL or C1
 * control character in a zip entry name. Mirrored here (see checkContent's
 * E_ARCHIVE_NAME_UNSAFE check) because content_report never runs it over
 * the top-level release zip's own entries. */
const UNSAFE_PATH_CHAR = /[\x00-\x1f\x7f-\x9f]/;

/**
 * @param {{zipPath: string, manifest: object}} o
 * @returns {{findings: object[], content: object[]}} `content` is the
 *   games-index-v1 `content[]` shape (manifest.md §2.7.4), built only from
 *   declared parts that are present and not licence-refused. A refused part
 *   is never listed; a verdict carrying E_CONTENT_LICENCE_REFUSED is
 *   `refuse` regardless (codes.mjs classOf), so the candidate is never
 *   built from this `content` anyway -- this filtering is defensive, not
 *   load-bearing.
 */
export function checkContent({ zipPath, manifest }) {
  const declaredRaw = manifest?.integration?.content;
  const declared = Array.isArray(declaredRaw) ? declaredRaw : [];
  const findings = [];

  const report = contentReport(zipPath, declared);
  if (!report.ok) {
    // Zip Cloaking (schemacheck.py's verify_zip_headers, run first inside
    // content_report) gets its own code; every other "not a readable
    // zip" failure here is still a content-check-shaped problem.
    const code = report.error.startsWith("E_ZIP_HEADERS_INCONSISTENT:") ? CODES.E_ZIP_HEADERS_INCONSISTENT : CODES.E_CONTENT_MISSING;
    findings.push(finding(code, `content: ${report.error}`));
    return { findings, content: [] };
  }

  for (const path of report.undeclared) {
    findings.push(finding(
      CODES.E_CONTENT_UNDECLARED,
      `content: "${path}" is a content-typed file (by extension and magic bytes) with no [[integration.content]] entry (manifest.md §2.7.2)`,
      { path },
    ));
  }
  for (const path of report.missing) {
    findings.push(finding(
      CODES.E_CONTENT_MISSING,
      `content: [[integration.content]] declares "${path}", and no content-typed file is at that path (manifest.md §2.7.2)`,
      { path },
    ));
  }
  for (const path of report.duplicates) {
    findings.push(finding(
      CODES.E_CONTENT_DUPLICATE,
      `content: "${path}" is covered by more than one [[integration.content]] entry (manifest.md §2.7.2)`,
      { path },
    ));
  }
  for (const r of report.licence_refusals) {
    findings.push(finding(
      CODES.E_CONTENT_LICENCE_REFUSED,
      `content: ${r.path}'s VRM licence refuses redistribution (${r.field} = ${JSON.stringify(r.value)}, manifest.md §2.7.3)`,
      { path: r.path, field: r.field },
    ));
  }
  // O-2: a VRM carrying both a 0.x and a 1.0 meta that disagree is refused
  // outright -- never "whichever meta parsed first wins" (manifest.md
  // §2.7.3 at AstraPlugins 516ba38; the content contract's ingest-v1.md §4.2).
  for (const r of report.licence_conflicts ?? []) {
    findings.push(finding(
      CODES.E_CONTENT_LICENCE_CONFLICT,
      `content: ${r.path} carries a VRM 0.x and a VRM 1.0 licence that disagree (${r.field}: ${r.detail}); ship one licence, the same in both metas (manifest.md §2.7.3)`,
      { path: r.path, field: r.field },
    ));
  }
  // AstraPlugins 4976d60: every GLB (by magic) and every .gltf, in any part
  // and of any class, is held to the content catalogue's format rules
  // BEFORE classification -- a duplicate JSON member, a chunk declared past
  // EOF, or an external image/buffer uri must never fall through to a
  // lenient parse that reads the file as "plain" (manifest.md §2.7.3).
  // AstraPlugins #129: on EVERY file, declared or not -- a GLB, text glTF or
  // bundle under another name (§2.7.1), a % ? # or \ in a uri, the 16 MiB /
  // depth-128 caps, a BOM on a .gltf; and the release's 32 MiB glTF JSON
  // budget, which has no one path ("").
  for (const r of report.format_refusals ?? []) {
    findings.push(finding(
      CODES.E_CONTENT_FORMAT,
      r.path
        ? `content: ${r.path} fails the content format rules (${r.detail}, manifest.md §2.7.1/§2.7.3)`
        : `content: the release fails the content format rules (${r.detail}, manifest.md §2.7.3)`,
      { path: r.path },
    ));
  }
  // AstraPlugins #129: an embedded .astrachar/.astrapack refused by the
  // content contract's own ingest_bundle keeps that contract's code; the
  // detail is content's, as "<gi path>!<inner path>: ..." (manifest.md §2.7.3).
  // A code this registry does not know is still a refusal, as E_CONTENT_FORMAT.
  for (const r of report.bundle_refusals ?? []) {
    findings.push(finding(
      CODES[r.code] ?? CODES.E_CONTENT_FORMAT,
      `content: ${r.path} is refused by the content contract's own bundle check (${r.code}: ${r.detail}, manifest.md §2.7.3)`,
      { path: r.path, content_code: r.code, detail: r.detail },
    ));
  }
  // legal DRAFT-v3.md Part 6 G4: "unknown" (no VRM meta at all) is a flag,
  // never a refusal -- it only becomes a problem if §2.7.3's declared-
  // licence fallback (below) also has nothing to fall back to.
  for (const path of report.licence_unknown ?? []) {
    findings.push(finding(
      CODES.F_CONTENT_VRM_META_UNKNOWN,
      `content: ${path} has no readable licence meta at all, or carries a licence or permission token Astra does not recognise (manifest.md §2.7.3) -- shown with the character checkbox and its declared licence`,
      { path },
    ));
  }
  // AstraPlugins #146 (53ab739, G5/W1): a pack part inside an embedded bundle
  // whose rights come from a declared licence, never VRM meta -- a
  // DIFFERENT flag from F_CONTENT_VRM_META_UNKNOWN above but the SAME
  // consequence (never a refusal, held for a moderator). The same bundle can
  // carry both flags at once (manifest.md §2.7.3, golden bundle-two-flags) --
  // this loop is independent of the one above, never an alternative to it.
  for (const path of report.licence_declared ?? []) {
    findings.push(finding(
      CODES.F_CONTENT_LICENCE_DECLARED,
      `content: ${path} is a pack part inside an embedded bundle whose rights come from its declared licence, never VRM meta (manifest.md §2.7.3) -- held for a moderator`,
      { path },
    ));
  }
  // G5: every covered part needs a licence from somewhere -- a readable
  // VRM licence, or the manifest's own declared one.
  for (const path of report.licence_undeclared ?? []) {
    findings.push(finding(
      CODES.E_CONTENT_LICENCE_UNDECLARED,
      `content: ${path} has no readable VRM licence and [[integration.content]] declares no "licence" for it either (manifest.md §2.7.3)`,
      { path },
    ));
  }
  // AstraPlugins #129 f3e2bd0: a game's own archive, opened one level deep by
  // the content contract's walk_zip. Cloaking refuses with content's code; an
  // archive the walk could not otherwise open publishes flagged.
  for (const r of report.archive_refusals ?? []) {
    findings.push(finding(
      CODES[r.code] ?? CODES.E_CONTENT_FORMAT,
      `content: the archive ${r.path} is refused (${r.code}: ${r.detail}); an archive must read the same to every reader (manifest.md §2.7.1)`,
      { path: r.path, content_code: r.code, detail: r.detail },
    ));
  }
  for (const r of report.archives_unscanned ?? []) {
    findings.push(finding(
      CODES.F_CONTENT_ARCHIVE_UNSCANNED,
      `content: the archive ${r.path} was not opened (${r.reason}); a model inside it is not checked (manifest.md §2.7.1)`,
      { path: r.path, reason: r.reason },
    ));
  }
  // Contract 6.14.0 (minice plugins-api/src/games/wire.rs, lib/service.mjs's
  // DISALLOWED_C0): a part's `path` is an IDENTITY -- matched by path and
  // sha256 in confirmed[], and shown to the author -- never prose, so it is
  // never rewritten the way a finding's message or a part's title is.
  // contentlite.py's path_refusal (part-digest-v1.md §2) already refuses an
  // EMBEDDED .astrachar/.astrapack's own entries on exactly this
  // (E_ARCHIVE_NAME_UNSAFE, "control-character"), but schemacheck.py's
  // content_report walks the TOP-LEVEL release zip with Python's zipfile
  // directly and holds an entry only to name_problem's magic/extension
  // agreement, never to path_refusal -- so a declared, present content path
  // with a control character would otherwise reach report.parts (and the
  // wire) unrefused, then violate 6.14.0's rule once the service enforces
  // it. This reuses path_refusal's own "control-character" definition and
  // code, over the paths that would actually become parts[], rather than
  // inventing a new one or scrubbing an identity.
  const unsafePaths = report.parts.filter((p) => UNSAFE_PATH_CHAR.test(p.path)).map((p) => p.path);
  for (const p of unsafePaths) {
    findings.push(finding(
      CODES.E_ARCHIVE_NAME_UNSAFE,
      `content: ${JSON.stringify(p)} carries a control character (part-digest-v1.md §2); a part's path is an identity and is refused, never rewritten`,
      { path: p },
    ));
  }

  const refusedPaths = new Set([
    ...report.licence_refusals,
    ...(report.licence_conflicts ?? []),
    ...(report.format_refusals ?? []),
    ...(report.bundle_refusals ?? []),
  ].map((r) => r.path));
  for (const p of unsafePaths) refusedPaths.add(p);
  const undeclaredPaths = new Set(report.licence_undeclared ?? []);
  const byPath = new Map(declared.filter((e) => e && typeof e.path === "string").map((e) => [e.path, e]));
  const content = report.parts
    .filter((p) => !refusedPaths.has(p.path) && !undeclaredPaths.has(p.path))
    .map((p) => {
      const entry = byPath.get(p.path) ?? {};
      const out = {
        path: p.path,
        kind: String(entry.kind ?? ""),
        title: String(entry.title ?? ""),
        credit: String(entry.credit ?? ""),
        sha256: p.sha256,
        licence_source: p.licence_source,
      };
      // licence is OPTIONAL in games-index-v1's contentPart (minLength 1
      // when present): a "vrm"-sourced part may have nothing declared at
      // all, and an empty string would itself fail that schema.
      if (entry.licence) out.licence = String(entry.licence);
      if (p.vrm_licence) out.vrm_licence = p.vrm_licence;
      return out;
    });

  return { findings, content };
}
