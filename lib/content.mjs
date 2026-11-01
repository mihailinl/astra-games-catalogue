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
    findings.push(finding(CODES.E_CONTENT_MISSING, `content: ${report.error}`));
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
  for (const g of report.gaps) {
    findings.push(finding(
      CODES.F_CONTENT_ASTRACHAR_UNREADABLE,
      `content: ${g.path}'s .astrachar body could not be read for the VRM gate (${g.reason}) -- a gap, not a refusal (manifest.md §2.7.3)`,
      { path: g.path },
    ));
  }

  const refusedPaths = new Set(report.licence_refusals.map((r) => r.path));
  const byPath = new Map(declared.filter((e) => e && typeof e.path === "string").map((e) => [e.path, e]));
  const content = report.parts
    .filter((p) => !refusedPaths.has(p.path))
    .map((p) => {
      const entry = byPath.get(p.path) ?? {};
      const out = {
        path: p.path,
        kind: String(entry.kind ?? ""),
        title: String(entry.title ?? ""),
        credit: String(entry.credit ?? ""),
        licence: String(entry.licence ?? ""),
        sha256: p.sha256,
      };
      if (p.vrm_licence) out.vrm_licence = p.vrm_licence;
      return out;
    });

  return { findings, content };
}
