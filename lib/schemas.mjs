// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Validation against AstraPlugins' S schemas, through AstraPlugins' own
// tools/schemalite.py (vendored at a pin, lib/vendored.mjs). This module
// never interprets a schema keyword; it hands documents to Python and reads
// back the verdicts, one process per batch.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { ROOT, VENDOR } from "./vendored.mjs";

const BRIDGE = path.join(ROOT, "lib", "schemacheck.py");
const PYTHON = process.env.PYTHON ?? "python3";

/**
 * @param {{schema: "games-index-v1"|"games-withdrawn-v1"|"manifest"|"engine-descriptor-v1", doc: unknown}[]} items
 * @returns {{ok: boolean, error: string}[]}
 */
export function validateMany(items) {
  if (items.length === 0) return [];
  const out = execFileSync(PYTHON, [BRIDGE, "validate"], {
    input: JSON.stringify({ items }),
    maxBuffer: 256 * 1024 * 1024,
  });
  const { results } = JSON.parse(out.toString("utf8"));
  if (!Array.isArray(results) || results.length !== items.length) {
    throw new Error("schemacheck.py answered a different number of results than it was asked");
  }
  return results;
}

export function validateOne(schema, doc) {
  return validateMany([{ schema, doc }])[0];
}

/**
 * One entry against games-index-v1.schema.json's `entry`: the entry inside a
 * minimal index document, so the schema is used exactly as published and no
 * sub-schema is carved out of it.
 */
export function validateEntries(entries) {
  return validateMany(entries.map((entry) => ({
    schema: "games-index-v1",
    doc: { schema: "astra.games.index/1", serial: 0, issued_at: 0, expires_at: 0, key_id: "games-current", entries: [entry], games: [] },
  })));
}

/** astra-gi.toml from a release zip, parsed by tomllib: {ok, manifest, text} (text: the member as shipped). */
export function readManifestFromZip(zipPath) {
  const out = execFileSync(PYTHON, [BRIDGE, "manifest", zipPath], { maxBuffer: 16 * 1024 * 1024 });
  return JSON.parse(out.toString("utf8"));
}

/** A loose TOML file (a golden, a fixture), parsed by tomllib with the same refusals. */
export function readTomlFile(file) {
  const out = execFileSync(PYTHON, [BRIDGE, "toml", file], { maxBuffer: 16 * 1024 * 1024 });
  return JSON.parse(out.toString("utf8"));
}

/**
 * Zip Cloaking: the release zip's local file headers cross-checked
 * against its own central directory (schemacheck.py's `verify_zip_headers`
 * / `zipcheck` command). `contentReport` already runs this first; exported
 * on its own so a test, or a future caller that needs it before reading
 * anything else out of the zip, does not have to go through `content`.
 * @param {string} zipPath
 */
export function verifyZipHeaders(zipPath) {
  const out = execFileSync(PYTHON, [BRIDGE, "zipcheck", zipPath], { maxBuffer: 16 * 1024 * 1024 });
  return JSON.parse(out.toString("utf8"));
}

/**
 * The catalogue's own reading of every file in a release zip: path in the
 * zip → SHA-256 of its inflated bytes (schemacheck.py's `files`). What
 * gi-probe 0.5.0 does not report — built_on's and code_changed's file set,
 * the game files' and the Link files' digests — is computed from this.
 * @param {string} zipPath
 * @returns {{ok: true, files: Record<string, string>} | {ok: false, error: string}}
 */
export function zipFiles(zipPath) {
  const out = execFileSync(PYTHON, [BRIDGE, "files", zipPath], { maxBuffer: 64 * 1024 * 1024 });
  return JSON.parse(out.toString("utf8"));
}

/**
 * AstraPlugins manifest.md §2.7's content-coverage check and HARD VRM
 * licence gate, over a release zip's real bytes, through schemacheck.py.
 * @param {string} zipPath
 * @param {object[]} declared the manifest's [[integration.content]] array
 */
export function contentReport(zipPath, declared) {
  const out = execFileSync(PYTHON, [BRIDGE, "content", zipPath], {
    input: JSON.stringify({ declared }),
    maxBuffer: 256 * 1024 * 1024,
  });
  return JSON.parse(out.toString("utf8"));
}

/** A pinned S schema, parsed — for the questions a schema answers about itself (which members exist). */
export function loadSchema(name) {
  const file = path.join(VENDOR, "astraplugins", "spec/games/schemas", `${name}.schema.json`);
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

/**
 * The reserved list (spec/games/reserved.yaml), read the way
 * check-games-goldens.py reads it: one flat level of `key:` then `- item`.
 */
export function loadReserved() {
  const file = path.join(VENDOR, "astraplugins", "spec/games/reserved.yaml");
  const out = {
    engine_codes: [],
    integration_id_reserved_prefixes: [],
    integration_name_reserved_substrings: [],
    profile_file_names: [],
  };
  let current = null;
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const key = /^(\w+):\s*(.*)$/.exec(line);
    if (key && !line.startsWith(" ")) {
      current = key[1];
      continue;
    }
    const item = /^\s*-\s*"?([^"\n]+?)"?\s*(#.*)?$/.exec(line);
    if (item && current in out) out[current].push(item[1]);
  }
  return out;
}
