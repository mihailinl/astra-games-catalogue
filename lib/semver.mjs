// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The semver this catalogue needs, and no more: a withdrawal row's
// `versions` is a range (games-withdrawn-v1.md §2.1), and the catalogue must
// know which listed releases a row covers to build the cascade and the
// takedown count. A range this parser does not understand is REFUSED by the
// act validator rather than guessed at — a takedown that silently matched
// nothing is the failure to avoid.
//
// Grammar: `*` | a disjunction `A || B`, each a space-separated conjunction of
// comparators `[<|<=|>|>=|=]X.Y.Z[-pre]`. No `^`, `~`, `x` ranges or hyphen
// ranges.

const VERSION_RE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

export function parseVersion(v) {
  const m = VERSION_RE.exec(String(v));
  if (!m) return null;
  return { major: +m[1], minor: +m[2], patch: +m[3], pre: m[4] ? m[4].split(".") : [] };
}

export function isVersion(v) {
  return parseVersion(v) !== null;
}

function cmpIdent(a, b) {
  const an = /^\d+$/.test(a);
  const bn = /^\d+$/.test(b);
  if (an && bn) return Math.sign(Number(a) - Number(b));
  if (an) return -1;
  if (bn) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

export function compare(a, b) {
  const x = typeof a === "string" ? parseVersion(a) : a;
  const y = typeof b === "string" ? parseVersion(b) : b;
  if (!x || !y) throw new Error(`not a version: ${!x ? a : b}`);
  for (const k of ["major", "minor", "patch"]) if (x[k] !== y[k]) return Math.sign(x[k] - y[k]);
  if (!x.pre.length && !y.pre.length) return 0;
  if (!x.pre.length) return 1;
  if (!y.pre.length) return -1;
  for (let i = 0; i < Math.max(x.pre.length, y.pre.length); i++) {
    if (i >= x.pre.length) return -1;
    if (i >= y.pre.length) return 1;
    const c = cmpIdent(x.pre[i], y.pre[i]);
    if (c) return c;
  }
  return 0;
}

const COMPARATOR_RE = /^(<=|>=|<|>|=)?(.+)$/;

/** @returns {null | ((v: string) => boolean)} null when the range is not in the grammar above */
export function parseRange(range) {
  const r = String(range).trim();
  if (r === "*") return () => true;
  if (!r) return null;
  const alternatives = [];
  for (const alt of r.split("||")) {
    const parts = alt.trim().split(/\s+/).filter(Boolean);
    if (!parts.length) return null;
    const tests = [];
    for (const p of parts) {
      const m = COMPARATOR_RE.exec(p);
      const op = m[1] ?? "=";
      const v = parseVersion(m[2]);
      if (!v) return null;
      tests.push((x) => {
        const c = compare(x, v);
        return op === "=" ? c === 0 : op === "<" ? c < 0 : op === "<=" ? c <= 0 : op === ">" ? c > 0 : c >= 0;
      });
    }
    alternatives.push((x) => tests.every((t) => t(x)));
  }
  return (v) => {
    const x = parseVersion(v);
    return x !== null && alternatives.some((a) => a(x));
  };
}

export function satisfies(version, range) {
  const test = parseRange(range);
  if (!test) throw new Error(`not a range this catalogue understands: ${range}`);
  return test(version);
}

/** An exact disjunction of versions, the form the cascade writes. */
export function exactRange(versions) {
  return [...new Set(versions)].sort(compare).join(" || ");
}
