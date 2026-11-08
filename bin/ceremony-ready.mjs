#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Run by the operator BEFORE a games trust.json N+1 that promotes `next` to
// `current` is published: is every served games document one that verifies
// under the live trust.json N and under N+1? (lib/ceremony.mjs says why, and
// what the three conditions are.) It reads only public data and holds no
// secret.
//
// Exit 0: every document passes, one line each naming the keys that verified
// it under each trust.json. Exit 1: a document, trust.json N or N+1 fails;
// the line names the host, the schema and the condition. Exit 2: something
// could not be fetched or read, so nothing was judged. That is never a pass.

import fs from "node:fs";
import { pathToFileURL } from "node:url";

import {
  candidateKindKeys, ceremonyReport, HOSTS, parseStrict, promotionProblems, reportLine, SERVED, TRUST_PATH, trustBody, trustBodyDigests,
} from "../lib/ceremony.mjs";
import { INDEX_SCHEMA, WITHDRAWN_SCHEMA } from "../lib/documents.mjs";
import { loadTrust } from "../lib/trust.mjs";
import { jcs } from "../lib/vendor/astra-registry/tools/lib/canonical.mjs";
import { TRUST_SCHEMA } from "../lib/vendor/astra-registry/bot/lib/sign.mjs";

const hostNames = HOSTS.map((h) => new URL(h).host).join(" and ");

export const HELP = `usage: node bin/ceremony-ready.mjs --next-trust <path> [--trust <path or URL>] [--doc <path>]...

Checks that trust.json N+1, a ceremony that promotes the games \`next\` key to
\`current\`, may be published. N+1 must be exactly that promotion: its current
is N's next (same key, same id), and N's current is gone. Then every games
document (astra.games.index/1 and astra.games.withdrawn/1, from every source)
must

  (a) pass under the live trust.json N: within the client's byte cap, no
      repeated member, every body check a verifier makes (schema, serial,
      span, issued_at ahead, the index's own invariants), not expired, and
      the body's key_id naming a role held by one of the keys that verify it,
      each counted only from its not_before;
  (b) do the same under N+1;
  (c) be verified under N+1 by N+1's current key, and under N and N+1 by
      some key other than N's current, so a client that already retired N's
      current for that schema still accepts it.

  --next-trust  the CANDIDATE trust.json N+1 (envelope or bare body). It
                need not be root-signed yet: when it carries signatures they
                must verify under the compiled root keys; when it carries none
                this says so, and prints the sha256 of the body's JCS and the
                signing digest, so the owner signs the bytes that were checked.
  --trust       the live trust.json N, a path or a URL. Default: fetched from
                ${HOSTS.map((h) => `${h}${TRUST_PATH}`).join("\n                and ")},
                which must serve the same document. Verified under the
                compiled root keys, as the signer verifies it.
  --doc         check local files instead of what is served (repeatable):
                exactly one index and one withdrawn list, told apart by their
                schema member. A --doc run says nothing about what
                ${hostNames} serve.

By default both documents are fetched from both hosts:
${HOSTS.flatMap((h) => SERVED.map((s) => `  ${h}${s.path}`)).join("\n")}

Needs python3 (the body checks run the pinned schemas through schemalite).
Exit 0: everything passes (one line per document, naming the keys that
verified it under each trust.json). Exit 1: a document, trust.json N or N+1
fails, named by host, schema and condition. Exit 2: a fetch or a read failed,
so nothing was judged; that is never a pass. Reads only public data.`;

const FETCH_TIMEOUT_MS = 30_000;

class Unreadable extends Error {}

function parseArgs(argv) {
  const o = { trust: null, nextTrust: null, docs: [], help: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--help" || a === "-h") {
      o.help = true;
      continue;
    }
    const value = () => {
      const v = argv[i + 1];
      if (v === undefined || v.startsWith("--")) throw new Error(`${a} needs a value`);
      i += 1;
      return v;
    };
    if (a === "--trust") o.trust = value();
    else if (a === "--next-trust") o.nextTrust = value();
    else if (a === "--doc") o.docs.push(value());
    else throw new Error(`unknown argument ${a}`);
  }
  if (!o.help && !o.nextTrust) throw new Error("--next-trust is required");
  return o;
}

const isUrl = (s) => /^https?:\/\//.test(s);

async function fetchBytes(url, fetchImpl) {
  let res;
  try {
    res = await fetchImpl(url, { redirect: "follow", signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  } catch (e) {
    throw new Unreadable(`${url}: ${e?.cause?.code ?? e?.message ?? e}`);
  }
  if (!res.ok) throw new Unreadable(`${url}: HTTP ${res.status}`);
  try {
    return Buffer.from(await res.arrayBuffer());
  } catch (e) {
    throw new Unreadable(`${url}: ${e?.message ?? e}`);
  }
}

function readBytes(file) {
  try {
    return fs.readFileSync(file);
  } catch (e) {
    throw new Unreadable(`${file}: ${e?.code ?? e?.message ?? e}`);
  }
}

/** Bytes → {doc, problems}; bytes that are not UTF-8 JSON at all are unreadable, not a verdict. */
function parsed(raw, where, opts) {
  try {
    return parseStrict(raw, opts);
  } catch (e) {
    throw new Unreadable(`${where}: not JSON (${e.message})`);
  }
}

/**
 * The command, callable from the tests. `roots` is the tests' seam for
 * throwaway root keys; the command line has no way to pass one, so an
 * operator's run always verifies under the compiled roots.
 *
 * @returns {Promise<number>} the exit code
 */
export async function main(argv, { fetchImpl = globalThis.fetch, roots, now = Math.floor(Date.now() / 1000), out = (l) => process.stdout.write(`${l}\n`), err = (l) => process.stderr.write(`${l}\n`) } = {}) {
  let o;
  try {
    o = parseArgs(argv);
  } catch (e) {
    err(`ceremony-ready: ${e.message}`);
    err(HELP.split("\n")[0]);
    return 2;
  }
  if (o.help) {
    out(HELP);
    return 0;
  }
  const local = o.docs.length > 0;

  // ── read everything first: any failure here is exit 2, before a verdict ──
  const trusts = []; // trust.json N, from each place it was read
  let next;
  const docs = [];
  try {
    if (o.trust) trusts.push({ where: o.trust, ...parsed(isUrl(o.trust) ? await fetchBytes(o.trust, fetchImpl) : readBytes(o.trust), o.trust, { cap: null }) });
    else for (const h of HOSTS) trusts.push({ where: `${h}${TRUST_PATH}`, ...parsed(await fetchBytes(`${h}${TRUST_PATH}`, fetchImpl), `${h}${TRUST_PATH}`, { cap: null }) });
    next = { where: o.nextTrust, ...parsed(readBytes(o.nextTrust), o.nextTrust, { cap: null }) };
    if (local) {
      for (const file of o.docs) docs.push({ source: `local:${file}`, file, ...parsed(readBytes(file), file) });
    } else {
      for (const h of HOSTS) {
        for (const s of SERVED) docs.push({ source: new URL(h).host, domain: s.domain, ...parsed(await fetchBytes(`${h}${s.path}`, fetchImpl), `${h}${s.path}`) });
      }
    }
  } catch (e) {
    if (!(e instanceof Unreadable)) throw e;
    err(`ceremony-ready: could not read ${e.message}. Nothing was judged, and that is not a pass.`);
    return 2;
  }

  // ── trust.json N: one document wherever it is served, root-verified ──
  for (const t of trusts) {
    if (t.problems.length) {
      err(`FAIL trust.json N (${t.where}): ${t.problems.join("; ")}`);
      return 1;
    }
  }
  if (trusts.length > 1 && new Set(trusts.map((t) => jcs(t.doc))).size > 1) {
    err(`FAIL trust.json N: ${trusts.map((t) => `${t.where} serves serial ${trustBody(t.doc)?.serial}`).join(", ")}; the hosts must serve the same trust.json before a ceremony`);
    return 1;
  }
  let trustN;
  try {
    trustN = loadTrust({ doc: trusts[0].doc, now, ...(roots ? { roots } : {}) });
  } catch (e) {
    err(`FAIL trust.json N (${trusts.map((t) => t.where).join(", ")}): ${e.message}`);
    return 1;
  }

  // ── trust.json N+1: the promotion, root-signed or about to be ──
  let trustN1;
  try {
    if (next.problems.length) throw new Error(next.problems.join("; "));
    if (trustBody(next.doc)?.schema !== TRUST_SCHEMA) throw new Error(`its schema is ${JSON.stringify(trustBody(next.doc)?.schema)}, not ${TRUST_SCHEMA}`);
    trustN1 = candidateKindKeys(next.doc);
  } catch (e) {
    err(`FAIL trust.json N+1 (${o.nextTrust}): ${e.message}`);
    return 1;
  }
  const signatures = next.doc?.signatures;
  let signedNote;
  if (Array.isArray(signatures) && signatures.length) {
    try {
      signedNote = `root-signed (${loadTrust({ doc: next.doc, now, ...(roots ? { roots } : {}) }).signedBy})`;
    } catch (e) {
      err(`FAIL trust.json N+1 (${o.nextTrust}): it carries signatures, and they do not hold: ${e.message}`);
      return 1;
    }
  } else signedNote = "NOT root-signed yet";
  const promotion = promotionProblems(trustN.kindKeys, trustN1);
  if (promotion.length) {
    for (const p of promotion) err(`FAIL trust.json N+1 (${o.nextTrust}): ${p}`);
    return 1;
  }
  const digests = trustBodyDigests(next.doc);
  const serialN1 = trustBody(next.doc)?.serial ?? "?";
  out(`trust.json N: serial ${trustN.serial}, root-verified (${trustN.signedBy}), read from ${trusts.map((t) => t.where).join(" and ")}; games current ${trustN.kindKeys.current.key_id}, next ${trustN.kindKeys.next.key_id}`);
  out(`trust.json N+1: serial ${serialN1}, ${signedNote}; games current ${trustN1.current.key_id}, next ${trustN1.next.key_id}`);
  out(`trust.json N+1 body: sha256(JCS(signed)) ${digests.jcs_sha256}; signing digest sha256("${TRUST_SCHEMA}" 0x00 JCS(signed)) ${digests.signing_digest}`);
  if (signedNote.startsWith("NOT")) err(`warning: trust.json N+1 carries no root signature. The owner must sign exactly the body whose JCS sha256 is ${digests.jcs_sha256}.`);
  if (local) out(`source: local files, NOT what is served. This run says nothing about what ${hostNames} serve.`);

  // ── the documents: both schemas from every source ──
  let failed = 0;
  if (local) {
    for (const d of docs) {
      const claimed = d.doc?.signed?.schema;
      d.domain = [INDEX_SCHEMA, WITHDRAWN_SCHEMA].includes(claimed) ? claimed : null;
      if (!d.domain) {
        failed += 1;
        out(`FAIL ${d.source}: its schema member ${JSON.stringify(claimed)} names neither ${INDEX_SCHEMA} nor ${WITHDRAWN_SCHEMA}`);
      }
    }
    for (const schema of [INDEX_SCHEMA, WITHDRAWN_SCHEMA]) {
      const n = docs.filter((d) => d.domain === schema).length;
      if (n !== 1) {
        failed += 1;
        out(`FAIL local files ${schema}: ${n} of the --doc files ${n === 1 ? "is" : "are"} one; pass exactly one index and one withdrawn list`);
      }
    }
  }
  const judged = ceremonyReport(docs.filter((d) => d.domain).map((d) => ({ source: d.source, domain: d.domain, envelope: d.doc, problems: d.problems })), { trustN: trustN.kindKeys, trustN1, now });
  for (const d of judged) {
    if (!d.result.ok) failed += 1;
    out(reportLine(d.source, d.domain, d.result, { serialN: trustN.serial, serialN1 }));
  }
  if (failed) {
    err(`not ready: ${failed} check(s) fail. Do not publish trust.json N+1.`);
    return 1;
  }
  out(local
    ? `ready (local files only, NOT what is served): both documents verify under trust.json N and N+1.`
    : `ready: all ${judged.length} documents served by ${hostNames} verify under trust.json N and N+1.`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1])).href) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      console.error(`ceremony-ready: ${e?.stack ?? e}`);
      process.exit(2);
    },
  );
}
