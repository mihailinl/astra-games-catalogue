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
// it under each trust.json. Exit 1: a document, or trust.json N, fails; the
// line names the host, the schema and the condition. Exit 2: something could
// not be fetched or read, so nothing was judged. That is never a pass.

import fs from "node:fs";
import { pathToFileURL } from "node:url";

import { candidateKindKeys, ceremonyChecks, DEFAULT_HOSTS, DEFAULT_TRUST_URL, reportLine, SERVED } from "../lib/ceremony.mjs";
import { INDEX_SCHEMA, WITHDRAWN_SCHEMA } from "../lib/documents.mjs";
import { loadTrust } from "../lib/trust.mjs";

export const HELP = `usage: node bin/ceremony-ready.mjs --next-trust <path> [--trust <path or URL>] [--doc <path>]... [--host <origin>]...

Checks that trust.json N+1 may be published: every served games document
(astra.games.index/1 and astra.games.withdrawn/1) must

  (a) verify under the live trust.json N: every key that verifies is
      collected, the body's key_id names a role one of them holds, each one's
      not_before is met, and it has not expired;
  (b) do the same under N+1;
  (c) be verified under N+1 by N+1's current key, and by some key other than
      N's current, so a client that already retired N's current for that
      schema still accepts it.

  --next-trust  the CANDIDATE trust.json N+1 (envelope or bare body). Only its
                games kind_keys are read. It need not be root-signed yet, and
                its root signature is NOT checked here: the owner signs it after
                this passes.
  --trust       the live trust.json N, a path or a URL; verified under the
                compiled root keys, as the signer verifies it.
                Default: ${DEFAULT_TRUST_URL}
  --doc         check this local file instead of fetching (repeatable); its
                schema member picks which of the two documents it is.
  --host        an origin to fetch the two documents from (repeatable),
                replacing the default ${DEFAULT_HOSTS.join(" and ")}.
                Each serves ${SERVED.map((s) => s.path).join(" and ")}.

Exit 0: every document passes (one line each, naming the keys that verified it
under each trust.json). Exit 1: a document or trust.json N fails, named by
host, schema and condition. Exit 2: a fetch or a read failed, so nothing was
judged; that is never a pass. Reads only public data; needs no secret.`;

const FETCH_TIMEOUT_MS = 30_000;

class Unreadable extends Error {}

function parseArgs(argv) {
  const o = { trust: DEFAULT_TRUST_URL, nextTrust: null, docs: [], hosts: [], help: false };
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
    else if (a === "--host") {
      const host = value().replace(/\/+$/, "");
      if (!isUrl(host) || !URL.canParse(host)) throw new Error(`--host ${host} is not an http(s) origin`);
      o.hosts.push(host);
    }
    else throw new Error(`unknown argument ${a}`);
  }
  if (!o.help && !o.nextTrust) throw new Error("--next-trust is required");
  if (o.docs.length && o.hosts.length) throw new Error("--doc and --host are two different sources; pass one");
  return o;
}

const isUrl = (s) => /^https?:\/\//.test(s);

async function fetchJson(url, fetchImpl) {
  let res;
  try {
    res = await fetchImpl(url, { redirect: "follow", signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  } catch (e) {
    throw new Unreadable(`${url}: ${e?.cause?.code ?? e?.message ?? e}`);
  }
  if (!res.ok) throw new Unreadable(`${url}: HTTP ${res.status}`);
  let text;
  try {
    text = await res.text();
  } catch (e) {
    throw new Unreadable(`${url}: ${e?.message ?? e}`);
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new Unreadable(`${url}: the response is not JSON`);
  }
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    throw new Unreadable(`${file}: ${e?.code ?? e?.message ?? e}`);
  }
}

/**
 * The command, callable from the tests. `roots` is the tests' seam for
 * throwaway root keys; the command line has no way to pass one, so an
 * operator's run always verifies N under the compiled roots.
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

  let trustDoc;
  let nextDoc;
  const docs = [];
  try {
    trustDoc = isUrl(o.trust) ? await fetchJson(o.trust, fetchImpl) : readJson(o.trust);
    nextDoc = readJson(o.nextTrust);
    if (o.docs.length) {
      for (const file of o.docs) docs.push({ source: `local:${file}`, envelope: readJson(file), domain: null });
    } else {
      for (const host of o.hosts.length ? o.hosts : DEFAULT_HOSTS) {
        for (const s of SERVED) docs.push({ source: new URL(host).host, envelope: await fetchJson(`${host}${s.path}`, fetchImpl), domain: s.domain });
      }
    }
  } catch (e) {
    if (!(e instanceof Unreadable)) throw e;
    err(`ceremony-ready: could not read ${e.message}. Nothing was judged, and that is not a pass.`);
    return 2;
  }

  let trustN;
  try {
    trustN = loadTrust({ doc: trustDoc, now, ...(roots ? { roots } : {}) });
  } catch (e) {
    err(`FAIL trust.json N (${o.trust}): ${e.message}`);
    return 1;
  }
  let trustN1;
  try {
    trustN1 = candidateKindKeys(nextDoc);
  } catch (e) {
    err(`FAIL trust.json N+1 (${o.nextTrust}): ${e.message}`);
    return 1;
  }
  const serialN1 = (nextDoc?.signed ?? nextDoc)?.serial ?? "?";
  out(`trust.json N: serial ${trustN.serial}, root-verified (${trustN.signedBy}); games current ${trustN.kindKeys.current.key_id}, next ${trustN.kindKeys.next.key_id}`);
  out(`trust.json N+1: serial ${serialN1}, root signature NOT checked; games current ${trustN1.current.key_id}, next ${trustN1.next.key_id}`);

  let failed = 0;
  for (const d of docs) {
    // a local file says which document it is; a served one is the client's constant for its path
    const claimed = d.envelope?.signed?.schema;
    const domain = d.domain ?? ([INDEX_SCHEMA, WITHDRAWN_SCHEMA].includes(claimed) ? claimed : null);
    if (!domain) {
      failed += 1;
      out(`FAIL ${d.source}: its schema member ${JSON.stringify(claimed)} names neither ${INDEX_SCHEMA} nor ${WITHDRAWN_SCHEMA}`);
      continue;
    }
    const r = ceremonyChecks({ envelope: d.envelope, domain }, { trustN: trustN.kindKeys, trustN1, now });
    if (!r.ok) failed += 1;
    out(reportLine(d.source, domain, r, { serialN: trustN.serial, serialN1 }));
  }
  if (failed) {
    err(`not ready: ${failed} of ${docs.length} document(s) fail. Do not publish trust.json N+1.`);
    return 1;
  }
  out(`ready: all ${docs.length} document(s) verify under trust.json N and N+1.`);
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
