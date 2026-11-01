#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Generate one games kind key. Run by the operator, never in CI.
//
//   node bin/keygen.mjs --role current --key-id astra-games-2026a \
//     --out /mnt/Storage/Minice/Keys/astra-games-2026a.ed25519
//
// Writes the base64 of the raw 32-byte Ed25519 seed to --out with mode 0600,
// refuses to overwrite, and prints ONLY the public half, as the `kind_keys`
// row the root ceremony adds to trust.json (minice docs/architecture/
// 2026-11-01-content-catalogue.md §5). The seed is never printed. Load the
// current key into the signing environment with
//   gh secret set GAMES_SIGNING_KEY_CURRENT --env publish-games < <file>
// and, for a rotation, the next key as GAMES_SIGNING_KEY_NEXT.

import crypto from "node:crypto";
import fs from "node:fs";

const args = process.argv.slice(2);
const opt = (n) => (args.indexOf(n) >= 0 ? args[args.indexOf(n) + 1] : null);
const out = opt("--out");
const role = opt("--role");
const keyId = opt("--key-id");
const notBefore = opt("--not-before") ?? `${new Date().toISOString().slice(0, 19)}Z`;
if (!out || !["current", "next"].includes(role) || !/^astra-games-[0-9]{4}[a-z]$/.test(String(keyId))) {
  console.error("usage: bin/keygen.mjs --role current|next --key-id astra-games-<year><letter> --out <file> [--not-before <RFC 3339>]");
  process.exit(2);
}
const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
const fd = fs.openSync(out, "wx", 0o600); // wx: fail if it exists
fs.writeSync(fd, `${seed.toString("base64")}\n`);
fs.closeSync(fd);
fs.chmodSync(out, 0o600);
console.log(JSON.stringify({ kind: "games", role, key_id: keyId, alg: "ed25519", public_key: pub, not_before: notBefore }));
