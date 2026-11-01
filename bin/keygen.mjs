#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Generate one games signing key (A§5.4). Run by the operator, never in CI.
//
//   node bin/keygen.mjs --key-id games-current --out /mnt/Storage/Minice/Keys/games-current.ed25519
//
// Writes the base64 of the raw 32-byte Ed25519 seed to --out with mode 0600,
// refuses to overwrite, and prints ONLY the public half as the keys.json row.
// The seed is never printed. Load "current" into the signing environment
// with `gh secret set GAMES_SIGNING_KEY_CURRENT --env games-signing < <file>`;
// "next" stays offline until the ratchet.

import crypto from "node:crypto";
import fs from "node:fs";

const args = process.argv.slice(2);
const opt = (n) => (args.indexOf(n) >= 0 ? args[args.indexOf(n) + 1] : null);
const out = opt("--out");
const keyId = opt("--key-id");
if (!out || !["games-current", "games-next"].includes(keyId)) {
  console.error("usage: bin/keygen.mjs --key-id games-current|games-next --out <file>");
  process.exit(2);
}
const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
const fd = fs.openSync(out, "wx", 0o600); // wx: fail if it exists
fs.writeSync(fd, `${seed.toString("base64")}\n`);
fs.closeSync(fd);
fs.chmodSync(out, 0o600);
console.log(JSON.stringify({ key_id: keyId, public_key: pub }));
