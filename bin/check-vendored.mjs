#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Canary K9 (and K12's schema half): the vendored files equal the pinned
// commit, and upstream has not changed them since.
//
//   node bin/check-vendored.mjs --upstream astra-registry --checkout <clone> [--upstream-ref origin/main]
//   node bin/check-vendored.mjs --upstream astraplugins --checkout <clone>
//   node bin/check-vendored.mjs --vendor astra-registry --checkout <clone>   (re-vendor at the pin)

import { checkVendored, PINS, vendorFrom } from "../lib/vendored.mjs";

const args = process.argv.slice(2);
const opt = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : null;
};

const vendor = opt("--vendor");
const checkout = opt("--checkout");
if (vendor) {
  if (!PINS[vendor] || !checkout) {
    console.error("usage: --vendor <upstream> --checkout <clone>");
    process.exit(2);
  }
  vendorFrom(vendor, checkout);
  console.log(`vendored ${PINS[vendor].files.length} files from ${PINS[vendor].repo}@${PINS[vendor].sha}`);
  process.exit(0);
}

const upstreams = opt("--upstream") ? [opt("--upstream")] : Object.keys(PINS);
let bad = 0;
for (const upstream of upstreams) {
  const problems = checkVendored({ upstream, checkout, upstreamRef: opt("--upstream-ref") });
  for (const p of problems) console.error(`FAIL  ${p}`);
  if (!problems.length) console.log(`ok    ${upstream} equals ${PINS[upstream].repo}@${PINS[upstream].sha}${checkout ? "" : " (headers only)"}`);
  bad += problems.length;
}
process.exit(bad ? 1 : 0);
