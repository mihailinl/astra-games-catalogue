// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// K9 and K12's schema half, offline: every vendored file is present and
// carries the header naming its source path and pinned commit. With a local
// clone named in ASTRA_REGISTRY_CHECKOUT / ASTRAPLUGINS_CHECKOUT the bytes are
// compared with the pin and upstream's watched branch too (ci.yml's
// `vendored` job always does this against fresh clones).

import assert from "node:assert/strict";
import fs from "node:fs";
import { test } from "node:test";

import { checkVendored, PINS, vendoredPath } from "../lib/vendored.mjs";

const CHECKOUTS = { "astra-registry": process.env.ASTRA_REGISTRY_CHECKOUT, astraplugins: process.env.ASTRAPLUGINS_CHECKOUT };

for (const upstream of Object.keys(PINS)) {
  test(`${upstream}: every vendored file is present with its header`, () => {
    assert.deepEqual(checkVendored({ upstream }), []);
  });

  test(`${upstream}: the vendored bytes equal ${PINS[upstream].repo}@${PINS[upstream].sha.slice(0, 7)}`, { skip: !CHECKOUTS[upstream] && "no local clone named" }, () => {
    assert.deepEqual(checkVendored({ upstream, checkout: CHECKOUTS[upstream], upstreamRef: `origin/${PINS[upstream].watch}` }), []);
  });
}

test("an edited vendored file is caught", () => {
  const file = vendoredPath("astra-registry", "bot/lib/certificate.mjs");
  const original = fs.readFileSync(file);
  try {
    fs.writeFileSync(file, Buffer.concat([Buffer.from("// local tweak\n"), original]));
    assert.ok(checkVendored({ upstream: "astra-registry" }).some((p) => p.includes("certificate.mjs")));
    if (CHECKOUTS["astra-registry"]) {
      fs.writeFileSync(file, Buffer.concat([original, Buffer.from("\n// local tweak\n")]));
      assert.ok(checkVendored({ upstream: "astra-registry", checkout: CHECKOUTS["astra-registry"] }).some((p) => p.includes("differs")));
    }
  } finally {
    fs.writeFileSync(file, original);
  }
});
