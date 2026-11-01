#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// Tell the plugins service that new documents are on the `data` branch
// (A§5.5: "the rest is the existing pipeline"). The service fetches and
// verifies them itself; this request only wakes it, so it carries nothing a
// forger could use: the issued_at, the key id and the data commit, under a
// GitHub OIDC token whose audience the service pins.
//
//   GAMES_NOTIFY_URL, GAMES_NOTIFY_AUDIENCE   repository variables (not secrets)
//   ISSUED_AT, KEY_ID, DATA_SHA                this run's own outputs
//
// With no URL configured it does nothing: serving can poll instead.

const url = process.env.GAMES_NOTIFY_URL;
if (!url) {
  console.log("GAMES_NOTIFY_URL is not set; the plugins service polls the data branch");
  process.exit(0);
}
try {
  if (!url.startsWith("https://")) throw new Error("GAMES_NOTIFY_URL is not https");
  const reqUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const reqToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!reqUrl || !reqToken) throw new Error("no OIDC token request in this job (permissions: id-token: write)");
  const aud = encodeURIComponent(process.env.GAMES_NOTIFY_AUDIENCE ?? "https://api.minice.ai/plugins/v1/games");
  const t = await fetch(`${reqUrl}&audience=${aud}`, { headers: { Authorization: `Bearer ${reqToken}` } });
  if (!t.ok) throw new Error(`OIDC token request answered HTTP ${t.status}`);
  const { value } = await t.json();
  const body = { schema: "astra.games.notify/1", issued_at: Number(process.env.ISSUED_AT), key_id: process.env.KEY_ID, data_sha: process.env.DATA_SHA };
  const res = await fetch(url, { method: "POST", headers: { Authorization: `Bearer ${value}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });
  console.log(`notified: HTTP ${res.status}`);
  // a failed wake is not a failed signing: the service also polls
} catch (e) {
  console.error(`notify skipped: ${e.message}`);
}
