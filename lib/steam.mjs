// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// The game behind a game-specific entry (A§5.2 step 6; merged §2.4).
//
// Ingest asks Steam's public store API whether the appid exists and what
// Steam itself discloses about it:
//
//   category 8          Valve Anti-Cheat enabled            → refused (VAC)
//   category 49 / 36    PvP / Online PvP                    → moderator flag
//   category 20         MMO                                 → moderator flag
//   genre 29            Massively Multiplayer               → moderator flag
//
// The online flag never refuses here: a game-specific entry for an online
// game is allowed, never "Recommended" (games-index-v1.md §2.5), and the
// engine-wide offer filter is the client's (merged §2.4, R26). Anti-cheat
// beyond VAC — kernel services, extended folder signatures, appinfo's own
// disclosure — is checked on the player's machine against the real folder,
// where the evidence is; the manifest's `anti_cheat` must say "none" here.

export const VAC_CATEGORY = 8;
export const ONLINE_CATEGORIES = Object.freeze({ 49: "PvP", 36: "Online PvP", 20: "MMO" });
export const ONLINE_GENRES = Object.freeze({ 29: "Massively Multiplayer" });

export class SteamUnanswered extends Error {
  constructor(message) {
    super(message);
    this.name = "SteamUnanswered";
  }
}

/** The production reader. Throws SteamUnanswered for anything that is not an answer. */
export function storeApi({ fetchImpl = fetch } = {}) {
  return {
    async appDetails(appid) {
      const url = `https://store.steampowered.com/api/appdetails?appids=${Number(appid)}&l=english`;
      let res;
      try {
        res = await fetchImpl(url, { headers: { "User-Agent": "astra-games-catalogue" } });
      } catch (e) {
        throw new SteamUnanswered(`Steam did not answer ${url}: ${e.message}`);
      }
      if (!res.ok) throw new SteamUnanswered(`Steam answered HTTP ${res.status} for ${url}`);
      let body;
      try {
        body = await res.json();
      } catch (e) {
        throw new SteamUnanswered(`Steam's answer for ${url} is not JSON`);
      }
      const row = body?.[String(Number(appid))];
      if (!row || typeof row.success !== "boolean") throw new SteamUnanswered(`Steam's answer has no row for ${appid}`);
      return row.success ? row.data : null;
    },
  };
}

/**
 * @param {object|null} data appdetails' `data`, or null for "no such app"
 * @returns {{exists: boolean, vac: boolean, online: string[], name: string|null}}
 */
export function readSignals(data) {
  if (!data) return { exists: false, vac: false, online: [], name: null };
  const cats = new Set((data.categories ?? []).map((c) => Number(c.id)));
  const genres = new Set((data.genres ?? []).map((g) => Number(g.id)));
  const online = [
    ...Object.entries(ONLINE_CATEGORIES).filter(([id]) => cats.has(Number(id))).map(([, n]) => n),
    ...Object.entries(ONLINE_GENRES).filter(([id]) => genres.has(Number(id))).map(([, n]) => n),
  ];
  return { exists: true, vac: cats.has(VAC_CATEGORY), online, name: typeof data.name === "string" ? data.name : null };
}
