<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 Minice — https://minice.ai
-->

# astra-games-catalogue

The catalogue of **game integrations** for [Astra](https://minice.ai): the
foundations that teach Astra an engine, and the integrations that teach it one
game. This repository turns a GitHub release into a catalogue entry and signs
the two documents every Astra client reads:

| document | what it says | spec |
|---|---|---|
| `astra.games.index/1` | every listed release, the moderator rows (`games[]`, `anticheat[]`, `loaders[]`) and who owns each engine code | [`games-index-v1.md`](https://github.com/mihailinl/AstraPlugins/blob/main/spec/games/games-index-v1.md) |
| `astra.games.withdrawn/1` | yanks, delistings, deprecations and revocations | [`games-withdrawn-v1.md`](https://github.com/mihailinl/AstraPlugins/blob/main/spec/games/games-withdrawn-v1.md) |

Both are small JSON documents in the plugin envelope, signed with Ed25519, and
re-signed every day and on every change. A copy older than 7 days stops new
installs and updates; Play and repair of what is already installed keep
working on the last copy a client verified.

## The trust model, in plain words

**A game integration is not sandboxed.** It is code that runs inside a game
with your privileges, and Astra says so on the install sheet. What this
catalogue gives you is *where it came from*, not a promise that it is safe.

**What a listed release has proven:**

- **Community releases** were built by GitHub Actions, on a GitHub-hosted
  runner, from a pushed tag of the public repository the publisher bound to
  their Minice account. That is GitHub's own build attestation, checked by
  the same certificate code the plugin registry uses
  ([`lib/vendor/astra-registry/`](lib/vendor/astra-registry/), vendored at a
  pinned commit). A hand-started build (`workflow_dispatch`), a branch build,
  a self-hosted runner, a commit that is not the tag's, or a repository whose
  owner changed is refused or held.
- **First-party releases** (the repositories in
  [`first-party.json`](first-party.json)) are admitted by **digest pin**
  instead: their Unity foundations compile against files from installed games
  and cannot be built in CI, so the owner pins each release's SHA-256 in
  `first-party.json` and the catalogue signs exactly those bytes. This is
  what Astra 0.2.7 already trusts through its compiled pins.
- **Every release** passed `gi-probe` (the launcher's own manifest and
  descriptor parser), the schemas in AstraPlugins' `spec/games/`, the engine
  code rules, and the anti-cheat and online-game checks.

**What it has not proven:** that anybody read the code. A release is listed
the moment it passes, labelled **«Не проверено модераторами»**. A moderator may
later mark it source-reviewed; that is a label, never a gate.

**No author holds a signing key.** Authors publish ordinary GitHub releases.
The only keys are the catalogue's two (`games-current`, `games-next`), and
they live only in this repository's protected `games-signing` environment.
The ingest job, which reads strangers' releases, holds no secret at all.

**Moderators act through the site**, each act confirmed with one 2FA, and
every act is a public JSON file in this repository's history. Each act
re-signs both documents in the same run, so a revoke reaches clients within
their hourly refresh.

**Engine codes have owners.** The first foundation that passes ingest with a
descriptor for a new code owns it; anyone else building for that engine
declares `[target] engine = "<code>"` and is offered beside it. A squatted or
abandoned code moves only by a moderator act that cites its evidence.

## Layout

| path | what |
|---|---|
| `first-party.json` | the owner's repositories by GitHub `repository_id`, and the per-release digest pins |
| `loaders.json` | the seed allowlist of loader builds that ship off by default (A§4.5); moderator acts add or remove on top |
| `keys.json` | the published public keys of `games-current` and `games-next` (K14) |
| `fixtures/` | the staging fixtures ingest is tested against, and the list-shape recordings (R29) |
| `lib/`, `bin/` | ingest, signing, acts, promotion; `lib/vendor/` holds the pinned copies |
| `.github/workflows/` | `ingest.yml` (no secrets), `sign.yml`, `promote.yml`, `resign.yml`, `ci.yml` |
| branch `data` | the catalogue's state and the signed documents under `dist/`; written only by `sign.yml` and `resign.yml` |

## Running the tests

```sh
node --test
```

Node 22 or newer and Python 3.11 or newer (for `tomllib`, and for
AstraPlugins' `tools/schemalite.py`, which validates every produced document).
Nothing is installed from a registry.

## Licence

GPL-3.0-or-later. Copyright Minice. See [`LICENSE`](LICENSE).
