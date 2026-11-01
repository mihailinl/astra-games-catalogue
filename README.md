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
| `gi-probe.json` | the pinned `gi-probe` build ingest runs; null until astra-game-launcher 0.5.0, and ingest waits until then |
| `.github/action-pins.json` | every action, by the commit its release tag peels to |
| `fixtures/` | the staging fixtures ingest is tested against, and the list-shape recordings (R29) |
| `lib/`, `bin/` | ingest, signing, acts, promotion; `lib/vendor/` holds the pinned copies |
| `.github/workflows/` | `ingest.yml` (no secrets), `sign.yml`, `promote.yml`, `resign.yml`, `ci.yml` |
| branch `data` | the catalogue's state and the signed documents under `dist/`; written only by `sign.yml` and `resign.yml` |

## How a release becomes a listing

1. The plugins service sends `repository_dispatch` **`games-release`**
   `{repo_id, tag, account?, binding_token?}` (registration, poll, Check now).
2. **Ingest** (`ingest.yml`, no secret) checks the release and uploads an
   unsigned candidate: `accept`, `hold` (a person decides), `wait` (retried)
   or `refuse`.
3. **Sign** (`sign.yml`, `games-signing`) re-checks the candidate against the
   schema and the catalogue's state, lists it, and re-signs both documents to
   the `data` branch under `dist/`.
4. **Promote** (`promote.yml`) makes first-party GitHub releases match what
   was signed.

## Moderator acts

The site sends one act per `repository_dispatch` **`games-act`**, as
`client_payload.act`, after the moderator's console 2FA:

```json
{ "schema": "astra.games.act/1", "type": "M_REVOKE", "at": 1798675100,
  "by": { "account": "a-moderator" },
  "confirmation": { "kind": "console-2fa", "ref": "<the site's confirmation id>" },
  "repo_id": 987654321, "versions": "<=1.1.9", "entry_id": "someone/peak-astra",
  "reason_code": "security", "reason_text": "…" }
```

| type | payload |
|---|---|
| `M_YANK` `M_DELIST` `M_DEPRECATE` `M_REVOKE` | `repo_id`, `versions` (`*`, comparators, `\|\|`), `entry_id` (required when the repository hosts several), `reason_code`, `reason_text`; a revoke may add `cascade.revoke: [entry ids]`; `break_glass` skips the 3-per-24-hours takedown bound |
| `M_GAMES_EDIT` | `op: upsert` + `row` (a `games[]` row), or `op: delete` + `id` |
| `M_ANTICHEAT_EDIT` | `op: add\|remove` + `row` (`{name, kind, value}`) |
| `M_LOADERS_EDIT` | `op: add` + `row` (`{name, sha256}`), or `op: remove` + `row.sha256` |
| `M_MARK_SOURCE_REVIEWED` | `entry_id`, `version` (the label binds to that release's digest) |
| `M_REASSIGN_ENGINE_CODE` | `code`, `to` (`{account, repo_id, repo_owner_id}` of a listed foundation's publisher), `reason_text` |
| `M_ADOPT_ENGINE_CODE` | `code`, `successor_entry_id`, `evidence: {unanswered_reports: [≥1], descriptor_failure: {kind: probe\|reports, refs: [≥1]}, successor_probe: "pass", successor_installs_without_failure: ≥1}` |
| `M_SET_UNMAINTAINED` | `entry_id`, `unmaintained`, `successor_entry_id` |
| `M_SET_RECOMMENDED_FOUNDATION` | `code`, `entry_id` (or null) |
| `M_PROMOTE` | `entry_id`, `version` of a first-party prerelease |
| `M_RELEASE_HOLD` | `hold_id` (`<repo_id>@<tag>`), `decision: accept\|refuse` |

Every act is recorded as `acts/<seq>.json` on `data`, and every act re-signs
both documents in its own run. A refused act changes nothing and fails the
run, after the re-sign has landed.

The plugins service sends health counts as **`games-health`**
`{health: {entry_id: {rating_avg (hundredths), rating_count,
open_reports_unanswered, reports_sent, reports_failed}}}`. `health`,
`unmaintained`, `successor_entry_id` and `recommended_foundations` are
computed and kept, and appear in the signed index once AstraPlugins'
`games-index-v1.schema.json` declares them (lib/documents.mjs).

## Running the tests

```sh
node --test
```

Node 22 or newer and Python 3.11 or newer (for `tomllib`, and for
AstraPlugins' `tools/schemalite.py`, which validates every produced document).
Nothing is installed from a registry.

## Licence

GPL-3.0-or-later. Copyright Minice. See [`LICENSE`](LICENSE).
