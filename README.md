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
  runner, from a pushed tag of the public repository the publisher bound on
  the site. That is GitHub's own build attestation, checked by
  the same certificate code the plugin registry uses
  ([`lib/vendor/astra-registry/`](lib/vendor/astra-registry/), vendored at a
  pinned commit). A hand-started build (`workflow_dispatch`), a branch build,
  a self-hosted runner, a commit that is not the tag's, or a repository whose
  owner changed is refused or held.
- **The binding** is the `astra-binding:` line the site gave the publisher,
  committed in `.well-known/astra-gi-owner` at the release's tag. The plugins
  service keeps only the SHA-256 of its token, and ingest compares that with
  the line it reads: a tag whose line is not the site's current binding is
  refused, and a line that changed since the listing is held for a person.
- **First-party releases** (the repositories in
  [`first-party.json`](first-party.json)) are admitted by **digest pin**
  instead: their Unity foundations compile against files from installed games
  and cannot be built in CI, so the owner pins each release's SHA-256 in
  `first-party.json` and the catalogue signs exactly those bytes. This is
  what Astra 0.2.7 already trusts through its compiled pins.
- **Every release** passed `gi-probe` (the launcher's own manifest and
  descriptor parser: `gi-probe check`, plus `validate-descriptor` for a
  foundation that owns an engine code and `compat` for a first-party release
  Astra 0.2.7 installs; `lib/probe.mjs` holds the table), the schemas in
  AstraPlugins' `spec/games/`, the engine code rules, and the anti-cheat and
  online-game checks.

- **Every content part** (animations, a character model, art, audio) was
  confirmed by the author on the site, part by part, under the current
  rights text. A part is one file, its path and its SHA-256: a changed file
  is asked about again, and a release waits (`W_CONTENT_UNCONFIRMED`) until
  every part is confirmed. The entry records which text versions they were
  confirmed under (`content_confirmed`); who confirmed, and when, stays in
  the plugins service.

**What it has not proven:** that anybody read the code. A release is listed
the moment it passes, labelled **«Не проверено модераторами»**. A moderator may
later mark it source-reviewed; that is a label, never a gate.

**No Minice account appears here.** The publisher of an entry is named by the
GitHub login that owned the repository when it was first bound; the Minice
account behind it stays private in the plugins service, and moderators appear
only as `mod-<n>`.

**No author holds a signing key.** Authors publish ordinary GitHub releases.
The only keys are the catalogue's two, and they live only in this
repository's protected `publish-games` environment (one environment per
content kind, with the plugin registry's `publish` branch policy). The
ingest job, which reads strangers' releases, holds no secret at all.

**The plugins service cannot write here.** It holds no GitHub credential. Its
waker can only start `ingest.yml` and `sign.yml` on `main`, with no inputs;
each workflow's `work` job then asks the service for its work, and its
`report` job answers. Both run in the `games-service` environment, which
holds no secret: their only credential is a short-lived GitHub OIDC token
for the audience `https://api.minice.ai/plugins/v1/games`, and the service
accepts it only from this repository's workflows on `main` in that
environment. No workflow takes `repository_dispatch`.

**Which two keys, and who says so.** The games keys are authorised the same
way as every other signing key Astra trusts: by the `kind_keys` member of the
registry's `trust.json`, which the compiled ROOT keys sign. It names exactly
two keys for kind `games`, a `current` and a `next`, both authorised in
advance:

```json
{ "kind": "games", "role": "current", "key_id": "astra-games-2026a",
  "alg": "ed25519", "public_key": "<base64, 32 bytes>", "not_before": "<RFC 3339>" }
```

- A games document is accepted only under one of those two keys. A key of
  another kind (commands, characters, packs) or the plugin index's key is
  refused for it, and a kind key never appears in `index_keys`. The signer
  verifies `trust.json` under the compiled roots before it signs anything,
  and refuses a secret that is not the authorised key of its role.
- **The authorisation is long-lived; signatures are short-lived.** Each
  document says `expires_at − issued_at` (7 days, never more than 8) and
  carries `serial = issued_at` above a per-kind floor, so an old or stolen
  document stops verifying within days and a still-trusted key cannot replay
  an older one. There is no per-key lifetime.
- **Routine rotation needs no ceremony and no client release**: put the next
  key in `GAMES_SIGNING_KEY_NEXT`, and the signer switches to it; clients
  already accept it. Which key is which comes from `trust.json`, never from
  the secret's name: each seed's public key is looked up there. With the old
  key's seed still beside it, the signer signs with `next` first and the old
  `current` beside it, and the document says `games-current`. That is the
  ceremony bridge below, on whenever both seeds are set. The key rotated away
  from is spent: it only ever co-signs, and it never signs alone. Spent is per
  document schema, not per kind (minice design §11a.9; AstraPlugins
  `games-index-v1.md` §3): the index and the withdrawn list are signed and
  served on separate schedules, and a client retires `current` for one of them
  only when a document of that same schema moves the rotation, so a withdrawn
  list is never refused because the index rotated first. `floors.json` on
  `data` records the spent keys per schema, each by id and public key.
- **A root ceremony** (the owner's one passphrase) happens only on a
  compromise, when both games keys are spent for a schema, or to add a kind: it re-signs
  `trust.json` without the bad key and with a fresh `next`.
- **A ceremony that promotes `next` to `current` is bridged.** A document
  only the promoted key signed is refused under either the old or the new
  `trust.json`, so every served document must carry both keys' signatures
  first. With both seeds set, the signer already does that, before and after
  the ceremony; the old key keeps co-signing until the next promotion. Before
  the new `trust.json` is published, the operator runs
  `node bin/ceremony-ready.mjs --next-trust <candidate trust.json>`, which
  fetches the live `trust.json` and both documents from both registry hosts
  (which must serve the same `trust.json`), refuses a candidate that is not
  that promotion, and prints the digest of the body the owner is to sign.
  Publish only on exit 0.
- Inside the document, `key_id` names the role (`games-current` or
  `games-next`, as AstraPlugins' schema enumerates); the signature's
  `key_id` names the key (`astra-games-2026a`).

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
| `gi-probe.json` | the pinned `gi-probe` build ingest runs: `version`, the Linux binary's `url` and `sha256`, and the build's `source_tree_sha256` every report must carry; with no `version`, ingest waits |
| `.github/action-pins.json` | every action, by the commit its release tag peels to |
| `fixtures/` | the staging fixtures ingest is tested against, and the list-shape recordings (R29) |
| `lib/`, `bin/` | ingest, signing, acts, promotion; `lib/vendor/` holds the pinned copies |
| `.github/workflows/` | `ingest.yml` (no secrets), `sign.yml`, `promote.yml`, `resign.yml`, `ci.yml` |
| `bin/service.mjs`, `lib/service.mjs` | the `work` and `report` jobs' client for the plugins service's games bot doors |
| `bin/ceremony-ready.mjs`, `lib/ceremony.mjs` | the operator's check before a games `trust.json` that promotes `next` is published |
| branch `data` | the catalogue's state and the signed documents under `dist/`; written only by `sign.yml` and `resign.yml` |

## How a release becomes a listing

1. The author binds the repository and presses **Check now** (or names a tag)
   on the site; the plugins service queues the release and its waker starts
   `ingest.yml`. A 15-minute schedule starts it too, if the waker is down.
2. **Lease** (`ingest.yml` `work`, `games-service`): the job leases up to 5
   releases (`POST bot/games/leases`), polls the repositories the service
   names for new releases and registers them (`POST bot/games/releases`),
   and writes one `games-request-<lease>.json` per lease:
   `{lease_id, repo_id, tag|null, binding_token_sha256, confirmed[]}`. No
   account, plaintext token or subject is ever in a lease.
3. **Ingest** (`ingest.yml` `ingest`, one matrix leg per lease, no secret)
   checks the release and uploads an unsigned candidate as
   `games-candidate-<lease>`: `accept`, `hold` (a person decides), `wait`
   (retried; an unconfirmed content part is a wait) or `refuse`.
4. **Report** (`ingest.yml` `report`, `games-service`): one
   `astra.games.ingest-result/1` per lease (`POST bot/games/ingest-results`).
   The site shows the findings and asks the author about each unconfirmed
   part; once they tick it, the release is leased again.
5. **Sign** (`sign.yml`, after the Ingest run): `work` pulls the pending
   moderator acts and health counts (`GET bot/games/work`); `sign`
   (`publish-games`) re-checks each candidate against the schema and the
   catalogue's state, lists it, applies the acts, and re-signs both documents
   to the `data` branch under `dist/`; `report` posts the outcome
   (`POST bot/games/sign-results`) and wakes the service
   (`POST games/signed-wake`, no credential). A run with nothing to sign
   stops after `work`; `resign.yml` re-signs daily regardless.
6. **Promote** (`promote.yml`) makes first-party GitHub releases match what
   was signed.

The service's base URL is the repository variable `GAMES_SERVICE_URL`
(default `https://api.minice.ai/plugins/v1`; `GAMES_SERVICE_AUDIENCE`
overrides the OIDC audience for a staging service).

## Moderator acts

A moderator acts on the site, with one console 2FA per act; the plugins
service stores the act and its waker starts `sign.yml`, whose `work` job
pulls every pending act, oldest first:

```json
{ "schema": "astra.games.act/1", "type": "M_REVOKE", "at": 1798675100,
  "by": { "account": "mod-7" },
  "confirmation": { "kind": "console-2fa", "ref": "<the service's act id>" },
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
| `M_LIFT` | `repo_id`, `versions`, `entry_id` (only when the row has one) and `lifts_at` (the row's `at`): the withdrawal row to lift, each exactly as the row carries it; `reason_text` |

**A lift** (`M_LIFT`, `games-withdrawn-v1.md` §2.2) is the only thing that ends
a `revoke` for `security` on a client that has seen it: such a row stays in
force there even when the list stops carrying it. The act names one row by
`repo_id`, `entry_id`, `versions` and `at`, byte for byte, and is refused with
the member that matched nothing when no row is named. Every row it names
leaves the list in that run (more than one when rows share a subject and a
second: a cascade's banner and yank, or two acts on one subject within a
second), and the lift is signed into `lifts`, where it
stays: the list serves the newest 256. It lifts nothing else: the rows a
revoke cascaded onto its dependants are lifted by their own acts. A lifted
takedown still counts toward the 3-per-24-hours bound.

Every act is recorded as `acts/<seq>.json` on `data`, and every act re-signs
both documents in its own run. An act is applied once per confirmation ref:
one the service serves again (its result never arrived) is answered
"applied, seq N" and not applied twice. A refused act changes nothing and
fails the run, after the re-sign has landed and been reported.

The work answer also carries the plugins service's health counts,
`{entry_id: {rating_avg (hundredths), rating_count,
open_reports_unanswered, reports_sent, reports_failed}}`, or null. `health`,
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
