<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 Minice — https://minice.ai
-->

# fixtures

| directory | what | read by |
|---|---|---|
| `staging/` | one staging release as GitHub and `gh attestation verify --format json` describe it: the good case, and one variant per refusal of A§11 S1b (a self-hosted runner, `workflow_dispatch`, a branch ref, a wrong sha, a wrong owner id) plus a transferred repository | `test/ingest.test.mjs` |
| `list-shape/` | list-shape recordings of game folders (merged plan R29: one corpus, B's format, written by `gi-probe capture`) for the descriptors this catalogue signs | `gi-probe` in ingest, once launcher 0.5.0 ships it |

Every id, digest and name in `staging/` is invented for the fixture. The
certificate values follow the shape `gh 2.100.0` prints (the registry's
B-T1.2 survey, `lib/vendor/astra-registry/bot/lib/certificate.mjs`).
