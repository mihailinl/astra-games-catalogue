<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 Minice — https://minice.ai
-->

# fixtures

| directory | what | read by |
|---|---|---|
| `staging/` | one staging release as GitHub and `gh attestation verify --format json` describe it: the good case, and one variant per refusal of A§11 S1b (a self-hosted runner, `workflow_dispatch`, a branch ref, a wrong sha, a wrong owner id) plus a transferred repository | `test/ingest.test.mjs` |
| `list-shape/` | list-shape recordings of game folders (merged plan R29: one corpus, B's format, written by `gi-probe capture`) for the descriptors this catalogue signs | `gi-probe` in ingest, once launcher 0.5.0 ships it |
| `vrm-conflict/` | O-2 (minice-01's content-contract review): `vrm-metas-disagree.vrm` carries a VRM 0.x meta that allows redistribution (`licenseName = Redistribution_Allowed`, `allowedUserName = Everyone`) and a VRM 1.0 meta that prohibits it (`allowRedistribution = false`) -- a gate that reads only the first meta passes it; `vrm-metas-agree.vrm` carries both, agreeing. Byte-for-byte AstraPlugins' goldens `testdata/games/content/vrm/` at 4de2e30 (sha256 `2377ad9d...35787` and `7b911eaf...3903c`), so this gate and the spec's checker judge the same bytes | `test/content.test.mjs` |
| `zip-cloaking/` | astra-ce's sec-probe vectors for Zip Cloaking shapes `lib/schemacheck.py`'s `verify_zip_headers` missed at first: `slack.zip` (a bit-3 Deflated entry whose central-directory `compressed_size` runs past the real deflate stream's own end, hiding a second local header in the slack), `upath.zip` (an Info-ZIP Unicode Path extra field, 0x7075, naming a different path than the entry's own header -- honoured by some readers, including Python's own `zipfile`), and `stored-dd.zip` (sec-probe2: a bit-3 Stored entry's real, signature-carrying data descriptor sits past a smuggled second header instead of right after the entry's own declared data) | `test/zipcheck.test.mjs` |

Every id, digest and name in `staging/` is invented for the fixture. The
certificate values follow the shape `gh 2.100.0` prints (the registry's
B-T1.2 survey, `lib/vendor/astra-registry/bot/lib/certificate.mjs`).
