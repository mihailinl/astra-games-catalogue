<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 Minice — https://minice.ai
-->

# fixtures

| directory | what | read by |
|---|---|---|
| `staging/` | one staging release as GitHub and `gh attestation verify --format json` describe it: the good case, and one variant per refusal of A§11 S1b (a self-hosted runner, `workflow_dispatch`, a branch ref, a wrong sha, a wrong owner id) plus a transferred repository | `test/ingest.test.mjs` |
| `list-shape/` | list-shape recordings of game folders (merged plan R29: one corpus, B's format, written by `gi-probe capture`) for the descriptors this catalogue signs | `gi-probe validate-descriptor --corpus`, once ingest runs it |
| `gi-probe/` | `fake-gi-probe.mjs`: a fake gi-probe 0.5.1 binary that `lib/probe.mjs` runs in the tests in place of the real one (which no test runs). It reads its command line as `main.rs` at `v0.5.1` does (`test/gi-probe-v051.mjs`, frozen from that tag's source), answers a wrong one with exit 2 and `error.usage`, and a right one with an `astra.gi-probe/1` report of exactly 0.5.1's keys; a test's scenario file makes it refuse, disagree or misbehave. Kept out of `test/` so `node --test` does not run it as a test file | `test/helpers.mjs` `fakeProbe` |
| `vrm-conflict/` | O-2 (minice-01's content-contract review): `vrm-metas-disagree.vrm` carries a VRM 0.x meta that allows redistribution (`licenseName = CC_BY`, `allowedUserName = Everyone`) and a VRM 1.0 meta that prohibits it (`allowRedistribution = false`) -- a gate that reads only the first meta passes it; `vrm-metas-agree.vrm` carries both, agreeing. Byte-for-byte AstraPlugins' goldens `testdata/games/content/vrm/` at 516ba38 (sha256 `7eec68ab...f106e` and `7e3659f5...4d7f5`; O-2c corrected `licenseName` from `Redistribution_Allowed`, which the gate now reads "unknown", not "allowed"), so this gate and the spec's checker judge the same bytes | `test/content.test.mjs` |
| `zip-cloaking/` | astra-ce's sec-probe vectors for Zip Cloaking shapes `lib/schemacheck.py`'s `verify_zip_headers` missed at first: `slack.zip` (a bit-3 Deflated entry whose central-directory `compressed_size` runs past the real deflate stream's own end, hiding a second local header in the slack), `upath.zip` (an Info-ZIP Unicode Path extra field, 0x7075, naming a different path than the entry's own header -- honoured by some readers, including Python's own `zipfile`), and `stored-dd.zip` (sec-probe2: a bit-3 Stored entry's real, signature-carrying data descriptor sits past a smuggled second header instead of right after the entry's own declared data) | `test/zipcheck.test.mjs` |

Every id, digest and name in `staging/` is invented for the fixture. The
certificate values follow the shape `gh 2.100.0` prints (the registry's
B-T1.2 survey, `lib/vendor/astra-registry/bot/lib/certificate.mjs`).
