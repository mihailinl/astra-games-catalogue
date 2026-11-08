# `data` — the games catalogue's state

Written only by this repository's workflows (`ingest.yml` reads it, `sign.yml`,
`resign.yml` and `promote.yml` push to it). Nothing here is edited by hand.

An empty branch is the first-run state: `lib/state.mjs::loadState` reads every
missing file as empty, and `floors.json` is created by the first signing run.
The plugins service's `games_fetch` mirrors this branch and serves only the two
signed documents it finds here, after verifying them with trust.json's `games`
kind keys.
