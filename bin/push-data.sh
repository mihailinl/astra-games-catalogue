#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Minice — https://minice.ai
#
# Commit the data checkout and push it to `data` with the repository's write
# deploy key — the only actor the ruleset "data: only the deploy key updates
# it" lets move `data` (the GitHub Actions app cannot be a bypass actor on a
# repository a person owns); "data is append-only" still holds it to
# fast-forwards. sign.yml and resign.yml call this; GITHUB_TOKEN stays
# read-only, so nothing else in a run can write to the repository at all.
#
#   bin/push-data.sh <data checkout> <commit message>
#   env: GAMES_DATA_DEPLOY_KEY (the private half, from publish-games), GITHUB_REPOSITORY
#
# The key goes to a 0600 file under RUNNER_TEMP for the one push and is
# removed after it. The host key is GitHub's published ed25519 key
# (`gh api meta -q .ssh_keys`), pinned: no trust on first use.
set -euo pipefail
dir=$1
msg=$2
: "${GAMES_DATA_DEPLOY_KEY:?the deploy key secret is not set in publish-games}"
: "${GITHUB_REPOSITORY:?}"

tmp=$(mktemp -d "${RUNNER_TEMP:-/tmp}/data-push.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
(umask 077 && printf '%s\n' "$GAMES_DATA_DEPLOY_KEY" > "$tmp/key")
printf '%s\n' 'github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl' > "$tmp/known_hosts"

cd "$dir"
git config user.name "astra-games-catalogue"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git add -A
git commit -q -m "$msg"
GIT_SSH_COMMAND="ssh -i '$tmp/key' -o IdentitiesOnly=yes -o IdentityAgent=none -o StrictHostKeyChecking=yes -o UserKnownHostsFile='$tmp/known_hosts' -o GlobalKnownHostsFile=/dev/null" \
  git push -q "git@github.com:${GITHUB_REPOSITORY}.git" HEAD:data
