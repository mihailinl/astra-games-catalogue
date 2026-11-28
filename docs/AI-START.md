<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 Minice — https://minice.ai
-->

# Astra in a game: start here

This page is for an AI coding agent (Codex, Claude, Cursor and the like). A person asked you either
to **make Astra work in a game** or to **find out why Astra did not appear in a game**. Astra gave
them a brief to paste: it names the game, its engine, its folders and Astra's logs for it. Read the
brief with this page.

- [1. What an integration is](#1-what-an-integration-is)
- [2. Choose the path](#2-choose-the-path)
- [3. Before any code](#3-before-any-code)
- [4. Unity: she is in the game](#4-unity-she-is-in-the-game)
- [5. Astra Link: her AI sees the game and acts in it](#5-astra-link-her-ai-sees-the-game-and-acts-in-it)
- [6. Unreal](#6-unreal)
- [7. Publish](#7-publish)
- [8. Diagnose a start without her](#8-diagnose-a-start-without-her)

## 1. What an integration is

**Astra** is a desktop assistant with a 3D character that her own engine draws. A *game
integration* is a mod that Astra installs into its own folder for that game (the game's
*profile*). Astra loads it only when the person presses **Play** in Astra; starting the game from
Steam as usual never loads it.

An integration can do two things, together or alone:

- **Put her in the game.** Her character stands in the game's own frame, lit by its sun and hidden
  by its walls, and follows the player. This works for Unity and Unreal games, through Astra's
  *foundations*.
- **Let Astra's AI see the game and act in it (Astra Link).** The game tells Astra what happens
  (events, a short context) and offers tools her AI may call: "come here", "what's missing for this
  recipe", "mark this on the map". This works in any engine whose mods can open a local WebSocket.

Many games need no integration at all: **"Astra for any Unity game"** (Unity, Mono) and the
**Unreal runner** put her in most games of their engine. Write an integration for what only code
that knows THIS game can do.

## 2. Choose the path

Take the engine from the brief.

| Engine | She in the game | Astra Link |
|---|---|---|
| Unity, Mono | an integration on the SDK: [§4](#4-unity-she-is-in-the-game) | `Link` in the same SDK: [§5](#5-astra-link-her-ai-sees-the-game-and-acts-in-it) |
| Unity, IL2CPP | the same SDK, experimental (BepInEx 6) | the same |
| Unreal | the Unreal runner; per-game fixes only: [§6](#6-unreal) | a mod of the game's own mod system speaking the Link protocol; no template yet |
| Godot, or one Astra does not recognise | not possible | a mod of the game's own mod system speaking the Link protocol; no template yet |

If the person wants something their engine does not allow (her in a game on an engine Astra cannot
draw into), say so before writing anything, and offer what is possible: Link alone often covers
"she knows what happens in my game and helps".

## 3. Before any code

- **No anti-cheat.** Never mod a game with kernel or server-side anti-cheat (EasyAntiCheat,
  BattlEye, Vanguard and the like), or a game whose rules forbid mods online: players get banned.
  Astra refuses such games anyway.
- **See it with the foundation first.** If Astra already supports the engine, have the person add
  the game in Astra's **Games** tab and press Play once. What is wrong with her there is the to-do
  list, and the log says what Astra sees (where the log is: [§8](#8-diagnose-a-start-without-her)).
- **Read the game, never copy it.** For Unity Mono, a .NET decompiler (ILSpy, dnSpyEx) shows the
  game's code on the person's machine. Reach the game's types by name at runtime; never put the
  game's code or files in the integration.
- **Your own folder.** Work in a new folder of your own, never inside the game's folder or Astra's
  profile. Publishing needs a public GitHub repository.

## 4. Unity: she is in the game

The guide, step by step, with the SDK's every call:
[astra-bepinex `docs/WRITE-AN-INTEGRATION.md`](https://github.com/mihailinl/astra-bepinex/blob/main/docs/WRITE-AN-INTEGRATION.md).
In short:

1. **Create the project** from the template (step 3 of the guide): `git clone
   https://github.com/mihailinl/astra-bepinex`, `dotnet new install
   ./astra-bepinex/templates/astra-integration`, then `dotnet new astra-integration -n <Name>
   --game "<Game>" --id <github-name>.<game> --runtime mono --steamAppId <id> --owner
   <github-name>`. You need the .NET 8 SDK.
2. **Build**: `bash tools/fetch.sh` once, then `dotnet build -c Release`. Leave `GameDir` empty, so
   the release builds in CI without the game.
3. **Write the game's knowledge** with the SDK (step 5): whom she follows (`UsePlayer`), which
   camera she is drawn into (`UseCamera`), her size (`Defaults`), where she stands when the player
   climbs, swims or drives (`UseBrain`), the game's states for her animations (`OnFrame` and
   `Params`), its light (`UseSun`, `UseLook`).
4. **Test in the game** (step 7): the game's profile exists once the game was played from Astra.
   Copy your DLL and `astra-item.json` into `<profile>/BepInEx/plugins/<Name>/`, press Play in Astra,
   and read `<profile>/BepInEx/LogOutput.log`: `integration '<id>' … is in charge`, `connected to
   Astra on 127.0.0.1:…`, and the `her:` line.
5. **Package and publish** (steps 8 and 9, and [§7](#7-publish) here).

Before a fix that needs code, try the foundation's own settings: `Scale`, `PlayerObject`,
`GroundLayers` and the follow distances in `<profile>/BepInEx/config/astra.unity-foundation.cfg`.

## 5. Astra Link: her AI sees the game and acts in it

The protocol: AstraPlugins
[`spec/games/link-v1.md`](https://github.com/mihailinl/AstraPlugins/blob/main/spec/games/link-v1.md);
the manifest's `[integration.link]` table:
[`spec/games/manifest.md`](https://github.com/mihailinl/AstraPlugins/blob/main/spec/games/manifest.md)
§2.6. For Unity, the SDK's `Link` does the protocol for you: the guide's step 5, "Astra's AI: Link".

What to know before you design it:

- **The person decides.** Every game has switches in Astra ("AI may act", "Tell Astra what
  happens", "She may speak on her own"), all off until the person turns them on. A tool that acts
  in the game runs only in a turn the person started.
- **Closed vocabularies.** Events are the protocol's words (`player_hurt`, `player_died`,
  `goal_reached`…), refusals are its codes, results are numbers, enums and booleans: never a string
  a player wrote (a sign, a chat line, a name). The context is at most 2 KiB.
- **Local only, to begin with.** Tools that change only what the local player sees (a map pin of
  their own, her walking to them) are the easy start. Anything that changes the shared world in a
  multiplayer game needs the "only while the player is alone" rule the guide describes.
- **Testing.** Link connects only for an integration installed from Astra's signed catalogue. Before
  publishing, it can be tested only with a debug build of Astra (the test stand in the Astra
  repository, `docs/games/LINK_TEST_STAND.md`), which means building Astra from source. Loading an
  integration from a folder in a normal Astra is planned and not there yet. Tell the person this
  plainly before they count on testing Link at home; the "she is in the game" half can be tested as
  in [§4](#4-unity-she-is-in-the-game).

## 6. Unreal

The Unreal runner ([astra-reshade](https://github.com/mihailinl/astra-reshade)) puts her into
Unreal games through UE4SS and a ReShade add-on. There is no SDK for an Unreal integration of your
own yet. What a game can need today:

- **UE4SS cannot find the engine in this game's program.** `UE4SS.log` says `Was unable to find AOB
  for '<Symbol>'`, or the scan times out. The fix is a signature override for this game only:
  [`runners/unreal/game-signatures/README.md`](https://github.com/mihailinl/astra-reshade/blob/main/runners/unreal/game-signatures/README.md)
  explains why it must be pinned to the game's program and how GTA III was fixed. Prepare it as a
  pull request to astra-reshade.
- Everything else (how she is drawn, the depth, the menus) is the runner's: report it ([§8](#8-diagnose-a-start-without-her)).

## 7. Publish

Players install from Astra's catalogue, which lists releases of public GitHub repositories:

1. **Release from CI only.** The template's `.github/workflows/release.yml` builds `astra-gi.zip` on
   a pushed tag `v*`, attests it and attaches it to the release. Keep the workflow, its name and its
   attestation step; a zip attached by hand is refused. A tag is final: fix anything with a new tag.
2. **The person binds the repository** on the Workshop site, <https://astra.minice.ai>: an account
   with a public handle, then the repository. The site gives an `astra-binding:` line; commit it as
   `.well-known/astra-gi-owner` at the repository's root, push, and the person presses "Check"
   («Проверить») on the site.
3. **The person adds the release** there. A listed release says "not reviewed by moderators" until a
   moderator looks; that is a label, not a gate. Animations, models, art and audio in the release
   need the author's confirmation of rights on the site, part by part.

Prepare everything; let the person press the buttons on the site.

## 8. Diagnose a start without her

The brief lists the logs that exist for this game, with their paths. Read them on this machine; they
never leave it unless the person sends them.

**Unity: `<profile>/BepInEx/LogOutput.log`** (with the player's own mods on: the BepInEx log in
their mod folder). The foundation's first lines name the Unity version, the graphics API and the
render pipeline.

- No log, or one older than the last start: the loader did not run. The game was started another
  way (its own launcher, Epic handing the start back, Steam launch options that pass their own
  `--doorstop-…`).
- No `connected to Astra on 127.0.0.1:…`: Astra's engine was not there.
- The `her:` line is the foundation's own diagnosis: `not placed yet`, `behind the camera` or `off
  screen` (where she stands), `(no picture from Astra)` (the engine sends nothing), `(pictures
  arrive, none is drawn)` (the drawing: pipeline or camera), `(hidden: …)` (the toggle key, `F8`).
  The foundation's
  [`CONTRIBUTING.md`](https://github.com/mihailinl/astra-bepinex/blob/main/CONTRIBUTING.md#reporting-a-game-that-does-not-work)
  explains each.
- An exception at the foundation's start, or `the integration '<id>' failed … and is switched off`.
- Unity's own `Player.log`: shader and graphics errors, and crashes before BepInEx starts.

**Unreal: `<profile>/ue4ss/UE4SS.log`** and **`astra-loader-status.json`**: `load-failed`,
`foreign-reshade` (the player's own ReShade is beside the game, so Astra's did not load),
`stale-astra` (an older Astra's files are there).

**Known causes**, each with what was done about it: the Unity foundation's
[`docs/RENDER-CASES.md`](https://github.com/mihailinl/astra-bepinex/blob/main/docs/RENDER-CASES.md)
and the Unreal runner's
[`docs/STATUS.md`](https://github.com/mihailinl/astra-reshade/blob/main/docs/STATUS.md) ("Known
open").

Then say which kind it is:

| Kind | Examples | What to do |
|---|---|---|
| **This game alone** | a camera of the interface or a second camera picked; she follows the wrong object or finds no player; the wrong size; Unreal signatures | the foundation's settings first ([§4](#4-unity-she-is-in-the-game)), else an integration for this game, or a signature override ([§6](#6-unreal)) |
| **Astra's shared code** | how and where she is drawn (walls, particles, a pipeline), code an IL2CPP game stripped, a loader that cannot start on this engine version | a report for Astra's developers |
| **Nothing to fix** | anti-cheat; a launcher that restarts the game without Astra's start | say so |

**A report** names the game and its store id, the engine and its version, the graphics API and
pipeline, Astra's version and the integration's, what the person saw, the cause you found, and the
log lines that show it (a few to a few dozen, not whole files). Leave out personal data: the user
name in paths (write `<user>`), other people's names, and the player's mods unless they agree. It
goes to Astra's support chat (Astra's "Send a report" on the game's row builds the archive), or as
an issue: [astra-bepinex](https://github.com/mihailinl/astra-bepinex/issues) for Unity,
[astra-reshade](https://github.com/mihailinl/astra-reshade/issues) for Unreal,
[astra-game-launcher](https://github.com/mihailinl/astra-game-launcher/issues) when the game did
not start the way Astra asked.

Do not edit Astra's files in the profile or the game's folder to make her appear: Astra replaces its
own files on the next update, and the change helps nobody else.
