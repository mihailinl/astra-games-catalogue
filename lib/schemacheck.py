#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Minice — https://minice.ai
"""The bridge from this repository's Node code to AstraPlugins' validator.

Every document and manifest this catalogue checks against an S schema goes
through `schemalite.validate` — AstraPlugins' own subset validator, vendored
byte for byte under lib/vendor/astraplugins/ at a pinned commit (canary K12).
Nothing here re-implements a keyword; this file only moves JSON in and out.

    python3 lib/schemacheck.py validate   < {"items": [{"schema": NAME, "doc": ...}, ...]}
    python3 lib/schemacheck.py manifest ZIP
        -> {"ok": true, "manifest": {...}} | {"ok": false, "error": "..."}
    python3 lib/schemacheck.py toml FILE      (the same, for a loose TOML file)

`manifest` reads astra-gi.toml from the root of a release zip with
`tomllib`, the same parser AstraPlugins' check-games-goldens.py uses. It reads
that one member and nothing else (zip hygiene is gi-probe's job, A§5.2 step
5), refuses a member bigger than MANIFEST_CAP, and refuses TOML values JSON
cannot carry exactly (datetimes) or JCS refuses (floats), because a
descriptor's digest is sha256(JCS(parsed)) (engine-descriptor-v1.md §1).
"""

from __future__ import annotations

import datetime
import json
import pathlib
import sys
import tomllib
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
VENDOR = HERE / "vendor" / "astraplugins"
sys.path.insert(0, str(VENDOR / "tools"))
import schemalite  # noqa: E402

SCHEMAS = {
    "games-index-v1": VENDOR / "spec/games/schemas/games-index-v1.schema.json",
    "games-withdrawn-v1": VENDOR / "spec/games/schemas/games-withdrawn-v1.schema.json",
    "manifest": VENDOR / "spec/games/schemas/manifest.schema.json",
    "engine-descriptor-v1": VENDOR / "spec/games/schemas/engine-descriptor-v1.schema.json",
}

MANIFEST_NAME = "astra-gi.toml"
MANIFEST_CAP = 256 * 1024


def validate(items):
    cache = {}
    out = []
    for item in items:
        name = item.get("schema")
        if name not in SCHEMAS:
            out.append({"ok": False, "error": f"unknown schema {name!r}"})
            continue
        if name not in cache:
            cache[name] = json.loads(SCHEMAS[name].read_text(encoding="utf-8"))
        try:
            schemalite.validate(item.get("doc"), cache[name])
            out.append({"ok": True, "error": ""})
        except schemalite.SchemaError as e:
            out.append({"ok": False, "error": str(e)})
        except NotImplementedError as e:
            out.append({"ok": False, "error": f"schemalite: {e}"})
    return {"results": out}


def _jsonable(value, at):
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, int):
        if abs(value) > 2**53 - 1:
            raise ValueError(f"{at}: integer {value} is outside JSON's exact range")
        return value
    if isinstance(value, float):
        raise ValueError(f"{at}: a float has no canonical JCS form, so it is refused")
    if isinstance(value, (datetime.date, datetime.time, datetime.datetime)):
        raise ValueError(f"{at}: a TOML datetime is refused")
    if isinstance(value, list):
        return [_jsonable(v, f"{at}[{i}]") for i, v in enumerate(value)]
    if isinstance(value, dict):
        return {k: _jsonable(v, f"{at}.{k}") for k, v in value.items()}
    raise ValueError(f"{at}: {type(value).__name__} is not representable")


def manifest(zip_path):
    try:
        with zipfile.ZipFile(zip_path) as z:
            members = [i for i in z.infolist() if i.filename == MANIFEST_NAME]
            if len(members) != 1:
                return {"ok": False, "error": f"the zip has {len(members)} {MANIFEST_NAME} at its root, not 1"}
            info = members[0]
            if info.file_size > MANIFEST_CAP:
                return {"ok": False, "error": f"{MANIFEST_NAME} is {info.file_size} bytes, over {MANIFEST_CAP}"}
            with z.open(info) as f:
                raw = f.read(MANIFEST_CAP + 1)
            if len(raw) > MANIFEST_CAP:
                return {"ok": False, "error": f"{MANIFEST_NAME} inflates past {MANIFEST_CAP} bytes"}
    except (zipfile.BadZipFile, OSError) as e:
        return {"ok": False, "error": f"not a readable zip: {e}"}
    try:
        text = raw.decode("utf-8")
        parsed = tomllib.loads(text)
        return {"ok": True, "manifest": _jsonable(parsed, "$")}
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, ValueError) as e:
        return {"ok": False, "error": f"{MANIFEST_NAME}: {e}"}


def toml_file(path):
    try:
        with open(path, "rb") as f:
            raw = f.read(MANIFEST_CAP + 1)
        if len(raw) > MANIFEST_CAP:
            return {"ok": False, "error": f"{path} is over {MANIFEST_CAP} bytes"}
        return {"ok": True, "manifest": _jsonable(tomllib.loads(raw.decode("utf-8")), "$")}
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, ValueError) as e:
        return {"ok": False, "error": f"{path}: {e}"}


def main(argv):
    if len(argv) >= 2 and argv[1] == "validate":
        req = json.load(sys.stdin)
        json.dump(validate(req.get("items", [])), sys.stdout)
        return 0
    if len(argv) == 3 and argv[1] == "toml":
        json.dump(toml_file(argv[2]), sys.stdout, ensure_ascii=False)
        return 0
    if len(argv) == 3 and argv[1] == "manifest":
        json.dump(manifest(argv[2]), sys.stdout, ensure_ascii=False)
        return 0
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
