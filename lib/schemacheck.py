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
    python3 lib/schemacheck.py content ZIP   < {"declared": [{"path", "kind", ...}, ...]}
        -> {"ok": true, "undeclared": [...], "missing": [...], "duplicates": [...],
            "parts": [{"path","sha256","vrm_licence"}], "licence_refusals": [...], "gaps": [...]}
         | {"ok": false, "error": "..."}

`manifest` reads astra-gi.toml from the root of a release zip with
`tomllib`, the same parser AstraPlugins' check-games-goldens.py uses. It reads
that one member and nothing else (zip hygiene is gi-probe's job, A§5.2 step
5), refuses a member bigger than MANIFEST_CAP, and refuses TOML values JSON
cannot carry exactly (datetimes) or JCS refuses (floats), because a
descriptor's digest is sha256(JCS(parsed)) (engine-descriptor-v1.md §1).

`content` is AstraPlugins' manifest.md §2.7 content-coverage check and HARD
VRM licence gate, run over the release zip's real bytes (the one place this
repository reads zip bytes beyond astra-gi.toml itself). It walks every zip
entry, classifies it as content-typed by extension AND magic bytes (an
extension alone is never enough), and compares the result against the
manifest's declared `[[integration.content]]` entries. The same
extension/magic table and the same GLB-chunk/VRM-meta logic are implemented
independently in AstraPlugins' tools/check-games-goldens.py, both pinned
against testdata/games/content/ (manifest.md §4's exception note) -- this is
NOT a vendored copy of that file, because one reads a real zip and the other
a loose directory.
"""

from __future__ import annotations

import datetime
import hashlib
import io
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


# ── content (manifest.md §2.7, merged plan §5.4) ────────────────────────
# manifest.md §2.7.1's detection table, and §2.7.3's HARD VRM GATE. The same
# logic as AstraPlugins' tools/check-games-goldens.py, independently
# implemented (one reads a real zip, the other a loose directory), both
# pinned against testdata/games/content/.

CONTENT_ENTRY_CAP = 64 * 1024 * 1024
ASTRACHAR_CAP = 256 * 1024 * 1024


def _is_zip(b):
    return len(b) >= 4 and b[0:2] == b"PK" and b[2] in (3, 5, 7)


def _is_glb(b):
    return len(b) >= 4 and b[0:4] == b"glTF"


def _is_gltf_text(b):
    return b.lstrip()[:1] == b"{"


def _is_fbx(b):
    return len(b) >= 18 and (b[0:18] == b"Kaydara FBX Binary" or b[0:5] == b"; FBX")


def _is_png(b):
    return b[0:8] == b"\x89PNG\r\n\x1a\n"


def _is_jpg(b):
    return b[0:3] == b"\xff\xd8\xff"


def _is_webp(b):
    return b[0:4] == b"RIFF" and b[8:12] == b"WEBP"


def _is_gif(b):
    return b[0:6] in (b"GIF87a", b"GIF89a")


def _is_ogg(b):
    return b[0:4] == b"OggS"


def _is_wav(b):
    return b[0:4] == b"RIFF" and b[8:12] == b"WAVE"


def _is_mp3(b):
    return b[0:3] == b"ID3" or (len(b) >= 2 and b[0] == 0xFF and (b[1] & 0xE0) == 0xE0)


def _is_flac(b):
    return b[0:4] == b"fLaC"


CONTENT_EXT_MAGIC = {
    ".astrapack": _is_zip, ".astrachar": _is_zip,
    ".vrma": _is_glb, ".glb": _is_glb, ".vrm": _is_glb,
    ".gltf": _is_gltf_text,
    ".fbx": _is_fbx,
    ".png": _is_png, ".jpg": _is_jpg, ".jpeg": _is_jpg, ".webp": _is_webp, ".gif": _is_gif,
    ".ogg": _is_ogg, ".wav": _is_wav, ".mp3": _is_mp3, ".flac": _is_flac,
}


def parse_glb_json_chunk(raw):
    if len(raw) < 20 or raw[0:4] != b"glTF":
        return None
    chunk_len = int.from_bytes(raw[12:16], "little")
    if raw[16:20] != b"JSON":
        return None
    data = raw[20:20 + chunk_len]
    if len(data) < chunk_len:
        return None
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def parse_vrm_licence(raw):
    """manifest.md §2.7.3's HARD VRM GATE. None when no VRM meta is present
    (not itself a refusal); otherwise {"vrm_version", "fields", "refusal"}."""
    doc = parse_glb_json_chunk(raw)
    if not isinstance(doc, dict):
        return None
    exts = doc.get("extensions")
    if not isinstance(exts, dict):
        return None
    vrm0 = exts.get("VRM")
    meta0 = vrm0.get("meta") if isinstance(vrm0, dict) else None
    if isinstance(meta0, dict):
        refusal = None
        if meta0.get("allowedUserName") == "OnlyAuthor":
            refusal = {"field": "extensions.VRM.meta.allowedUserName", "value": "OnlyAuthor"}
        elif meta0.get("licenseName") == "Redistribution_Prohibited":
            refusal = {"field": "extensions.VRM.meta.licenseName", "value": "Redistribution_Prohibited"}
        fields = {k: meta0[k] for k in ("allowedUserName", "licenseName") if k in meta0}
        return {"vrm_version": "0.x", "fields": fields, "refusal": refusal}
    vrm1 = exts.get("VRMC_vrm")
    meta1 = vrm1.get("meta") if isinstance(vrm1, dict) else None
    if isinstance(meta1, dict):
        refusal = None
        if meta1.get("avatarPermission") == "onlyAuthor":
            refusal = {"field": "extensions.VRMC_vrm.meta.avatarPermission", "value": "onlyAuthor"}
        elif meta1.get("allowRedistribution") is False:
            refusal = {"field": "extensions.VRMC_vrm.meta.allowRedistribution", "value": False}
        fields = {k: meta1[k] for k in ("avatarPermission", "allowRedistribution") if k in meta1}
        return {"vrm_version": "1.0", "fields": fields, "refusal": refusal}
    return None


def read_astrachar_body_vrm(outer_zip, entry_name):
    """The body inside a .astrachar bundle, read for the VRM gate, WHEN the
    bundle's format is readable (astra-companion docs/character-files-and-
    2d-editor.md §1.3/§1.4). Returns (vrm_licence_or_None, gap_reason_or_None)
    -- a gap is never a refusal."""
    try:
        with outer_zip.open(entry_name) as f:
            raw = f.read(ASTRACHAR_CAP + 1)
        if len(raw) > ASTRACHAR_CAP:
            return None, "astrachar_too_large"
        inner = zipfile.ZipFile(io.BytesIO(raw))
        with inner.open("astrachar.json") as f:
            char = json.loads(f.read(1024 * 1024 + 1))
        if char.get("format") != "astra.character":
            return None, "astrachar_bad_format"
        body = char.get("body")
        if not isinstance(body, dict) or not isinstance(body.get("file"), str):
            return None, "astrachar_body_not_a_file"  # ref / omitted / null / missing key
        body_path = body["file"]
        if not body_path.lower().endswith(".vrm"):
            return None, "astrachar_body_not_vrm"
        with inner.open(body_path) as f:
            body_bytes = f.read(CONTENT_ENTRY_CAP + 1)
        if len(body_bytes) > CONTENT_ENTRY_CAP or not _is_glb(body_bytes[:32]):
            return None, "astrachar_body_unreadable"
        return parse_vrm_licence(body_bytes), None
    except (zipfile.BadZipFile, KeyError, json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
        return None, f"astrachar_unreadable: {type(e).__name__}"


def content_report(zip_path, declared):
    """AstraPlugins manifest.md §2.7: the content-coverage check and the HARD
    VRM licence gate, over a real release zip. `declared` is the parsed
    manifest's `[[integration.content]]` array (a list of dicts)."""
    try:
        z = zipfile.ZipFile(zip_path)
    except (zipfile.BadZipFile, OSError) as e:
        return {"ok": False, "error": f"not a readable zip: {e}"}

    content_files = []
    parts_by_path = {}
    gaps = []
    with z:
        for info in z.infolist():
            if info.is_dir():
                continue
            ext = pathlib.PurePosixPath(info.filename).suffix.lower()
            sniff = CONTENT_EXT_MAGIC.get(ext)
            if sniff is None:
                continue
            try:
                with z.open(info) as f:
                    prefix = f.read(32)
            except OSError:
                continue
            if not sniff(prefix):
                continue
            if info.file_size > CONTENT_ENTRY_CAP:
                return {"ok": False, "error": f"{info.filename} is {info.file_size} bytes, over {CONTENT_ENTRY_CAP}"}
            with z.open(info) as f:
                raw = f.read(CONTENT_ENTRY_CAP + 1)
            if len(raw) > CONTENT_ENTRY_CAP:
                return {"ok": False, "error": f"{info.filename} inflates past {CONTENT_ENTRY_CAP} bytes"}
            content_files.append(info.filename)
            vrm_licence = parse_vrm_licence(raw) if ext == ".vrm" else None
            parts_by_path[info.filename] = {
                "sha256": hashlib.sha256(raw).hexdigest(),
                "vrm_licence": vrm_licence,
            }

        for entry in declared:
            path = entry.get("path") if isinstance(entry, dict) else None
            if not isinstance(path, str) or path not in parts_by_path:
                continue
            if pathlib.PurePosixPath(path).suffix.lower() == ".astrachar":
                vrm_licence, gap = read_astrachar_body_vrm(z, path)
                if gap:
                    gaps.append({"path": path, "reason": gap})
                parts_by_path[path]["vrm_licence"] = vrm_licence

    declared_paths = [e.get("path") for e in declared if isinstance(e, dict) and isinstance(e.get("path"), str)]
    seen, dup = set(), set()
    for p in declared_paths:
        if p in seen:
            dup.add(p)
        else:
            seen.add(p)
    declared_set = set(declared_paths)
    content_set = set(content_files)
    undeclared = sorted(content_set - declared_set)
    missing = sorted(declared_set - content_set)
    duplicates = sorted(dup)

    parts = []
    licence_refusals = []
    for path in sorted(declared_set & content_set):
        info = parts_by_path[path]
        parts.append({"path": path, "sha256": info["sha256"], "vrm_licence": info["vrm_licence"]})
        vl = info["vrm_licence"]
        if vl and vl.get("refusal"):
            licence_refusals.append({"path": path, "field": vl["refusal"]["field"], "value": vl["refusal"]["value"]})

    return {
        "ok": True,
        "undeclared": undeclared,
        "missing": missing,
        "duplicates": duplicates,
        "parts": parts,
        "licence_refusals": licence_refusals,
        "gaps": gaps,
    }


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
    if len(argv) == 3 and argv[1] == "content":
        req = json.load(sys.stdin)
        json.dump(content_report(argv[2], req.get("declared", [])), sys.stdout, ensure_ascii=False)
        return 0
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
