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
            "parts": [{"path","sha256","licence_source","vrm_licence"?}],
            "licence_refusals": [...], "licence_unknown": [...],
            "licence_undeclared": [...], "gaps": [...]}
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


def extract_vrm_meta(raw):
    """(vrm_version, meta_dict) from extensions.VRM.meta / extensions.
    VRMC_vrm.meta, or None when the GLB carries neither -- legal
    DRAFT-v3.md Part 6 G4's "unknown" case (flagged, never refused: not
    every .vrm file carries a meta block)."""
    doc = parse_glb_json_chunk(raw)
    if not isinstance(doc, dict):
        return None
    exts = doc.get("extensions")
    if not isinstance(exts, dict):
        return None
    vrm0 = exts.get("VRM")
    if isinstance(vrm0, dict) and isinstance(vrm0.get("meta"), dict):
        return "0.x", vrm0["meta"]
    vrm1 = exts.get("VRMC_vrm")
    if isinstance(vrm1, dict) and isinstance(vrm1.get("meta"), dict):
        return "1.0", vrm1["meta"]
    return None


def rule_vrm_licence_refused(vrm_version, meta):
    """
    manifest.md §2.7.3 / marketplace legal DRAFT-v3.md Part 6 G4, D8
    (widened): refuse on the decided redistribution refusal OR an
    author-only/named-people avatar permission, reading EACH SPEC'S OWN
    DEFAULT for a field the file leaves out -- never "absent means
    allowed". Defaults are astra-companion's own (src/vrm/meta.rs:80-100,
    licence_of/redistribution_of, the implementation this gate ports):
      VRM 1.0 absent avatarPermission -> "onlyAuthor"; absent/non-true
        allowRedistribution -> prohibited (the meta schema's own default).
      VRM 0.x absent allowedUserName -> "OnlyAuthor"; absent licenseName ->
        prohibited (UniVRM's default).
    Returns {"refused", "field", "value", "defaulted"}.
    """
    if vrm_version == "0.x":
        license_name = meta.get("licenseName")
        if license_name is None:
            return {"refused": True, "field": "extensions.VRM.meta.licenseName", "value": None, "defaulted": True}
        if license_name == "Redistribution_Prohibited":
            return {"refused": True, "field": "extensions.VRM.meta.licenseName", "value": license_name, "defaulted": False}
        allowed_user = meta.get("allowedUserName")
        if allowed_user is None:
            return {"refused": True, "field": "extensions.VRM.meta.allowedUserName", "value": None, "defaulted": True}
        if allowed_user in ("OnlyAuthor", "ExplicitlyLicensedPerson"):
            return {"refused": True, "field": "extensions.VRM.meta.allowedUserName", "value": allowed_user, "defaulted": False}
        return {"refused": False, "field": None, "value": None, "defaulted": False}
    if vrm_version == "1.0":
        allow_redist = meta.get("allowRedistribution")
        if allow_redist is not True:
            return {
                "refused": True, "field": "extensions.VRMC_vrm.meta.allowRedistribution",
                "value": allow_redist, "defaulted": "allowRedistribution" not in meta,
            }
        avatar_perm = meta.get("avatarPermission")
        if avatar_perm is None:
            return {"refused": True, "field": "extensions.VRMC_vrm.meta.avatarPermission", "value": None, "defaulted": True}
        if avatar_perm in ("onlyAuthor", "onlySeparatelyLicensedPerson"):
            return {"refused": True, "field": "extensions.VRMC_vrm.meta.avatarPermission", "value": avatar_perm, "defaulted": False}
        return {"refused": False, "field": None, "value": None, "defaulted": False}
    raise NotImplementedError(vrm_version)


# legal DRAFT-v3.md Part 6 G5: kept with the part so the install sheet and
# the public card can show the whole licence line. Raw keys the file
# carries -- an absent key's spec default is applied only by
# rule_vrm_licence_refused above, never fabricated here (that is the
# install sheet's own display concern).
VRM_GATE_FIELDS = {"0.x": ("allowedUserName", "licenseName"), "1.0": ("avatarPermission", "allowRedistribution")}
VRM_USAGE_FIELDS = {
    "0.x": ("violentUssageName", "sexualUssageName", "commercialUssageName"),
    "1.0": ("allowExcessivelyViolentUsage", "allowExcessivelySexualUsage", "allowPoliticalOrReligiousUsage", "allowAntisocialOrHateUsage"),
}


def vrm_gate(raw):
    """The full G4/G5 verdict for one .vrm's (or a readable .astrachar
    body's) bytes. Returns {"status": "ok"|"refused"|"unknown",
    "vrm_licence": {"vrm_version","fields"}|None, "refusal": {...}|None}.
    "unknown" is never a refusal: G4 says it is flagged
    (F_CONTENT_VRM_META_UNKNOWN) and passes only with the character
    checkbox and the licence line, which is the publish form's job."""
    extracted = extract_vrm_meta(raw)
    if extracted is None:
        return {"status": "unknown", "vrm_licence": None, "refusal": None}
    vrm_version, meta = extracted
    verdict = rule_vrm_licence_refused(vrm_version, meta)
    fields = {k: meta[k] for k in VRM_GATE_FIELDS[vrm_version] + VRM_USAGE_FIELDS[vrm_version] if k in meta}
    vrm_licence = {"vrm_version": vrm_version, "fields": fields}
    if verdict["refused"]:
        refusal = {"field": verdict["field"], "value": verdict["value"], "defaulted": verdict["defaulted"]}
        return {"status": "refused", "vrm_licence": vrm_licence, "refusal": refusal}
    return {"status": "ok", "vrm_licence": vrm_licence, "refusal": None}


def read_astrachar_body_vrm(outer_zip, entry_name):
    """The body inside a .astrachar bundle, gated the same as a bare .vrm,
    WHEN the bundle's format is readable (astra-companion docs/character-
    files-and-2d-editor.md §1.3/§1.4). Returns (gate_or_None,
    gap_reason_or_None) -- a gap (the bundle itself unreadable) is never a
    refusal; `gate` is `vrm_gate`'s own result when it is."""
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
        return vrm_gate(body_bytes), None
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
            gate = vrm_gate(raw) if ext == ".vrm" else None
            parts_by_path[info.filename] = {"sha256": hashlib.sha256(raw).hexdigest(), "gate": gate}

        for entry in declared:
            path = entry.get("path") if isinstance(entry, dict) else None
            if not isinstance(path, str) or path not in parts_by_path:
                continue
            if pathlib.PurePosixPath(path).suffix.lower() == ".astrachar":
                gate, gap = read_astrachar_body_vrm(z, path)
                if gap:
                    gaps.append({"path": path, "reason": gap})
                parts_by_path[path]["gate"] = gate

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

    declared_by_path = {e["path"]: e for e in declared if isinstance(e, dict) and isinstance(e.get("path"), str)}
    parts = []
    licence_refusals = []
    licence_unknown = []
    licence_undeclared = []
    for path in sorted(declared_set & content_set):
        info = parts_by_path[path]
        gate = info["gate"]
        gate_status = gate["status"] if gate else None
        vrm_licence = gate["vrm_licence"] if gate and gate_status != "unknown" else None
        if gate_status == "refused":
            licence_refusals.append({"path": path, "field": gate["refusal"]["field"], "value": gate["refusal"]["value"]})
        if gate_status == "unknown":
            licence_unknown.append(path)
        declared_licence = declared_by_path.get(path, {}).get("licence")
        if vrm_licence is not None:
            licence_source = "vrm"
        elif declared_licence:
            licence_source = "declared"
        else:
            licence_source = None
            licence_undeclared.append(path)
        part = {"path": path, "sha256": info["sha256"], "licence_source": licence_source}
        if vrm_licence is not None:
            part["vrm_licence"] = vrm_licence
        parts.append(part)

    return {
        "ok": True,
        "undeclared": undeclared,
        "missing": missing,
        "duplicates": duplicates,
        "parts": parts,
        "licence_refusals": licence_refusals,
        "licence_unknown": licence_unknown,
        "licence_undeclared": licence_undeclared,
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
