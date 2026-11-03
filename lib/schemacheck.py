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
            "licence_refusals": [...], "licence_conflicts": [...], "licence_unknown": [...],
            "licence_undeclared": [...], "format_refusals": [{"path","detail"}, ...],
            "bundle_refusals": [{"path","code","detail"}, ...]}
         | {"ok": false, "error": "..."}
    python3 lib/schemacheck.py zipcheck ZIP
        -> {"ok": true} | {"ok": false, "error": "..."}   (Zip Cloaking, see verify_zip_headers)
    python3 lib/schemacheck.py files ZIP
        -> {"ok": true, "files": {"<path in zip>": "<sha256>", ...}} | {"ok": false, "error": "..."}

`manifest` also returns `text`, the member's own UTF-8 text, so that
gi-probe's `validate-descriptor` reads the bytes the author shipped rather
than this file's re-serialisation of them.

`files` is the catalogue's own reading of every file in the zip: its name
(`\\` read as `/`, as gi-probe's check reads entry names) and the SHA-256
of its inflated bytes. built_on, code_changed, the game files' digests, the
Link skill and schema digests all come from it; gi-probe 0.5.0 reports none
of them at the top level. It holds the zip to the launcher's own default
limits (astra-game-launcher v0.5.0 src/package.rs `Limits::default`: 20 000
entries, 1 GiB inflated), so a zip gi-probe opened is always read whole.

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
a loose directory. Both read BOTH VRM metas of a file that carries a 0.x and
a 1.0 block, and refuse a disagreement E_CONTENT_LICENCE_CONFLICT -- the two
verdicts differing, an unknown against an allowed included (O-2/O-2b,
AstraPlugins 516ba38); fixtures/vrm-conflict/ holds that commit's goldens.
The gate itself runs by the file's own glTF extensions, never by a `.vrm`
name: an avatar (VRM, VRMC_vrm) in any part, an animation
(VRMC_vrm_animation) never, a plain glTF/GLB only in a "character" part. An
unrecognised licence or permission token is never read as allowed -- it is
"unknown" (O-2b/O-2c), flagged the same way a no-meta file is.

Every rule the games gate shares with the content catalogue (AstraPlugins
#129) is CALLED from the content contract's own reference checker, vendored
under lib/vendor/astraplugins/tools/ (check-content-goldens.py with
contentlite.py), never restated here: the text-glTF sniff and the GLB name
rule over EVERY entry, the `%?#\\` uri rule, the 16 MiB / depth-128 / 32 MiB
caps and the .gltf byte-order-mark rule, and a whole embedded
.astrachar/.astrapack through `ingest_bundle` (walk_zip, ingest-v1.md §3
steps 1-8, 10, 11, 12), its refusal keeping content's own code.
test/content.test.mjs runs every testdata/games/content/releases/ golden
(vendored) through this file and requires its vectors.json verdict.
"""

from __future__ import annotations

import codecs
import datetime
import hashlib
import io
import json
import pathlib
import posixpath
import re
import struct
import sys
import tomllib
import zipfile
import zlib

HERE = pathlib.Path(__file__).resolve().parent
VENDOR = HERE / "vendor" / "astraplugins"
sys.path.insert(0, str(VENDOR / "tools"))
import schemalite  # noqa: E402


def _load_content_checker():
    import importlib.util
    spec = importlib.util.spec_from_file_location("check_content_goldens", VENDOR / "tools" / "check-content-goldens.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# The content contract's own reference checker (AstraPlugins
# spec/content/ingest-v1.md §3-§4), vendored byte for byte with
# tools/contentlite.py: every rule the games catalogue shares with the
# content catalogue is CALLED from it, never restated here (manifest.md
# §2.7.1, §2.7.3 at AstraPlugins #129).
CG = _load_content_checker()

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
        return {"ok": True, "manifest": _jsonable(parsed, "$"), "text": text}
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


class GltfFormatError(ValueError):
    """`E_CONTENT_FORMAT` (the content catalogue's ingest-v1.md §3 step 10,
    adopted so the two gates agree on every file): a GLB that is not whole,
    glTF JSON that does not parse or names a member twice, or an external
    reference. Mirrors AstraPlugins tools/check-games-goldens.py at 4976d60
    (spec/games-vrm-conflict-kindkeys)."""


def _no_duplicate_members(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise GltfFormatError(f"the glTF JSON names {key!r} twice")
        out[key] = value
    return out


def _strict_json(data: bytes):
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicate_members)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise GltfFormatError(f"the glTF JSON does not parse: {e}") from None
    except RecursionError:
        # thousands of levels deep: the parser's own stack gives out first --
        # a file this gate refuses, never a crash of the gate itself
        raise GltfFormatError("the glTF JSON does not parse: it nests too deep to read") from None


def _cap_problem(path, raw: bytes):
    """The content catalogue's own `gltf_problem`: a JSON chunk or `.gltf`
    over 16 MiB (checked before parsing), JSON that does not parse
    (RecursionError included) or is not an object, nesting deeper than 128."""
    return CG.gltf_problem(path or "", raw)


def parse_glb_strict(raw: bytes) -> dict:
    """A GLB's JSON chunk, or GltfFormatError. The GLB must be whole: its
    header's total length equals the file's size and its first chunk is JSON
    and ends inside the file, so a chunk declared past EOF is never read as
    whatever bytes happen to be there. The JSON must parse with no member
    named twice -- one reader's `allowRedistribution: false` is another's
    `true`, and JSON that does not parse must never fall through to "plain",
    which an animation part does not judge."""
    if len(raw) < 20 or raw[0:4] != b"glTF":
        raise GltfFormatError("not a GLB")
    total = int.from_bytes(raw[8:12], "little")
    if total != len(raw):
        raise GltfFormatError(f"the GLB header says {total} bytes and the file has {len(raw)}")
    if raw[16:20] != b"JSON":
        raise GltfFormatError("the GLB's first chunk is not JSON")
    chunk_len = int.from_bytes(raw[12:16], "little")
    if 20 + chunk_len > len(raw):
        raise GltfFormatError("the GLB's JSON chunk runs past the end of the file")
    why = _cap_problem(None, raw)
    if why:
        raise GltfFormatError(f"the GLB's {why}" if why.startswith("its ") else f"the GLB has {why}")
    doc = _strict_json(raw[20:20 + chunk_len])
    if not isinstance(doc, dict):
        raise GltfFormatError("the glTF JSON is not an object")
    return doc


class _AnyFile:
    """`present` when there is no release to look in: every relative name is
    taken to exist, so only the shape of the uri is judged."""

    def __contains__(self, _name) -> bool:
        return True


def gltf_uri_problem(raw: bytes, doc: dict, path, present) -> str | None:
    """No external reference: the content catalogue's own `uri_refusal`
    (with AstraPlugins #131). In a GLB every `images[].uri` and
    `buffers[].uri` is a `data:` URI; in a `.gltf` a `data:` URI or a
    relative path, percent-decoded exactly once -- `Base%20Color.png` names
    `Base Color.png` -- with no raw `?`, `#` or `\\`, no malformed or double
    escape, and once decoded no scheme, no `..` and no leading `/`, naming a
    file the release holds. `images`/`buffers` must be arrays of objects
    (content's `gltf_array_shape_refusal`, which replaced the guard this
    file kept). No own-part test: a game integration's part is one file."""
    where = present if present is not None and path is not None else _AnyFile()
    return CG.uri_refusal(path or "", raw, where, {})


def gltf_format_problem(raw: bytes, path=None, present=None) -> str | None:
    """Every GLB (by its magic) and every `.gltf`, in any part and of any
    class: the reason it is `E_CONTENT_FORMAT`, or None. Runs BEFORE
    classification."""
    is_glb = raw[:4] == b"glTF"
    if not is_glb and not (path is not None and path.lower().endswith(".gltf")):
        return None
    if not is_glb:
        # glTF 2.0 is UTF-8 JSON without a byte-order mark: any BOM on a .gltf
        # is refused by the content catalogue's own rule -- on a .gltf only
        why = CG.bom_refusal(path, raw) or _cap_problem(path, raw)
        if why:
            return why
    try:
        doc = parse_glb_strict(raw) if is_glb else _strict_json(raw)
    except GltfFormatError as e:
        return str(e)
    if not isinstance(doc, dict):
        return "the glTF JSON is not an object"
    return gltf_uri_problem(raw, doc, path, present)


def extract_vrm_metas_doc(doc):
    """extract_vrm_metas over an already-parsed glTF JSON document (a GLB's
    JSON chunk or a `.gltf` file's whole text)."""
    if not isinstance(doc, dict):
        return {}
    exts = doc.get("extensions")
    if not isinstance(exts, dict):
        return {}
    out = {}
    vrm0 = exts.get("VRM")
    if isinstance(vrm0, dict) and isinstance(vrm0.get("meta"), dict):
        out["0.x"] = vrm0["meta"]
    vrm1 = exts.get("VRMC_vrm")
    if isinstance(vrm1, dict) and isinstance(vrm1.get("meta"), dict):
        out["1.0"] = vrm1["meta"]
    return out


def extract_vrm_metas(raw):
    """{"0.x": meta_dict, "1.0": meta_dict} for WHICHEVER of
    extensions.VRM.meta / extensions.VRMC_vrm.meta the GLB carries -- both,
    when it carries both, never only the first one found (O-2: the earlier
    `extract_vrm_meta` returned on the first match, so a file whose VRM 0.x
    meta allowed and whose VRM 1.0 meta prohibited passed the gate
    outright). Empty when it carries neither -- legal DRAFT-v3.md Part 6
    G4's "unknown" case (flagged, never refused: not every .vrm file
    carries a meta block). Mirrors AstraPlugins tools/check-games-goldens.py
    at 516ba38 (spec/games-vrm-conflict-kindkeys)."""
    return extract_vrm_metas_doc(parse_glb_json_chunk(raw))


def _reading(value, allowed, prohibited, default_prohibited=True):
    """One field's reading: "allowed", "prohibited" or "unknown"."""
    if value is None:
        return "prohibited" if default_prohibited else "unknown"
    if not isinstance(value, str):
        return "prohibited"
    if allowed(value):
        return "allowed"
    if value in prohibited:
        return "prohibited"
    return "unknown"


def rule_vrm_licence_refused(vrm_version, meta):
    """manifest.md §2.7.3's HARD VRM GATE / marketplace legal DRAFT-v3.md
    Part 6 G4, D8 (widened): one meta's verdict, read exactly as the content
    contract's ingest-v1.md §4.2 and astra-companion's `src/vrm/meta.rs`
    (`licence_of`, `redistribution_of`) read it, so that the games and
    content gates agree on every file. Each meta gives two readings:

      VRM 1.0 `allowRedistribution`: `true` allowed; `false`, absent or not
        a bool (the string "true" included) prohibited.
      VRM 0.x `licenseName`: `CC0` or any token beginning `CC_` allowed;
        `Redistribution_Prohibited`, absent or not a string prohibited;
        `Other` or ANY other token unknown (the terms are elsewhere).
      VRM 1.0 `avatarPermission` / 0.x `allowedUserName`: `everyone` /
        `Everyone` allowed; `onlyAuthor`, `onlySeparatelyLicensedPerson` /
        `OnlyAuthor`, `ExplicitlyLicensedPerson`, absent (the spec default)
        or not a string prohibited; ANY other token unknown.

    The verdict is "prohibited" if either reading is, else "unknown" if
    either is, else "allowed". An unrecognised token is never allowed.
    Returns {"verdict", "refused", "field", "value", "defaulted"}: "field"
    names the reading that decided a prohibited or unknown verdict (the
    redistribution field first), "value" its literal value, and
    "defaulted" whether the field was absent and a spec default decided."""
    if vrm_version == "0.x":
        fields = (
            ("extensions.VRM.meta.licenseName", "licenseName",
             _reading(meta.get("licenseName"), lambda v: v == "CC0" or v.startswith("CC_"), ("Redistribution_Prohibited",))),
            ("extensions.VRM.meta.allowedUserName", "allowedUserName",
             _reading(meta.get("allowedUserName"), lambda v: v == "Everyone", ("OnlyAuthor", "ExplicitlyLicensedPerson"))),
        )
    elif vrm_version == "1.0":
        redist = meta.get("allowRedistribution")
        fields = (
            ("extensions.VRMC_vrm.meta.allowRedistribution", "allowRedistribution",
             "allowed" if redist is True else "prohibited"),
            ("extensions.VRMC_vrm.meta.avatarPermission", "avatarPermission",
             _reading(meta.get("avatarPermission"), lambda v: v == "everyone", ("onlyAuthor", "onlySeparatelyLicensedPerson"))),
        )
    else:
        raise NotImplementedError(vrm_version)
    for wanted in ("prohibited", "unknown"):
        for field, key, reading in fields:
            if reading == wanted:
                return {"verdict": wanted, "refused": wanted == "prohibited", "field": field,
                        "value": meta.get(key), "defaulted": key not in meta}
    return {"verdict": "allowed", "refused": False, "field": None, "value": None, "defaulted": False}


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


def rule_vrm_conflict(meta0x, meta1_0):
    """manifest.md §2.7.3 (AstraPlugins 516ba38) / the content contract's
    ingest-v1.md §4.2: a file carrying BOTH a VRM 0.x and a VRM 1.0 meta is
    judged on EACH (O-2 -- a reader that stops at the first meta it finds
    would pass a file whose 0.x meta allows and whose 1.0 meta prohibits).
    If the two verdicts differ -- an unknown against an allowed included --
    it is refused as E_CONTENT_LICENCE_CONFLICT. Usage flags are display,
    never compared here, exactly as the content gate does not compare them.

    Returns {"field", "detail"} or None when the two verdicts agree."""
    v0 = rule_vrm_licence_refused("0.x", meta0x)
    v1 = rule_vrm_licence_refused("1.0", meta1_0)
    if v0["verdict"] != v1["verdict"]:
        def side(v):
            return v["verdict"] + (f" ({v['field']})" if v["field"] else "")
        return {"field": "gate verdict", "detail": f"VRM 0.x reads {side(v0)}; VRM 1.0 reads {side(v1)}"}
    return None


AVATAR_EXTENSIONS = ("VRM", "VRMC_vrm")
ANIMATION_EXTENSION = "VRMC_vrm_animation"


def gltf_document(raw, path=None):
    """The glTF JSON of a GLB (by its magic, whatever it is called) or of a
    `.gltf` text file, or None for anything else."""
    if raw[:4] == b"glTF":
        return parse_glb_json_chunk(raw)
    if path is not None and path.lower().endswith(".gltf") and _is_gltf_text(raw):
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
    return None


def gltf_class(doc):
    """The content contract's ingest-v1.md §4 classification, by the glTF
    JSON's extensions and never by the file's name: "avatar" when an avatar
    extension (`VRM`, `VRMC_vrm`) appears in `extensions` or
    `extensionsUsed`; "animation" when `VRMC_vrm_animation` does and no
    avatar extension does; "plain" otherwise."""
    names = set()
    if isinstance(doc, dict):
        if isinstance(doc.get("extensions"), dict):
            names.update(doc["extensions"])
        if isinstance(doc.get("extensionsUsed"), list):
            names.update(n for n in doc["extensionsUsed"] if isinstance(n, str))
    if any(n in names for n in AVATAR_EXTENSIONS):
        return "avatar"
    if ANIMATION_EXTENSION in names:
        return "animation"
    return "plain"


def vrm_gate(raw, path=None, present=None):
    """The full G4/G5 verdict for one glTF's bytes (a GLB by its magic, or a
    `.gltf` text file), reading BOTH a VRM 0.x and a VRM 1.0 meta when it
    carries both (O-2). Returns {"status": "ok"|"refused"|"conflict"|"unknown"|"format",
    "vrm_licence": {"vrm_version","fields"}|None, "refusal": {...}|None}.
    "unknown" is no VRM meta of either spec, meta that cannot be read, or a
    meta whose verdict is unknown (an unrecognised licence or permission
    token). It is NEVER a refusal: G4 says it is flagged
    (F_CONTENT_VRM_META_UNKNOWN) and passes only with the character checkbox
    and a declared licence (G5); `refusal` then names the deciding field
    when there is one. "conflict" is E_CONTENT_LICENCE_CONFLICT
    (`rule_vrm_conflict`) and runs before any single-meta verdict. "format" is
    E_CONTENT_FORMAT (`gltf_format_problem`) and runs before even that --
    AstraPlugins 4976d60: a GLB that is not whole, glTF JSON that does not
    parse or names a member twice, or an external image/buffer uri, must
    never fall through to a lenient parse that reads it as "unknown" or
    "plain"."""
    problem = gltf_format_problem(raw, path, present)
    if problem is not None:
        return {"status": "format", "vrm_licence": None, "refusal": {"field": "format", "detail": problem}}
    doc = gltf_document(raw, path)
    metas = extract_vrm_metas_doc(doc)
    if not metas:
        return {"status": "unknown", "vrm_licence": None, "refusal": None}
    if "0.x" in metas and "1.0" in metas:
        conflict = rule_vrm_conflict(metas["0.x"], metas["1.0"])
        if conflict is not None:
            return {"status": "conflict", "vrm_licence": None, "refusal": conflict}
    # Both present and agreeing, or only one present: VRM 1.0 takes display
    # precedence when both exist, the same order astra-companion's own
    # `licence_of` reads them in ("a file carrying both is read as 1.0").
    vrm_version = "1.0" if "1.0" in metas else "0.x"
    meta = metas[vrm_version]
    verdict = rule_vrm_licence_refused(vrm_version, meta)
    fields = {k: meta[k] for k in VRM_GATE_FIELDS[vrm_version] + VRM_USAGE_FIELDS[vrm_version] if k in meta}
    vrm_licence = {"vrm_version": vrm_version, "fields": fields}
    if verdict["verdict"] == "unknown":
        return {"status": "unknown", "vrm_licence": None,
                "refusal": {"field": verdict["field"], "value": verdict["value"], "defaulted": verdict["defaulted"]}}
    if verdict["refused"]:
        refusal = {"field": verdict["field"], "value": verdict["value"], "defaulted": verdict["defaulted"]}
        return {"status": "refused", "vrm_licence": vrm_licence, "refusal": refusal}
    return {"status": "ok", "vrm_licence": vrm_licence, "refusal": None}


# ── content by bytes, for EVERY entry (manifest.md §2.7.1, AstraPlugins #129) ──
# A name never decides whether a file is content: a GLB under any name but
# .vrm/.glb/.vrma, a text glTF under any name but .gltf (the content
# catalogue's own `is_gltf_json`), or a bundle -- a zip whose last entry is
# astrachar.json, by content's own `walk_zip` -- under any name but
# .astrachar/.astrapack is E_CONTENT_FORMAT. Three deliberate differences
# from the content catalogue, because a game integration ships arbitrary
# files: a glTF's top-level asset is an object (three.js reads asset.version);
# a UTF-16/32 byte-order mark is not refused (localisation files carry one) --
# such a text is sniffed as what it decodes to, which only over-refuses
# (three.js and fetch().text() decode UTF-8 whatever the mark); and the
# per-character sniff is bounded -- an asset key with an object value is
# looked for first at C speed, the sniff reads at most 64 MiB per release,
# and above 16 MiB (or past that budget) the key alone refuses.

BUNDLE_EXTS = (".astrachar", ".astrapack")
_BOM_CODECS = dict(CG.UNICODE_BOMS)  # content's own mark -> encoding map, UTF-32 first (#132)
_ASSET_KEY = re.compile(rb'"(?:a|\\u0061)(?:s|\\u0073)(?:s|\\u0073)(?:e|\\u0065)(?:t|\\u0074)"')
# ... whose value is an object: three.js reads asset.version, so a glTF's asset is
# one (AstraPlugins #129 15dab18, a games-only difference): {"asset": "hero.png"}
# is a game's data file, not a glTF
_ASSET_OBJ = re.compile(_ASSET_KEY.pattern + rb"[ \t\r\n]*:[ \t\r\n]*\{")
_WS_RUN = re.compile(rb"[ \t\r\n]+")
_STREAM_CHUNK = 1024 * 1024


def _bom_of(raw: bytes):
    for bom, codec in _BOM_CODECS.items():
        if raw.startswith(bom):
            return bom, codec
    return b"", None


def sniff_text(raw: bytes) -> bytes:
    """The text decoded by its byte-order mark, as UTF-8. Sniffing that only
    ever over-refuses: a browser's fetch().text() and three.js decode UTF-8
    whatever the mark, so a UTF-16 glTF does not load there at all; the margin
    covers a reader that does detect the encoding (Python's json.loads on
    bytes does) -- AstraPlugins #129 e72b05d corrected this rationale."""
    bom, codec = _bom_of(raw)
    return raw[len(bom):].decode(codec, "replace").encode("utf-8") if codec else raw


# The per-character sniff reads at most this much of one release; past it, a
# JSON-looking file whose bytes name an asset key is refused unread, as one
# over 16 MiB is (AstraPlugins #129 254e60b: twenty 16 MiB files of
# {"":0,"":0,...} held the gate for 102 s; content's sniff reads ~4 MiB/s).
SNIFF_BUDGET = 64 * 1024 * 1024


class ReleaseBudget:
    """What one release may make the gate spend: the bytes the per-character
    sniff reads (SNIFF_BUDGET), and the glTF JSON it may parse -- 32 MiB per
    release, embedded bundles included."""

    def __init__(self):
        self.sniffed = 0
        self.gltf_json = 0


def is_text_gltf(raw: bytes, budget=None) -> bool:
    """The content catalogue's own text-glTF sniff over the decoded text.
    First the C-speed test: no asset key anywhere (plain or \\u-escaped) is no
    glTF, and the slow sniff never runs. Above 16 MiB, or once the release's
    SNIFF_BUDGET is spent, the key alone refuses."""
    text = sniff_text(raw)
    body = text[len(CG.UTF8_BOM):] if text.startswith(CG.UTF8_BOM) else text
    if body.lstrip(b" \t\r\n")[:1] != b"{" or _ASSET_OBJ.search(body) is None:
        return False
    if len(raw) > CG.MAX_GLTF_JSON:
        return True
    budget = budget if budget is not None else ReleaseBudget()
    if budget.sniffed + len(text) > SNIFF_BUDGET:
        return True
    budget.sniffed += len(text)
    return CG.is_gltf_json(text)


def _json_looking(head: bytes) -> bool:
    text = sniff_text(head)
    text = text[len(CG.UTF8_BOM):] if text.startswith(CG.UTF8_BOM) else text
    first = text.lstrip(b" \t\r\n")[:1]
    return first in (b"{", b"")  # b"": only whitespace so far -- look at the whole file


def _stream_search(z, info, pattern, decode: bool) -> bool:
    """Does the entry's (decoded) text match `pattern`, read in chunks? For
    entries too large to hold whole."""
    with z.open(info) as f:
        first = f.read(4)
        bom, codec = _bom_of(first) if decode else (b"", None)
        dec = codecs.getincrementaldecoder(codec)("replace") if codec else None
        pending, tail = first[len(bom):], b""
        while True:
            chunk = pending + f.read(_STREAM_CHUNK)
            pending = b""
            if not chunk:
                return False
            data = dec.decode(chunk).encode("utf-8") if dec else chunk
            # whitespace runs collapse to one space, so a key, its colon and its
            # brace never lie further apart than the overlap below, however much
            # whitespace a file puts between them
            buf = _WS_RUN.sub(b" ", tail + data)
            if pattern.search(buf):
                return True
            tail = buf[-64:]


_BUNDLE_MANIFEST_NAME = re.compile(re.escape(b"astrachar.json"))


def is_bundle_bytes(raw: bytes) -> bool:
    """ingest-v1.md §3: a bundle is a zip whose LAST entry is astrachar.json,
    read with content's own walk_zip -- only an archive Astra's importer would
    open as a bundle counts."""
    if not _is_zip(raw[:4]) or b"astrachar.json" not in raw:
        return False
    try:
        order = json.loads(CG.walk_zip(raw)["\0order"])
    except Exception:  # noqa: BLE001 -- refused or unreadable: no importer opens it as a bundle
        return False
    return bool(order) and order[-1] == "astrachar.json"


def _read_whole(z, info, cap):
    with z.open(info) as f:
        raw = f.read(cap + 1)
    return raw if len(raw) <= cap else None


def name_problem(z, info, head: bytes, raw, budget=None) -> str | None:
    """Why an entry's name and its bytes disagree (E_CONTENT_FORMAT), or None.
    `head` is its first bytes; `raw` its whole bytes when already read."""
    name = info.filename
    low = name.lower()
    if head[:4] == CG.GLB_MAGIC:
        return None if CG.name_matches_magic(name, head) else "a GLB (it begins with glTF) named something not .vrm, .glb or .vrma"
    if not low.endswith(".gltf") and _json_looking(head):
        if info.file_size > CG.MAX_GLTF_JSON:
            if _stream_search(z, info, _ASSET_OBJ, decode=True):
                return f"a JSON text over 16 MiB ({info.file_size} bytes) that names an asset key, named something not .gltf"
        else:
            data = raw if raw is not None else _read_whole(z, info, CG.MAX_GLTF_JSON)
            if data is not None and is_text_gltf(data, budget):
                return "a text glTF (a JSON object with a top-level asset member) named something not .gltf"
    if _is_zip(head[:4]) and not low.endswith(BUNDLE_EXTS) and info.file_size <= ASTRACHAR_CAP \
            and _stream_search(z, info, _BUNDLE_MANIFEST_NAME, decode=False):
        data = raw if raw is not None else _read_whole(z, info, ASTRACHAR_CAP)
        if data is not None and is_bundle_bytes(data):
            return "a content bundle (a zip whose last entry is astrachar.json) named something not .astrachar or .astrapack"
    return None


# ── a game's own archives, one level deep (manifest.md §2.7.1, AstraPlugins #129 f3e2bd0) ──
# A zip that is not a content bundle -- a .jar, a mod .zip, by its PK magic and
# never by its name -- is opened ONE level deep with the content contract's own
# walk_zip, every cloak check included, under game-archive limits (65,536
# entries, 512 MiB uncompressed, no Stored-only rule). Every GLB, text glTF and
# bundle in it is judged exactly as a top-level entry is, and is a part to
# DECLARE as `<archive path>!<inner path>`. Cloaking is refused; anything else
# that stops the walk publishes flagged F_CONTENT_ARCHIVE_UNSCANNED, and so
# does an archive inside an archive.

CONTAINER_MAX_ENTRIES = 65_536
CONTAINER_MAX_TOTAL = 512 * 1024 * 1024
CLOAK_CODES = ("E_ZIP_HEADERS_INCONSISTENT", "E_ZIP_END_RECORD")
INNER_PART_EXTS = CG.GLB_EXTS + (".gltf",) + BUNDLE_EXTS
_HEAD = 64


def _decoded_chunks(raw: bytes, size: int):
    """In-memory bytes as UTF-8 text a piece at a time: a UTF-16/32 text
    decoded by its byte-order mark, anything else as it is -- never whole."""
    bom, codec = _bom_of(raw)
    if codec is None:
        for at in range(0, len(raw), size):
            yield raw[at:at + size]
        return
    dec = codecs.getincrementaldecoder(codec)("replace")
    for at in range(len(bom), len(raw), size):
        yield dec.decode(raw[at:at + size]).encode("utf-8")
    yield dec.decode(b"", final=True).encode("utf-8")


def _first_char_bytes(raw: bytes) -> bytes:
    first = True
    for piece in _decoded_chunks(raw, _HEAD):
        if first and piece.startswith(CG.UTF8_BOM):
            piece = piece[len(CG.UTF8_BOM):]
        first = first and not piece
        rest = piece.lstrip(b" \t\r\n")
        if rest:
            return rest[:1]
    return b""


def _names_key_bytes(raw: bytes, pattern) -> bool:
    if _bom_of(raw)[1] is None:
        return pattern.search(raw) is not None
    tail = b""
    for piece in _decoded_chunks(raw, _STREAM_CHUNK):
        window = tail + piece
        if pattern.search(window):
            return True
        tail = window[-4096:]
    return False


def name_problem_bytes(key: str, raw: bytes, budget) -> str | None:
    """name_problem for in-memory bytes (an archive's member): the same rules,
    reading only as much of the text as each needs."""
    low = key.lower()
    if raw[:4] == CG.GLB_MAGIC:
        return None if CG.name_matches_magic(key, raw) else "a GLB (it begins with glTF) named something not .vrm, .glb or .vrma"
    if not low.endswith(".gltf") and _first_char_bytes(raw) == b"{" and _names_key_bytes(raw, _ASSET_OBJ):
        if len(raw) > CG.MAX_GLTF_JSON:
            return f"a JSON text over 16 MiB ({len(raw)} bytes) that names an asset key, named something not .gltf"
        if is_text_gltf(raw, budget):
            return "a text glTF (a JSON object with a top-level asset member) named something not .gltf"
    if _is_zip(raw[:4]) and not low.endswith(BUNDLE_EXTS) and is_bundle_bytes(raw):
        return "a content bundle (a zip whose last entry is astrachar.json) named something not .astrachar or .astrapack"
    return None


def walk_container(raw: bytes) -> dict:
    """{"status": "ok", "files"} | {"status": "unscanned", "reason"} |
    {"status": "refused", "code", "detail"}: content's walk_zip under the
    game-archive limits. Only cloaking, an archive the reader cannot follow,
    and a glTF JSON total over 32 MiB refuse."""
    saved = CG.MAX_ENTRIES, CG.MAX_TOTAL, CG.STORED_ONLY
    CG.MAX_ENTRIES, CG.MAX_TOTAL, CG.STORED_ONLY = CONTAINER_MAX_ENTRIES, CONTAINER_MAX_TOTAL, ()
    try:
        files = CG.walk_zip(raw)
    except CG.Refusal as r:
        if r.code in CLOAK_CODES and "zip64" not in r.detail:
            return {"status": "refused", "code": r.code, "detail": r.detail}
        if r.code == "E_ARCHIVE_TOO_LARGE" and "glTF JSON" in r.detail:
            return {"status": "refused", "code": "E_CONTENT_FORMAT", "detail": r.detail}
        return {"status": "unscanned", "reason": f"{r.code}: {r.detail}"}
    except Exception as e:  # noqa: BLE001 -- an archive content's reader cannot follow: fail closed
        return {"status": "refused", "code": "E_CONTENT_FORMAT", "detail": f"the archive cannot be read ({type(e).__name__}: {e})"}
    finally:
        CG.MAX_ENTRIES, CG.MAX_TOTAL, CG.STORED_ONLY = saved
    files.pop("\0order", None)
    return {"status": "ok", "files": {p: b for p, b in files.items() if not p.endswith("/")}}


def _content_typed_bytes(key: str, raw: bytes) -> bool:
    sniff = CONTENT_EXT_MAGIC.get(pathlib.PurePosixPath(key).suffix.lower())
    return sniff is not None and sniff(raw[:32])


def is_inner_part(key: str, raw: bytes) -> bool:
    """A GLB, a .gltf or a bundle inside an archive: a part to declare."""
    return key.lower().endswith(INNER_PART_EXTS) and _content_typed_bytes(key, raw)


# ── an embedded .astrachar / .astrapack (manifest.md §2.7.3) ──────────────
# Judged by the content contract's OWN `ingest_bundle`: walk_zip and
# ingest-v1.md §3 steps 1-8, 10, 11 and step 12's every-file-in-a-part rule.
# Step 9 (the server's blocklist) has no list here; step 12's parts-mismatch
# half has no declared digests to compare. The part's declared licence
# stands for every part of the bundle (content's `declared_licence`).
# Content's Unknown (held there) is F_CONTENT_VRM_META_UNKNOWN here, and a
# refusal keeps content's own code, its detail prefixed `<path>!`.

def _bundle_layout(files):
    """(part roots, body path, body bytes) by content's own reading of the
    walked files, or ([], None, None) when it cannot read that far."""
    try:
        files = {p: b for p, b in files.items() if not p.startswith("\0")}
        man = CG.C.strict_loads(files["astrachar.json"])
        body = (man.get("body") or {}).get("file")
        settings = (man.get("character") or {}).get("dir")
        parts = CG.parts_of(files, body, settings, strict=False, pack=CG.pack_kind(man))
        return sorted(root for _kind, root in parts), body, files.get(body) if isinstance(body, str) else None
    except Exception:  # noqa: BLE001 -- ingest_bundle then refuses with the step that failed
        return [], None, None


def _ingest_walked(raw: bytes, files, ctx):
    """Content's ingest_bundle over a bundle ALREADY walked: its own walk_zip
    call is answered with that walk, so a bundle is unzipped once."""
    real = CG.walk_zip
    CG.walk_zip = lambda b: dict(files) if b is raw else real(b)
    try:
        return CG.ingest_bundle(raw, ctx)
    finally:
        CG.walk_zip = real


def bundle_verdict(path: str, raw: bytes, licence, budget=None) -> dict:
    """{"status": "ok"|"unknown"|"bundle", "refusal": {"code","detail"}|None,
    "body": (path, bytes)|None}. Unzipped ONCE by content's walk_zip; its glTF
    JSON (from the walk's headers) is charged to the release's 32 MiB before
    anything in it is parsed (AstraPlugins #129 cabb305: four 32 MiB bundles
    once made the gate parse 128 MiB of JSON, and were accepted)."""
    budget = budget if budget is not None else ReleaseBudget()
    try:
        files = CG.walk_zip(raw)
    except CG.Refusal as r:
        return {"status": "bundle", "refusal": {"code": r.code, "detail": f"{path}!{r.detail}"}, "body": None}
    except Exception as e:  # noqa: BLE001 -- content's reader raised on a hostile shape: refuse, never crash
        return {"status": "bundle", "body": None, "refusal": {
            "code": "E_CONTENT_FORMAT", "detail": f"{path}!: the content checker cannot read it ({type(e).__name__}: {e})"}}
    own = sum(CG.gltf_json_bytes(p, b[:16], len(b)) for p, b in files.items() if not p.startswith("\0"))
    if budget.gltf_json + own > CG.MAX_GLTF_JSON_TOTAL:
        return {"status": "bundle", "body": None, "refusal": {"code": "E_CONTENT_FORMAT", "detail":
                f"{path}!: {budget.gltf_json + own} bytes of glTF JSON in the release with this bundle, "
                f"over {CG.MAX_GLTF_JSON_TOTAL} (32 MiB)"}}
    budget.gltf_json += own
    roots, body_path, body = _bundle_layout(files)
    try:
        got = _ingest_walked(raw, files, {"declared_licence": roots if licence else []})
    except CG.Refusal as r:
        return {"status": "bundle", "refusal": {"code": r.code, "detail": f"{path}!{r.detail}"}, "body": None}
    except Exception as e:  # noqa: BLE001 -- content's reader raised on a hostile shape: refuse, never crash
        return {"status": "bundle", "body": None, "refusal": {
            "code": "E_CONTENT_FORMAT", "detail": f"{path}!: the content checker cannot read it ({type(e).__name__}: {e})"}}
    status = "unknown" if "F_CONTENT_VRM_META_UNKNOWN" in got["flags"] else "ok"
    return {"status": status, "refusal": None, "body": (body_path, body) if body is not None else None}


# ── Zip Cloaking ─────────────────────────────────────────────────────────
# A crafted zip whose LOCAL file headers disagree with its CENTRAL
# DIRECTORY lets a validator and an extractor see two different archives.
# Python's `zipfile` (and every other reader this process or gi-probe
# uses) reads the CENTRAL DIRECTORY; a hidden local entry the central
# directory does not list is invisible to it but very visible to a naive
# sequential unzip. Ingest must see the same single archive the launcher
# will (gi-probe, lane L, refuses the same thing), so this runs before any
# content-typed classification even starts.

LOCAL_FILE_HEADER_SIG = 0x04034B50
CENTRAL_DIR_SIG = 0x02014B50
EOCD_SIG = 0x06054B50
EOCD_FIXED_SIZE = 22  # signature through comment length, before the comment itself
CD_RECORD_FIXED_SIZE = 46
LOCAL_HEADER_FIXED_SIZE = 30
FLAG_DATA_DESCRIPTOR = 0x08
ZIP_CHECK_CAP = 256 * 1024 * 1024
ZIP_METHOD_STORED = 0
ZIP_METHOD_DEFLATED = 8
# PKWARE APPNOTE 4.6.9: "Info-ZIP Unicode Path Extra Field". Many readers
# (including Python's own zipfile -- confirmed against astra-ce's
# sec-probe vectors: ZipFile.namelist() returns THIS field's path, not the
# header's own name) prefer it over the entry's declared name, which makes
# it a second, independent name a central-directory-only parser (this
# function) would never otherwise see. Refused outright, never read.
UNICODE_PATH_EXTRA_TAG = 0x7075
# APPNOTE 4.5.3: the ZIP64 extended information extra field. A 32-bit size
# field of exactly 0xFFFFFFFF is a SENTINEL, not a size; the real 64-bit
# value sits here instead. Only entry-level sizes are resolved (never the
# EOCD's own locator fields below, which stay a hard refusal) -- a single
# entry's real UNCOMPRESSED size can legitimately need 64 bits (a sparse
# content file) even while this repository's own 256 MiB archive cap
# means its COMPRESSED size and every offset never will.
ZIP64_EXTRA_TAG = 0x0001
ZIP64_SENTINEL = 0xFFFFFFFF
# APPNOTE 4.3.9: the (optional) data descriptor signature. Its absence is
# part of the format, not a sign of tampering by itself (APPNOTE 4.3.9.3).
DATA_DESCRIPTOR_SIG = 0x08074B50


def _find_eocd(buf: bytes) -> int:
    """The End Of Central Directory record's own offset, searched from the
    tail: a zip's trailing comment (up to 65535 bytes) can push it back
    from EOF, so this is not simply `len(buf) - 22`."""
    sig = struct.pack("<I", EOCD_SIG)
    lo = max(0, len(buf) - EOCD_FIXED_SIZE - 65535)
    idx = buf.rfind(sig, lo)
    if idx == -1:
        raise ValueError("no end-of-central-directory record")
    return idx


def _extra_has_tag(extra: bytes, tag: int) -> bool:
    """Walks a zip extra field's `{id:u16, size:u16, data}` sub-records for
    `tag`. A malformed extra (a sub-record whose declared size runs past
    what is left) simply ends the walk early -- validating the extra
    field's own shape is not this function's job."""
    pos = 0
    while pos + 4 <= len(extra):
        tag_id, size = struct.unpack_from("<HH", extra, pos)
        if tag_id == tag:
            return True
        pos += 4 + size
    return False


def _resolve_zip64_sizes(extra: bytes, csize: int, usize: int):
    """When either size is the ZIP64 sentinel, reads the real 64-bit value
    from this entry's own ZIP64 extended information extra field (tag
    0x0001), in the field order the format fixes: uncompressed size, then
    compressed size -- each present only when its own 32-bit field was
    the sentinel, so a record with only one sentinel'd field is only 8
    bytes long, not 16. Returns `(csize, usize)` unchanged when neither is
    a sentinel, or None when a sentinel's real value cannot be found (no
    tag 0x0001, or its record is shorter than the sentinels in play need)."""
    if csize != ZIP64_SENTINEL and usize != ZIP64_SENTINEL:
        return csize, usize
    pos = 0
    while pos + 4 <= len(extra):
        tag_id, size = struct.unpack_from("<HH", extra, pos)
        data = extra[pos + 4:pos + 4 + size]
        if tag_id == ZIP64_EXTRA_TAG:
            off = 0
            if usize == ZIP64_SENTINEL:
                if off + 8 > len(data):
                    return None
                usize = struct.unpack_from("<Q", data, off)[0]
                off += 8
            if csize == ZIP64_SENTINEL:
                if off + 8 > len(data):
                    return None
                csize = struct.unpack_from("<Q", data, off)[0]
            return csize, usize
        pos += 4 + size
    return None


def _check_data_descriptor(buf: bytes, end: int, crc: int, csize: int, usize: int):
    """A bit-3 (general-purpose flag "data descriptor present") entry's
    data descriptor, required EXACTLY at `end` -- the entry's own
    recorded end: its local header plus its declared compressed data,
    nothing more, nothing less. The leading 4-byte signature is OPTIONAL
    by the format itself (APPNOTE 4.3.9.3: older tools omit it); whether
    or not it is there, the crc/compressed-size/uncompressed-size that
    follow must equal the central directory's own (its only trustworthy
    copy). A descriptor that is missing, truncated, or sitting anywhere
    but exactly here -- even if a byte-for-byte-correct one exists further
    into the file, describing a LONGER span that swallows a hidden entry
    -- is refused: astra-ce sec-probe `stored-dd.zip` is exactly this
    shape, a real signed descriptor whose crc/sizes describe the entry's
    own data PLUS a smuggled second header, placed after that smuggled
    header rather than right after the entry's own 15 declared bytes.
    Returns `(None, the descriptor's own byte length -- signature included
    when present)` when consistent, or `(reason, None)`. The length is the
    caller's to add to this entry's own tiled range: the descriptor's
    bytes are real, physically-present file content between this entry's
    data and whatever comes next, not something a plain `compressed_size`
    already accounts for.
    """
    pos = end
    sig_len = 4 if pos + 4 <= len(buf) and struct.unpack_from("<I", buf, pos)[0] == DATA_DESCRIPTOR_SIG else 0
    pos += sig_len
    if pos + 12 > len(buf):
        return f"no data descriptor at its recorded end (offset {end})", None
    dcrc, dcsize, dusize = struct.unpack_from("<III", buf, pos)
    if dcrc != crc or dcsize != csize or dusize != usize:
        return (
            f"the data descriptor at its recorded end (offset {end}) carries "
            f"(crc={dcrc},csize={dcsize},usize={dusize}), which disagrees with the "
            f"central directory's (crc={crc},csize={csize},usize={usize})"
        ), None
    return None, sig_len + 12


def _verify_entry_data(buf: bytes, data_start: int, method: int, csize: int, usize: int, crc: int):
    """Decodes an entry's own declared span, `buf[data_start:data_start +
    csize]` (csize/usize/crc/method are always the CENTRAL DIRECTORY's --
    the only trustworthy copy, data-descriptor entry or not), and confirms
    it really is what it claims to be:
      - Stored: compressed size must equal uncompressed size; nothing to
        decode, so any other relationship can only be a lie.
      - Deflated: raw-inflating (zlib, wbits=-15: no zlib/gzip wrapper)
        must consume EXACTLY `csize` bytes and produce EXACTLY `usize`
        bytes whose CRC-32 is `crc`. A real deflate bitstream carries its
        own end-of-stream marker; if decoding it finishes before `csize`,
        the remaining bytes are DEFLATE SLACK -- room INSIDE this entry's
        own declared range that a correct decompressor never reads but a
        streaming reader can, for a second local header a central-
        directory-only parser's tiling check alone would never catch
        (astra-ce sec-probe `slack.zip`: a bit-3 entry's data descriptor
        agrees with the real, short deflate stream; only its central-
        directory `compressed_size` is inflated to also cover a hidden
        header). GIs come from arbitrary build tools that may legitimately
        set the data-descriptor flag, so bit 3 itself is never refused --
        only a stream that does not actually fill its declared span.
    Any other method is refused outright: astra-companion's own character-
    bundle zip core allows only Stored and Deflate (docs/character-files-
    and-2d-editor.md §1.1), and silently accepting a method this function
    cannot verify would be worse than saying so.
    Returns None (consistent) or a reason string.
    """
    span = buf[data_start:data_start + csize]
    if method == ZIP_METHOD_STORED:
        if csize != usize:
            return f"a Stored entry's compressed size {csize} does not equal its uncompressed size {usize}"
        return None
    if method == ZIP_METHOD_DEFLATED:
        d = zlib.decompressobj(-15)
        try:
            out = d.decompress(span)
            # Drain whatever the decompressor is still holding once input
            # has run out, BEFORE judging .eof/.unused_data -- decompress()
            # alone is not guaranteed to flush every buffered output byte
            # the moment the stream's own end-of-stream marker is reached.
            out += d.flush()
        except zlib.error as e:
            return f"its Deflate stream does not decode: {e}"
        if not d.eof:
            return f"its Deflate stream does not end within the declared compressed size {csize}"
        if d.unused_data:
            return (
                f"its Deflate stream ends {len(d.unused_data)} byte(s) before the declared "
                f"compressed size {csize} -- deflate slack inside the entry's own declared range"
            )
        if len(out) != usize:
            return f"its Deflate stream decodes to {len(out)} byte(s), not the declared uncompressed size {usize}"
        if zlib.crc32(out) != crc:
            return f"its decoded bytes do not hash to its declared CRC-32 {crc:#010x}"
        return None
    return f"compression method {method} is neither Stored nor Deflate"


def verify_zip_headers(zip_path) -> dict:
    """
    Refuses `E_ZIP_HEADERS_INCONSISTENT` when:
      - a local header's signature is wrong;
      - a local header's name, compression method, CRC or either size
        disagrees with its central-directory record (a data-descriptor
        entry -- general-purpose flag bit 3 -- carries no reliable crc or
        sizes in its OWN local header by design, so those three fields are
        never compared for one: the central directory is their only
        trustworthy copy);
      - a local header sits outside the file, or its declared byte range
        (header + the central directory's compressed size for it)
        overlaps another entry's;
      - the central-directory-listed entries do not exactly TILE the
        region before the central directory starts, with no gap and no
        overlap -- a gap is either leading junk (before the first entry)
        or room for a hidden local entry the central directory never
        mentions (between two listed entries or after the last one);
      - an entry carries an Info-ZIP Unicode Path extra field (0x7075, in
        either its local or central copy) -- a second name some readers
        (Python's own zipfile included) honour over the one above, that a
        central-directory-only parser would never otherwise see at all;
      - an entry's own declared data does not decode to what it claims:
        a Stored entry whose sizes disagree, or a Deflated entry whose
        raw-inflated stream does not consume exactly its declared
        compressed size and produce exactly its declared uncompressed
        size and CRC-32 (`_verify_entry_data`, run on EVERY Deflated entry
        -- its sizes resolved first if either is a ZIP64 sentinel) --
        DEFLATE SLACK plus a legitimate data-descriptor entry (bit 3,
        never refused on its own: GIs come from arbitrary build tools
        that may set it) is exactly what the tiling check above cannot
        see, because the slack sits INSIDE an entry's own declared range,
        not in a gap between entries;
      - a bit-3 entry's data descriptor is missing, wrong, or sitting
        anywhere but EXACTLY at the entry's own recorded end
        (`_check_data_descriptor`) -- a byte-for-byte-correct descriptor
        placed further into the file, describing a LONGER span that also
        covers a smuggled second header, is a different lie than the
        Deflate-slack one above and needs its own check: a Stored entry
        has no deflate stream to catch it, and a Deflated one could carry
        a genuine, exactly-fitting stream while still having its
        descriptor planted in the wrong place.
    ZIP64 at the END OF CENTRAL DIRECTORY (a locator whose own fields are
    the 0xFFFF / 0xFFFFFFFF sentinel) is refused outright rather than
    half-verified: nothing this repository ingests needs an archive that
    large, and a checker that silently skipped fields it does not
    understand would be worse than one that says so. A SINGLE entry's own
    ZIP64 extra field is different and IS resolved (`_resolve_zip64_sizes`):
    a legitimately huge uncompressed size (a sparse content file) inside an
    otherwise ordinary, small archive is not the same claim as an archive
    too large for this check to read at all.
    Returns {"ok": True} or {"ok": False, "error": "..."}.
    """
    try:
        size = pathlib.Path(zip_path).stat().st_size
        if size > ZIP_CHECK_CAP:
            return {"ok": False, "error": f"{zip_path} is {size} bytes, over {ZIP_CHECK_CAP}"}
        with open(zip_path, "rb") as f:
            buf = f.read()
    except OSError as e:
        return {"ok": False, "error": f"cannot read {zip_path}: {e}"}

    try:
        eocd = _find_eocd(buf)
    except ValueError as e:
        return {"ok": False, "error": str(e)}

    _disk_no, _cd_disk_no, _disk_entries, total_entries, cd_size, cd_offset, _comment_len = (
        struct.unpack_from("<HHHHIIH", buf, eocd + 4)
    )
    if total_entries == 0xFFFF or cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF:
        return {"ok": False, "error": "ZIP64 central directory is not supported by this check"}
    if cd_offset + cd_size > len(buf):
        return {"ok": False, "error": "the central directory extends past the end of the file"}

    ranges = []  # (local_header_offset, data_end, name)
    pos = cd_offset
    cd_end = cd_offset + cd_size
    while pos < cd_end:
        entry_start = pos
        if pos + CD_RECORD_FIXED_SIZE > len(buf):
            return {"ok": False, "error": f"a central directory entry at {pos} is truncated"}
        (
            csig, _vmb, _vn, _cflags, ccomp, _mtime, _mdate, ccrc, ccsize, cusize,
            fn_len, extra_len, cmt_len, _disk_start, _int_attrs, _ext_attrs, lho,
        ) = struct.unpack_from("<IHHHHHHIIIHHHHHII", buf, pos)
        if csig != CENTRAL_DIR_SIG:
            return {"ok": False, "error": f"a central directory entry at {pos} has the wrong signature"}
        name = bytes(buf[entry_start + CD_RECORD_FIXED_SIZE:entry_start + CD_RECORD_FIXED_SIZE + fn_len])
        central_extra = bytes(
            buf[entry_start + CD_RECORD_FIXED_SIZE + fn_len:entry_start + CD_RECORD_FIXED_SIZE + fn_len + extra_len]
        )
        pos = entry_start + CD_RECORD_FIXED_SIZE + fn_len + extra_len + cmt_len

        if lho + LOCAL_HEADER_FIXED_SIZE > len(buf):
            return {"ok": False, "error": f"E_ZIP_HEADERS_INCONSISTENT: {name!r}'s local header offset {lho} is outside the file"}
        lsig, _lvn, lflags, lcomp, _lmtime, _lmdate, lcrc, lcsize, lusize, lfn_len, lextra_len = (
            struct.unpack_from("<IHHHHHIIIHH", buf, lho)
        )
        if lsig != LOCAL_FILE_HEADER_SIG:
            return {"ok": False, "error": f"E_ZIP_HEADERS_INCONSISTENT: {name!r}'s local header at {lho} has the wrong signature"}
        lname_start = lho + LOCAL_HEADER_FIXED_SIZE
        if lname_start + lfn_len + lextra_len > len(buf):
            return {"ok": False, "error": f"E_ZIP_HEADERS_INCONSISTENT: {name!r}'s local header name or extra field runs past the end of the file"}
        lname = bytes(buf[lname_start:lname_start + lfn_len])
        local_extra = bytes(buf[lname_start + lfn_len:lname_start + lfn_len + lextra_len])
        if lname != name:
            return {"ok": False, "error": f"E_ZIP_HEADERS_INCONSISTENT: the central directory calls this entry {name!r}; its local header calls itself {lname!r}"}
        if lcomp != ccomp:
            return {"ok": False, "error": f"E_ZIP_HEADERS_INCONSISTENT: {name!r}'s local compression method {lcomp} disagrees with the central directory's {ccomp}"}
        if not (lflags & FLAG_DATA_DESCRIPTOR):
            if lcrc != ccrc or lcsize != ccsize or lusize != cusize:
                return {
                    "ok": False,
                    "error": (
                        f"E_ZIP_HEADERS_INCONSISTENT: {name!r}'s local header "
                        f"(crc={lcrc},csize={lcsize},usize={lusize}) disagrees with the "
                        f"central directory's (crc={ccrc},csize={ccsize},usize={cusize})"
                    ),
                }
        # Info-ZIP Unicode Path Extra Field: a second name, honoured by
        # some readers (Python's own zipfile included) over the one
        # above, that a central-directory-only parser would never
        # otherwise see at all. Refused outright, in either copy.
        if _extra_has_tag(central_extra, UNICODE_PATH_EXTRA_TAG) or _extra_has_tag(local_extra, UNICODE_PATH_EXTRA_TAG):
            return {"ok": False, "error": f"E_ZIP_HEADERS_INCONSISTENT: {name!r} carries a Unicode Path extra field (0x7075), which is never allowed"}

        # ZIP64: resolved AFTER the raw local-vs-central comparison above
        # (which must see the SAME sentinel on both sides to agree, not a
        # resolved value on one side only), but before anything that needs
        # the entry's real size -- which is every check from here on, so
        # the Deflate end-check below runs correctly on EVERY entry, large
        # or small, instead of either mis-slicing a 4-byte sentinel as a
        # ~4 GiB span or skipping the check via the "past EOF" guard.
        resolved = _resolve_zip64_sizes(central_extra, ccsize, cusize)
        if resolved is None:
            return {"ok": False, "error": f"E_ZIP_HEADERS_INCONSISTENT: {name!r}'s size is the ZIP64 sentinel with no resolving extra field (tag 0x0001)"}
        ccsize, cusize = resolved

        data_start = lname_start + lfn_len + lextra_len
        data_end = data_start + ccsize  # the central directory's size is authoritative either way
        if data_end > len(buf):
            return {"ok": False, "error": f"E_ZIP_HEADERS_INCONSISTENT: {name!r}'s data runs past the end of the file"}
        bad = _verify_entry_data(buf, data_start, ccomp, ccsize, cusize, ccrc)
        if bad:
            return {"ok": False, "error": f"E_ZIP_HEADERS_INCONSISTENT: {name!r}: {bad}"}
        # A data descriptor is required EXACTLY at the entry's own
        # recorded end, after (not instead of) the exact-end check above
        # -- a Deflated bit-3 entry's "real stream fits the declared span"
        # fact and its "a descriptor confirms that span, in the right
        # place" fact are two different lies to tell.
        dd_len = 0
        if lflags & FLAG_DATA_DESCRIPTOR:
            dd_bad, dd_len = _check_data_descriptor(buf, data_end, ccrc, ccsize, cusize)
            if dd_bad:
                return {"ok": False, "error": f"E_ZIP_HEADERS_INCONSISTENT: {name!r}: {dd_bad}"}
        # The descriptor's own bytes are real file content between this
        # entry and whatever comes next -- part of its tiled range too.
        ranges.append((lho, data_end + dd_len, name))

    ranges.sort(key=lambda r: r[0])
    cursor = 0
    for start, end, name in ranges:
        if start < cursor:
            return {"ok": False, "error": f"E_ZIP_HEADERS_INCONSISTENT: {name!r} at {start} overlaps the previous entry, which runs to {cursor}"}
        if start > cursor:
            where = "before the first entry" if cursor == 0 else f"before {name!r}"
            return {"ok": False, "error": f"E_ZIP_HEADERS_INCONSISTENT: {start - cursor} undeclared byte(s) {where}, at offset {cursor} -- a hidden local entry could sit there"}
        cursor = end
    if cursor != cd_offset:
        return {
            "ok": False,
            "error": (
                f"E_ZIP_HEADERS_INCONSISTENT: {cd_offset - cursor} undeclared byte(s) between the last "
                f"listed entry (ending at {cursor}) and the central directory (starting at {cd_offset})"
            ),
        }

    return {"ok": True}


def content_report(zip_path, declared):
    """AstraPlugins manifest.md §2.7: the content-coverage check and the HARD
    VRM licence gate, over a real release zip. `declared` is the parsed
    manifest's `[[integration.content]]` array (a list of dicts). Runs
    verify_zip_headers FIRST (Zip Cloaking): a release whose local headers
    disagree with its own central directory is refused before anything is
    classified as content at all. Then EVERY entry is read by its bytes
    (§2.7.1), every GLB and .gltf is held to the format rules and caps, the
    release's glTF JSON budget is summed from headers, and every declared
    .astrachar/.astrapack is judged by the content contract's own code."""
    zh = verify_zip_headers(zip_path)
    if not zh["ok"]:
        return {"ok": False, "error": zh["error"]}
    try:
        z = zipfile.ZipFile(zip_path)
    except (zipfile.BadZipFile, OSError) as e:
        return {"ok": False, "error": f"not a readable zip: {e}"}

    content_files = []
    parts_by_path = {}
    format_refusals = []
    format_paths = set()
    archives = []
    archives_unscanned = []
    archive_refusals = []
    present_of = {}  # an archive member's siblings, for its .gltf's relative uris

    def format_refuse(path, detail):
        if path not in format_paths:
            format_paths.add(path)
            format_refusals.append({"path": path, "detail": detail})

    with z:
        infos = [i for i in z.infolist() if not i.is_dir()]
        # Every file path in the release zip (not only the content-typed
        # ones): what a `.gltf`'s plain relative buffer/image uri may name.
        present = {i.filename for i in infos}
        budget = ReleaseBudget()
        for info in infos:
            name = info.filename
            if name == MANIFEST_NAME:
                # the manifest is astra-gi.toml at the release ROOT only; one in a
                # folder is a file like any other, judged by its bytes (AstraPlugins
                # #129 7163c45: a VRM saved as models/astra-gi.toml was exempt)
                continue
            try:
                with z.open(info) as f:
                    head = f.read(64)
            except OSError:
                continue
            # the release's glTF JSON, from headers before anything is parsed
            # (the content catalogue's 32 MiB per archive, B1)
            budget.gltf_json += CG.gltf_json_bytes(name, head[:16], info.file_size)
            raw = None
            sniff = CONTENT_EXT_MAGIC.get(pathlib.PurePosixPath(name).suffix.lower())
            if sniff is not None and sniff(head[:32]):
                if info.file_size > CONTENT_ENTRY_CAP:
                    return {"ok": False, "error": f"{name} is {info.file_size} bytes, over {CONTENT_ENTRY_CAP}"}
                raw = _read_whole(z, info, CONTENT_ENTRY_CAP)
                if raw is None:
                    return {"ok": False, "error": f"{name} inflates past {CONTENT_ENTRY_CAP} bytes"}
                content_files.append(name)
                parts_by_path[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "raw": raw, "gate": None}
            why = name_problem(z, info, head, raw, budget)
            if why:
                format_refuse(name, why)
                continue
            # every GLB and every .gltf, declared or not, of any class (§2.7.3)
            if head[:4] == b"glTF" or name.lower().endswith(".gltf"):
                if raw is None and info.file_size > CG.MAX_GLTF_JSON:
                    format_refuse(name, f"a .gltf of {info.file_size} bytes, over {CG.MAX_GLTF_JSON}")
                    continue
                data = raw if raw is not None else _read_whole(z, info, CG.MAX_GLTF_JSON)
                why = gltf_format_problem(data, name, present) if data is not None else "unreadable"
                if why:
                    format_refuse(name, why)
                continue
            if _is_zip(head[:4]) and not name.lower().endswith(BUNDLE_EXTS):
                archives.append(info)
        # a game's own archives, one level deep, after every top-level entry is
        # summed into the budget (AstraPlugins #129 f3e2bd0)
        for info in archives:
            name = info.filename
            if info.file_size > CONTAINER_MAX_TOTAL:
                archives_unscanned.append({"path": name, "reason": f"{info.file_size} bytes, over {CONTAINER_MAX_TOTAL}"})
                continue
            raw = _read_whole(z, info, CONTAINER_MAX_TOTAL)
            if raw is None or is_bundle_bytes(raw):
                continue  # a renamed bundle was refused above by its name
            walked = walk_container(raw)
            if walked["status"] == "refused":
                archive_refusals.append({"path": name, "code": walked["code"], "detail": walked["detail"]})
                continue
            if walked["status"] == "unscanned":
                archives_unscanned.append({"path": name, "reason": walked["reason"]})
                continue
            inner = {f"{name}!{q}": d for q, d in walked["files"].items()}
            own = sum(CG.gltf_json_bytes(k, d[:16], len(d)) for k, d in inner.items())
            if budget.gltf_json + own > CG.MAX_GLTF_JSON_TOTAL:
                format_refuse(name, f"{budget.gltf_json + own} bytes of glTF JSON in the release with this archive, "
                                    f"over {CG.MAX_GLTF_JSON_TOTAL} (32 MiB)")
                continue
            budget.gltf_json += own
            inner_present = set(inner)
            for k, d in sorted(inner.items()):
                if k in present:  # a top-level entry literally named like this member
                    format_refuse(k, "a file named like a member of an archive beside it")
                    continue
                why = name_problem_bytes(k, d, budget) or gltf_format_problem(d, k, inner_present)
                if why:
                    format_refuse(k, why)
                    continue
                if _is_zip(d[:4]) and not k.lower().endswith(BUNDLE_EXTS):
                    archives_unscanned.append({"path": k, "reason": "an archive inside an archive: opened one level deep"})
                    continue
                if is_inner_part(k, d):
                    content_files.append(k)
                    parts_by_path[k] = {"sha256": hashlib.sha256(d).hexdigest(), "raw": d, "gate": None}
                    present_of[k] = inner_present
        if budget.gltf_json > CG.MAX_GLTF_JSON_TOTAL:
            format_refuse("", f"{budget.gltf_json} bytes of glTF JSON in the release, over {CG.MAX_GLTF_JSON_TOTAL} (32 MiB)")

        # The VRM gate's selection rule (AstraPlugins 516ba38's part_licence):
        # judged by the file's own bytes, never by a `.vrm` name -- an avatar
        # (VRM, VRMC_vrm) in ANY part, an animation (VRMC_vrm_animation, no
        # avatar extension) NEVER, and a plain glTF/GLB only when its
        # declared part's kind is "character". A part refused for its format
        # above is not judged again; a `.astrachar`/`.astrapack` is judged
        # whole by the content contract's own ingest_bundle (AstraPlugins
        # #129), its body's readable VRM licence becoming the part's licence.
        for entry in declared:
            path = entry.get("path") if isinstance(entry, dict) else None
            if not isinstance(path, str) or path not in parts_by_path or path in format_paths:
                continue
            raw = parts_by_path[path]["raw"]
            if path.lower().endswith(BUNDLE_EXTS) and _is_zip(raw[:4]):
                bv = bundle_verdict(path, raw, entry.get("licence"), budget)
                gate = {"status": bv["status"], "vrm_licence": None, "refusal": bv["refusal"]}
                if bv["status"] == "ok" and bv["body"] is not None:
                    body_gate = vrm_gate(bv["body"][1], bv["body"][0])
                    if body_gate["status"] == "ok":
                        gate["vrm_licence"] = body_gate["vrm_licence"]
                parts_by_path[path]["gate"] = gate
                continue
            doc = gltf_document(raw, path)
            if doc is not None:
                cls = gltf_class(doc)
                if cls == "avatar" or (cls == "plain" and entry.get("kind") == "character"):
                    parts_by_path[path]["gate"] = vrm_gate(raw, path, present_of.get(path, present))

        for info_dict in parts_by_path.values():
            info_dict.pop("raw", None)

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
    # a declared file refused for what it is (a .gltf with a BOM is not
    # content-typed) is there: it is not also "missing"
    missing = sorted(declared_set - content_set - format_paths)
    duplicates = sorted(dup)

    declared_by_path = {e["path"]: e for e in declared if isinstance(e, dict) and isinstance(e.get("path"), str)}
    parts = []
    licence_refusals = []
    licence_conflicts = []
    licence_unknown = []
    licence_undeclared = []
    bundle_refusals = []
    for path in sorted(declared_set & content_set):
        if path in format_paths:
            continue  # E_CONTENT_FORMAT, refused before licence_source is even asked
        info = parts_by_path[path]
        gate = info["gate"]
        gate_status = gate["status"] if gate else None
        if gate_status == "conflict":
            # refused outright, before licence_source is even asked
            licence_conflicts.append({"path": path, "field": gate["refusal"]["field"], "detail": gate["refusal"]["detail"]})
            continue
        if gate_status == "format":
            format_refusals.append({"path": path, "detail": gate["refusal"]["detail"]})
            continue
        if gate_status == "bundle":
            # an embedded bundle the content contract refuses, with its own code
            bundle_refusals.append({"path": path, "code": gate["refusal"]["code"], "detail": gate["refusal"]["detail"]})
            continue
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
        "licence_conflicts": licence_conflicts,
        "licence_unknown": licence_unknown,
        "licence_undeclared": licence_undeclared,
        "format_refusals": format_refusals,
        "bundle_refusals": bundle_refusals,
        "archive_refusals": archive_refusals,
        "archives_unscanned": archives_unscanned,
    }


# The launcher's own default zip limits (astra-game-launcher v0.5.0
# src/package.rs, `Limits::default`): a zip gi-probe opened is inside them.
FILES_MAX_ENTRIES = 20_000
FILES_MAX_INFLATED = 1024 * 1024 * 1024


def zip_files(zip_path):
    try:
        with zipfile.ZipFile(zip_path) as z:
            infos = [i for i in z.infolist() if not i.is_dir()]
            if len(infos) > FILES_MAX_ENTRIES:
                return {"ok": False, "error": f"the zip has {len(infos)} files, over {FILES_MAX_ENTRIES}"}
            out = {}
            total = 0
            for info in infos:
                name = info.filename.replace("\\", "/")
                if name in out:
                    return {"ok": False, "error": f"{name} is in the zip twice"}
                h = hashlib.sha256()
                with z.open(info) as f:
                    while True:
                        chunk = f.read(1 << 20)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > FILES_MAX_INFLATED:
                            return {"ok": False, "error": f"the zip inflates past {FILES_MAX_INFLATED} bytes"}
                        h.update(chunk)
                out[name] = h.hexdigest()
    except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError, EOFError, zlib.error) as e:
        return {"ok": False, "error": f"not a readable zip: {e}"}
    return {"ok": True, "files": out}


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
    if len(argv) == 3 and argv[1] == "files":
        json.dump(zip_files(argv[2]), sys.stdout, ensure_ascii=False)
        return 0
    if len(argv) == 3 and argv[1] == "zipcheck":
        json.dump(verify_zip_headers(argv[2]), sys.stdout, ensure_ascii=False)
        return 0
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
