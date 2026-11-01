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
    python3 lib/schemacheck.py zipcheck ZIP
        -> {"ok": true} | {"ok": false, "error": "..."}   (Zip Cloaking, see verify_zip_headers)

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
a 1.0 block, and refuse a disagreement E_CONTENT_LICENCE_CONFLICT (O-2,
AstraPlugins 4de2e30); fixtures/vrm-conflict/ holds that commit's goldens.
"""

from __future__ import annotations

import datetime
import hashlib
import io
import json
import pathlib
import struct
import sys
import tomllib
import zipfile
import zlib

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


def extract_vrm_metas(raw):
    """{"0.x": meta_dict, "1.0": meta_dict} for WHICHEVER of
    extensions.VRM.meta / extensions.VRMC_vrm.meta the GLB carries -- both,
    when it carries both, never only the first one found (O-2: the earlier
    `extract_vrm_meta` returned on the first match, so a file whose VRM 0.x
    meta allowed and whose VRM 1.0 meta prohibited passed the gate
    outright). Empty when it carries neither -- legal DRAFT-v3.md Part 6
    G4's "unknown" case (flagged, never refused: not every .vrm file
    carries a meta block). Mirrors AstraPlugins tools/check-games-goldens.py
    at 4de2e30 (spec/games-vrm-conflict-kindkeys)."""
    doc = parse_glb_json_chunk(raw)
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


# The overlap between the two specs' usage-flag vocabularies: 0.x's
# *UssageName string enum ("Allow" vs anything else -- UniVRM) against 1.0's
# allowExcessively*Usage boolean. 0.x's `commercialUssageName` and 1.0's
# `allowPoliticalOrReligiousUsage` / `allowAntisocialOrHateUsage` have no
# counterpart on the other side and are never compared.
VRM_USAGE_OVERLAP = {
    "violent": ("violentUssageName", "allowExcessivelyViolentUsage"),
    "sexual": ("sexualUssageName", "allowExcessivelySexualUsage"),
}


def rule_vrm_conflict(meta0x, meta1_0):
    """manifest.md §2.7.3 (AstraPlugins 4de2e30) / the content contract's
    ingest-v1.md §4.2: a file carrying BOTH a VRM 0.x and a VRM 1.0 meta is
    judged on EACH, each with its own spec's absent-field defaults, and a
    disagreement is E_CONTENT_LICENCE_CONFLICT:

      - the two gate verdicts differ (one side's redistribution or avatar
        permission refuses and the other's does not), or
      - an overlapping usage flag BOTH sides carry reads a different
        allow/disallow between the two specs.

    Returns {"field", "detail"} or None when they do not disagree."""
    v0 = rule_vrm_licence_refused("0.x", meta0x)
    v1 = rule_vrm_licence_refused("1.0", meta1_0)
    if v0["refused"] != v1["refused"]:
        def side(v):
            return f"refused ({v['field']})" if v["refused"] else "allowed"
        return {"field": "gate verdict", "detail": f"VRM 0.x reads {side(v0)}; VRM 1.0 reads {side(v1)}"}
    for label, (key0, key1) in VRM_USAGE_OVERLAP.items():
        if key0 in meta0x and key1 in meta1_0:
            allowed0 = meta0x[key0] == "Allow"
            allowed1 = meta1_0[key1] is True
            if allowed0 != allowed1:
                return {"field": f"usage:{label}", "detail": f"VRM 0.x {key0}={meta0x[key0]!r}; VRM 1.0 {key1}={meta1_0[key1]!r}"}
    return None


def vrm_gate(raw):
    """The full G4/G5 verdict for one .vrm's (or a readable .astrachar
    body's) bytes, reading BOTH metas when the GLB carries both (O-2).
    Returns {"status": "ok"|"refused"|"conflict"|"unknown", "vrm_licence":
    {"vrm_version","fields"}|None, "refusal": {...}|None}.
    "unknown" (no meta of either spec) is never a refusal: G4 says it is
    flagged (F_CONTENT_VRM_META_UNKNOWN) and passes only with the character
    checkbox and the licence line, which is the publish form's job.
    "conflict" (rule_vrm_conflict) runs before any single-meta verdict and
    carries no vrm_licence: the part is refused before display is asked."""
    metas = extract_vrm_metas(raw)
    if not metas:
        return {"status": "unknown", "vrm_licence": None, "refusal": None}
    if "0.x" in metas and "1.0" in metas:
        conflict = rule_vrm_conflict(metas["0.x"], metas["1.0"])
        if conflict is not None:
            return {"status": "conflict", "vrm_licence": None, "refusal": conflict}
    # Both present and agreeing, or only one: VRM 1.0 takes display
    # precedence when both exist (astra-companion's `licence_of`: "a file
    # carrying both is read as 1.0").
    vrm_version = "1.0" if "1.0" in metas else "0.x"
    meta = metas[vrm_version]
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
    classified as content at all."""
    zh = verify_zip_headers(zip_path)
    if not zh["ok"]:
        return {"ok": False, "error": zh["error"]}
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
    licence_conflicts = []
    licence_unknown = []
    licence_undeclared = []
    for path in sorted(declared_set & content_set):
        info = parts_by_path[path]
        gate = info["gate"]
        gate_status = gate["status"] if gate else None
        if gate_status == "conflict":
            # refused outright, before licence_source is even asked
            licence_conflicts.append({"path": path, "field": gate["refusal"]["field"], "detail": gate["refusal"]["detail"]})
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
    if len(argv) == 3 and argv[1] == "zipcheck":
        json.dump(verify_zip_headers(argv[2]), sys.stdout, ensure_ascii=False)
        return 0
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
