#!/usr/bin/env python3
# DiE EP-pattern miner — codemap 5.38.0
#
# Scans every Detect-It-Easy `.sg` detector script under db/PE/ and extracts
# the hand-curated entry-point byte patterns embedded in each `compareEP()`
# call, paired with the script's `meta(type, name)` declaration and any
# `sVersion`/`sOptions` strings assigned in the same logical block.
#
# Output: a flat JSON array of records consumed at runtime by codemap's
# `die-fingerprint` action. Each record carries enough metadata for the
# 7-axis fingerprint taxonomy (packer/protector/cryptor/installer/sfx/
# joiner/patcher/compiler/library/language/format/tool/sign/game/dotnet/
# native/marker).
#
# Usage:
#   python3 tools/die_miner.py \
#       --db ~/reference/codemap-research-targets/15-die/db/PE \
#       --out codemap-core/data/die-epsig.json
#
# Re-run on every DiE upstream release to refresh the corpus.

import argparse
import json
import os
import re
import sys
from pathlib import Path

META_RE = re.compile(r'meta\s*\(\s*"([^"]+)"\s*,\s*"([^"]+)"', re.MULTILINE)

# DiE detection-call patterns. We capture three logical "kinds" of byte
# signature in a single corpus:
#   ep_*   — entry-point anchored (PE/MSDOS/NE/LE/LX.compareEP)
#   sig_*  — anywhere-in-section (PE.isSignaturePresent, PE.isSignatureInSectionPresent,
#                                 PE.findSignature, Binary.isSignaturePresent)
#   ovl_*  — overlay-region (PE.compareOverlay)
COMPARE_EP_RE = re.compile(
    r'(?:PE|MSDOS|NE|LE|LX|MACHO|ELF|Binary)\.compareEP\s*\(\s*"([^"]+)"\s*(?:,\s*([^)]+))?\)',
    re.MULTILINE,
)
SIG_PRESENT_RE = re.compile(
    r'(?:PE|Binary)\.isSignature(?:InSection)?Present\s*\([^,]+,\s*"([^"]+)"\s*\)',
    re.MULTILINE,
)
FIND_SIG_RE = re.compile(
    r'PE\.findSignature\s*\([^,]+,\s*[^,]+,\s*"([^"]+)"\s*\)',
    re.MULTILINE,
)
OVERLAY_RE = re.compile(
    r'PE\.compareOverlay\s*\(\s*"([^"]+)"\s*(?:,\s*([^)]+))?\)',
    re.MULTILINE,
)
SVERSION_RE = re.compile(r'sVersion\s*=\s*"([^"]+)"')
SOPTIONS_RE = re.compile(r'sOptions\s*=\s*"([^"]+)"')

# DiE-specific wildcard tokens. PEiD has only `??` (single-byte wildcard).
# DiE adds:
#   $$         — relative jump byte, auto-resolved at match time (1 byte)
#   $$$$       — 2-byte relative jump
#   $$$$$$$$   — 4-byte relative jump
#   **/!!/__   — negative wildcards (rarely used in PE/*.sg, ignored in v1)
# v1 strategy: downgrade every $$* token to plain `??` per byte. Lossy
# (won't match jumps if relative-target validation matters) but functional
# for the dominant case where the bytes around the jump are the discriminating
# part of the signature.
WILDCARD_RUN_RE = re.compile(r'\$+')

# Patterns we drop because they aren't representable as bare wildcards
# without a real DiE-DSL interpreter.
NEGATIVE_WILDCARD_RE = re.compile(r'(?:\*\*|!!|__)')


def normalize_pattern(raw: str) -> tuple[str, int]:
    """Convert a DiE compareEP pattern into hex+`??` form codemap can match.

    Returns (normalized, lossy_count). `lossy_count` is the number of
    `$$*` runs we replaced with plain `??` — useful for telemetry.
    """
    lossy = 0
    # First strip any whitespace DiE allows in patterns (uncommon but legal).
    s = raw.replace(" ", "").replace("\t", "")

    # Drop negative-wildcard patterns entirely — too few + can't be
    # represented as a positive match.
    if NEGATIVE_WILDCARD_RE.search(s):
        return ("", 0)

    def replace_dollars(m: re.Match) -> str:
        nonlocal lossy
        run = m.group(0)
        # `$$` = 1 byte = 2 hex chars. So a run of n $-chars = n/2 bytes.
        n_bytes = len(run) // 2
        if n_bytes == 0:
            return ""
        lossy += 1
        return ".." * n_bytes

    s = WILDCARD_RUN_RE.sub(replace_dollars, s)

    # Convert DiE's `.` (single nibble wildcard, two `.` = `??`) to canonical
    # `?` form so the matcher only has to handle one wildcard char.
    s = s.replace(".", "?")

    # Validate: every char is hex or `?`. Strip anything else (some DiE
    # patterns have stray chars like `~` which aren't documented).
    cleaned_chars = []
    for c in s:
        if c in "0123456789abcdefABCDEF?":
            cleaned_chars.append(c.lower())
    s = "".join(cleaned_chars)
    if len(s) % 2 != 0:
        # Odd length — drop trailing nibble to keep byte alignment.
        s = s[:-1]
    return (s, lossy)


# 7-axis taxonomy. Maps DiE meta(type) to one of the standard fingerprint
# axes used across PEiD / Exeinfo / CFF Explorer / PEStudio.
TAXONOMY_AXES = {
    "packer", "protector", "cryptor", "installer", "sfx", "joiner",
    "patcher", "compiler", "library", "language", "format", "tool",
    "sign", "game", "dotnet", "native", "marker", "archive", "overlay",
    "operation system", "linker", "stub",
}


def axis_for_type(t: str) -> str:
    """Map DiE meta(type) to a 7-axis taxonomy bucket."""
    tl = t.lower().strip()
    if tl in TAXONOMY_AXES:
        return tl
    # DiE has occasional ad-hoc types — bucket them as 'tool'.
    return "tool"


# Heuristic: associate each compareEP with the nearest sVersion / sOptions
# assignment in the same brace-bracketed `if` body. We can't fully parse
# JS so we fall back to "look in a window of ±N lines".
WINDOW_LINES = 6


def mine_file(path: Path) -> list[dict]:
    """Mine a single `.sg` file and return the records it produced."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    # Find meta(type, name) — the FIRST top-level call wins.
    m = META_RE.search(text)
    if not m:
        return []
    raw_type, name = m.group(1), m.group(2)
    axis = axis_for_type(raw_type)

    lines = text.splitlines()
    line_offsets: list[int] = [0]
    for line in lines:
        line_offsets.append(line_offsets[-1] + len(line) + 1)

    def line_for_offset(off: int) -> int:
        # Binary search would be faster but list is small.
        for i in range(len(line_offsets) - 1):
            if line_offsets[i] <= off < line_offsets[i + 1]:
                return i
        return len(lines) - 1

    def emit(kind: str, raw_pat: str, offset_expr: str, start: int) -> dict | None:
        try:
            offset = int(offset_expr.strip(), 0) if offset_expr.strip() else 0
        except ValueError:
            offset = 0

        normalized, lossy = normalize_pattern(raw_pat)
        fixed_bytes = (len(normalized) - normalized.count("?")) // 2
        if fixed_bytes < 4 or len(normalized) < 8:
            return None

        ln = line_for_offset(start)
        lo = max(0, ln - WINDOW_LINES)
        hi = min(len(lines), ln + WINDOW_LINES + 1)
        window = "\n".join(lines[lo:hi])
        ver_m = SVERSION_RE.search(window)
        opt_m = SOPTIONS_RE.search(window)
        version = ver_m.group(1) if ver_m else ""
        options = opt_m.group(1) if opt_m else ""

        return {
            "axis": axis,
            "type": raw_type,
            "family": name,
            "version": version,
            "options": options,
            "kind": kind,
            "offset": offset,
            "pattern": normalized,
            "lossy": lossy,
            "source": path.name,
            "line": ln + 1,
            "fixed_bytes": fixed_bytes,
        }

    records: list[dict] = []
    for cm in COMPARE_EP_RE.finditer(text):
        rec = emit("ep", cm.group(1), cm.group(2) or "0", cm.start())
        if rec is not None:
            records.append(rec)
    for cm in SIG_PRESENT_RE.finditer(text):
        rec = emit("sig", cm.group(1), "0", cm.start())
        if rec is not None:
            records.append(rec)
    for cm in FIND_SIG_RE.finditer(text):
        rec = emit("sig", cm.group(1), "0", cm.start())
        if rec is not None:
            records.append(rec)
    for cm in OVERLAY_RE.finditer(text):
        rec = emit("overlay", cm.group(1), cm.group(2) or "0", cm.start())
        if rec is not None:
            records.append(rec)

    return records


def main() -> int:
    ap = argparse.ArgumentParser(description="Mine DiE EP byte patterns from .sg scripts.")
    ap.add_argument("--db", required=True, help="Path to DiE db/PE/ directory.")
    ap.add_argument("--out", required=True, help="Output JSON path.")
    ap.add_argument("--limit", type=int, default=0, help="Limit files (debug).")
    args = ap.parse_args()

    db = Path(args.db).expanduser().resolve()
    out = Path(args.out).expanduser().resolve()
    if not db.is_dir():
        print(f"Not a directory: {db}", file=sys.stderr)
        return 1

    # `--db` may be `db/PE` (single format) or the parent `db/` (mine all
    # binary-format scripts). We treat both shapes equivalently — recurse
    # into known binary-format subdirs if present, else just glob *.sg.
    binary_format_dirs = ["PE", "MSDOS", "NE", "LE", "LX", "MACH", "MACHOFAT", "ELF", "Binary", "COM"]
    sg_files: list[Path] = []
    sub_present = [d for d in binary_format_dirs if (db / d).is_dir()]
    if sub_present:
        for sd in sub_present:
            sg_files.extend(sorted((db / sd).glob("*.sg")))
    else:
        sg_files = sorted(db.glob("*.sg"))
    if args.limit > 0:
        sg_files = sg_files[: args.limit]

    all_records: list[dict] = []
    file_count = 0
    for sg in sg_files:
        recs = mine_file(sg)
        if recs:
            file_count += 1
        all_records.extend(recs)

    # Sort: by axis, family, version, longest fixed_bytes first.
    all_records.sort(
        key=lambda r: (r["axis"], r["family"], r["version"], -r["fixed_bytes"])
    )

    # De-dup: collapse identical (kind, pattern, offset, family, version,
    # options) tuples — same pattern under multiple options strings is
    # still one row of intelligence.
    seen: set[tuple] = set()
    deduped: list[dict] = []
    for r in all_records:
        k = (r["kind"], r["pattern"], r["offset"], r["family"],
             r["version"], r["options"])
        if k in seen:
            continue
        seen.add(k)
        deduped.append(r)

    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fp:
        json.dump(deduped, fp, separators=(",", ":"), ensure_ascii=False)
        fp.write("\n")

    # Print a one-line summary
    axis_counts: dict[str, int] = {}
    for r in deduped:
        axis_counts[r["axis"]] = axis_counts.get(r["axis"], 0) + 1
    by_axis = ", ".join(f"{k}={v}" for k, v in sorted(axis_counts.items()))
    print(
        f"Mined {len(deduped)} unique patterns from {file_count} files "
        f"(scanned {len(sg_files)}). Axes: {by_axis}",
        file=sys.stderr,
    )
    print(f"Written: {out} ({out.stat().st_size:,} bytes)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
