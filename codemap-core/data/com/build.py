#!/usr/bin/env python3
"""
Convert capa COM databases (classes.py + interfaces.py) into bincode-v1
format consumed by codemap's com_scan action.

Source: ~/reference/codemap-research-targets/01-capa/capa/features/com/
License: capa is Apache-2.0; data vendored with attribution.

Output bincode-v1 layout (little-endian, fixed-width u64 lengths):
  Vec<([u8; 16], String)>
    - u64 length prefix
    - per entry: 16 raw GUID bytes (NATURAL byte order, i.e. how the
      ASCII GUID string reads left-to-right) + u64 name-length + UTF-8
      name. Multiple capa names sharing one GUID are joined with '|'.

The raw 16-byte form Microsoft COM stores on disk is the same bytes
with groups 1/2/3 little-endian-swapped — the runtime byte-swaps the
read 16 bytes back into natural order before lookup, so the DB only
keeps one canonical form.
"""

from __future__ import annotations

import struct
import sys
from collections import defaultdict
from pathlib import Path

CAPA_ROOT = Path.home() / "reference" / "codemap-research-targets" / "01-capa"
sys.path.insert(0, str(CAPA_ROOT))

from capa.features.com import classes as C  # noqa: E402
from capa.features.com import interfaces as I  # noqa: E402


def guid_to_natural_bytes(guid: str) -> bytes:
    hex_chars = guid.replace("-", "")
    if len(hex_chars) != 32:
        raise ValueError(f"bad GUID: {guid!r}")
    return bytes.fromhex(hex_chars)


def collapse(d: dict[str, list[str]]) -> list[tuple[bytes, str]]:
    inv: dict[bytes, list[str]] = defaultdict(list)
    for name, guids in d.items():
        for g in guids:
            try:
                inv[guid_to_natural_bytes(g.upper())].append(name)
            except ValueError:
                pass
    out = []
    for guid_bytes in sorted(inv.keys()):
        names = inv[guid_bytes]
        # Stable, dedup, alpha
        joined = "|".join(sorted(set(names)))
        out.append((guid_bytes, joined))
    return out


def write_bincode(entries: list[tuple[bytes, str]], path: Path) -> None:
    with path.open("wb") as f:
        f.write(struct.pack("<Q", len(entries)))
        for guid_bytes, name in entries:
            assert len(guid_bytes) == 16
            nb = name.encode("utf-8")
            f.write(guid_bytes)
            f.write(struct.pack("<Q", len(nb)))
            f.write(nb)


def main() -> None:
    out_dir = Path(__file__).resolve().parent
    classes = collapse(C.COM_CLASSES)
    ifaces = collapse(I.COM_INTERFACES)
    write_bincode(classes, out_dir / "classes.bin")
    write_bincode(ifaces, out_dir / "interfaces.bin")
    cls_size = (out_dir / "classes.bin").stat().st_size
    ifc_size = (out_dir / "interfaces.bin").stat().st_size
    print(f"classes.bin    {len(classes):>6} entries  {cls_size:>9} bytes")
    print(f"interfaces.bin {len(ifaces):>6} entries  {ifc_size:>9} bytes")
    print(f"total          {cls_size + ifc_size:>9} bytes")


if __name__ == "__main__":
    main()
