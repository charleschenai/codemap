# signsrch.xml — License & Attribution

This file (`signsrch.xml`) is a vendored copy of the signsrch signature
corpus, used by codemap as a runtime-loaded data file (parsed at build
time into a bincode blob, then `include_bytes!`-d into the codemap-core
crate).

## Provenance

- **Original signature corpus:** `signsrch` by Luigi Auriemma
  (<https://aluigi.altervista.org/mytoolz.htm>). Distributed under
  GNU General Public License v2 or any later version (GPL-2-or-later).
- **XML re-pack:** `Signsrch2XML` by Sirmaus (Sat Sep 30 20:19:30 2017),
  which converted Auriemma's binary `.bms` signature DB into the
  `<pattern><p t="…">HEX</p></pattern>` XML form vendored here.
- **Upstream repository this snapshot was taken from:**
  `L4ys/IDASignsrch` IDAPython plugin (GPL-3.0). The plugin shim is
  not vendored — only the corpus data file is.

## License

The signsrch corpus inherits **GNU General Public License version 2 or
(at your option) any later version** from the upstream `signsrch` tool.
The XML file is not raw original code; it is a database of public
cryptographic constants and algorithmic byte patterns (S-boxes from
published cipher specs, IVs from RFCs, polynomial constants, etc.).
The selection and arrangement may carry a thin compilation copyright
under GPL-2-or-later.

A copy of the GPL-2 license is reproduced below for reference; the
authoritative text is at <https://www.gnu.org/licenses/gpl-2.0.html>.

## codemap usage

codemap-core itself is licensed under MIT. The signsrch corpus is
shipped as a separate data file, parsed at build time, and the
resulting bincode blob is `include_bytes!`-d into codemap-core. This
follows the established pattern (e.g. `capa-rules` shipped under
Apache, `FLOSS` rules shipped under MIT, both consumed by tools under
different licenses) of treating an immutable third-party rule corpus
as a runtime-loaded data dependency rather than statically-linked
GPL-2 source code.

Users who redistribute codemap binaries that include the signsrch
corpus should:

1. Reproduce this `signsrch.LICENSE.md` alongside the binary, OR
2. Build codemap with the corpus omitted (set
   `CODEMAP_SIGNSRCH_OPTOUT=1` at build time — falls back to the
   22-entry hand-curated catalog).

## Attribution required

When citing or redistributing this corpus, credit:

- Luigi Auriemma — original signsrch tool and signature collection
- Sirmaus — Signsrch2XML conversion (2017)
- L4ys — `IDASignsrch` IDA plugin packaging (the snapshot source)

## GPL-2-or-later notice

```
This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
```

Full GPL-2 text: <https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt>
