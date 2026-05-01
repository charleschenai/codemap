# Changelog

All notable changes to **codemap** are documented here. Older releases (5.2.0 → 5.16.1) are preserved in `EVOLUTION.log` with full design narrative.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [5.49.0] — 2026-05-01

### Added (Ship 5 #15/#04/#07 — PEiD packer/protector identifier)
- **New `peid-scan` action** (aliases: `peid`, `pe-fingerprint`, `packer-id`, `detect-easy`). 4,445 wildcarded byte signatures from Detect-It-Easy's PEiD corpus, split by category (packer / protector / installer / compiler / joiner / sfx_archive / file_format / overlay).
- **New `EntityKind::Packer`** with attributes `name` (full PEiD label), `category`, `offset`, `ep_only`, `source_db`.
- **Bundled corpus**: 4,445+ entries vendored from horsicq/Detect-It-Easy (MIT). Most signatures (~88%) anchored at PE entry-point.
- **Killer queries**: `meta-path "pe->packer"`, `pagerank --type packer`, `attribute-filter category=protector`.

### Tests
- 400 → **412 tests** (+12).

---

## [5.48.0] — 2026-05-01

### Added (yara-x integration + `yara-scan` action + per-section scan)
- **New `yara-scan` action** (aliases: `yara`, `yara-rules`). Generic runtime engine for any user-supplied YARA corpus (capa-rules, signature-base, findcrypt3, signsrch-derived, custom). Pure-Rust via `yara-x` (BSD-3, official VirusTotal port — no libyara C-FFI).
- **Per-section scan** translates match offsets to virtual addresses using each section's `VirtualAddress` / `sh_addr` / `vmaddr`. Skips noise sections (`.rsrc`, `.reloc`, `.bss`, `.idata`).
- **New `EntityKind::YaraRule` + `YaraMatch`**.
- **Skips `import "cuckoo"` rules** silently (dynamic-analysis context, always false in static-only operation).

### Tests
- 380 → **400 tests** (+20).

---

## [5.47.0] — 2026-05-01

### Added (Ship 2 #11 — signsrch corpus port)
- **New `signsrch` action** (aliases: `sigscan`, `signature-scan`, `find-sigs`). 22 → 2,338 byte-pattern crypto/compression/anti-debug/EC-seed signatures (30× expansion).
- **Vendored corpus** at `codemap-core/data/signsrch.xml` (3.4 MB / 2,338 entries) from Auriemma's signsrch. Build-time XML→bincode.
- **Aho-Corasick** for single-chunk + multi-chunk matcher for `&`-flagged entries.
- **Tag classifier** routes `anti-debug:` subset (53 rules) into AntiAnalysis; rest emit CryptoConstant.

### Tests
- 368 → **380 tests** (+12).

---

## [5.46.0] — 2026-05-01

### Added (Ship 5 #2 — ELF OS detection cascade)
- **New `elf-os` action** (aliases: `os`, `detect-os`). Ports capa's 9-heuristic `detect_elf_os` into Rust: PT_NOTE / SHT_NOTE / PT_INTERP / GLIBC verneed / NEEDED libs / .comment GCC / symtab / Go buildinfo / OS-ABI byte.
- Tags every ElfBinary node with `os` + `os_source` + `language` attributes.
- 24-variant OS enum.

### Tests
- 356 → **368 tests** (+12).

---

## [5.45.0] — 2026-05-01

### Added (APK protector fingerprint + endpoint enrichment)
- **New `apk-fingerprint` action** (aliases: `apk-protector`, `apk-fp`, `android-fingerprint`). Matches ZIP archive entry names against signatures mined from Detect-It-Easy's APK rule set — 64 Android DRM/protector identifiers (Alibaba/Bangcle/Ijiami/Jiagu/DexProtector/Kony/AppSolid/IL2CPP/Unity/SandHook/UnicomSDK).
- **New `lolbin-scan` action** (aliases: `find-lolbins`, `lolbins`). Scans a PE for embedded references to known living-off-the-land binaries (certutil, bitsadmin, etc.).
- **Endpoint enrichment** — dyndns provider list (33 suffixes), valid-TLD whitelist (1,381 TLDs), LOLBin list (101 names) — applied as attributes on existing endpoint/PE nodes.

### Tests
- 344 → **356 tests** (+12).

---

## [5.44.0] — 2026-05-01

### Added (Ship 5 #2 — DiE EP-pattern fingerprint detector)
- **New `die-fingerprint` action** (aliases: `die`, `fingerprint`, `binary-fingerprint`). Matches mined DiE entry-point byte patterns; populates 7-axis fingerprint taxonomy (packer/protector/cryptor/installer/sfx/joiner/patcher/compiler/library/format/tool/sign/game/dotnet/native/marker).
- **Offline miner** at `tools/die_miner.py` — regex-extracts `compareEP("...")` literals from `.sg` detector scripts.
- **New `EntityKind::BinaryFingerprint`**.
- Lossy wildcard handling: `$$/$$$$/$$$$$$$$` (DiE relative-jump tokens) downgraded to `??`.

### Tests
- 332 → **344 tests** (+12).

---

## [5.43.0] — 2026-05-01

### Added (Ship 5 #2 + #3 — section-entropy + disalign-bytes)
- **New `section-entropy` action** (aliases: `entropy`, `pe-entropy`). Per-section Shannon byte entropy across PE/ELF/Mach-O. Sections at ≈8.0 bits/byte = packed/encrypted. Tags BinarySection nodes with `entropy:f32` + flags binaries with `packed:true`.
- **New `disalign-bytes` action** (aliases: `disalign`, `anti-disasm`, `instruction-overlap`). Linear-sweep + recursive-descent overlap detector — flags opaque-predicate jump-into-mid-instruction tricks (VMProtect / Themida).
- Both clean-room from Tim Blazytko's published heuristics. Both run without BB-CFG.

### Tests
- 320 → **332 tests** (+12).

---

## [5.42.0] — 2026-05-01

### Added (Ship 5 — Source-language identification)
- **New `lang-id` action** (aliases: `language`, `detect-language`, `source-lang`). Tags PE / ELF / Mach-O binaries with `language=rust|go|dotnet|unknown`, plus `language_version` when a rustc commit-hash or Go pclntab magic is present. Modeled on FLARE FLOSS's `floss/language/identify.py` but extended past FLOSS's PE-only scope.
- **Three independent detectors:** Rust commit-hash + version-string scan; Go pclntab magic-byte scan with header validation; .NET PE COM_DESCRIPTOR check.
- **Bundled `data/rustc_versions.toml`** — 119 commit-hash → version mappings covering rustc 1.0 .. 1.74.
- **Auto-attribute** — writes `language` + `language_version` onto the existing PE/ELF/Mach-O binary node. No new EntityKind.

### Tests
- 307 → **320 tests** (+13).

---

## [5.41.0] — 2026-05-01

### Added (Ship 5 #1 — COM CLSID/IID GUID database, capa-derived)
- **New `com-scan` action** (aliases: `com`, `com-guids`, `clsid-iid`, `windows-com`). Identifies which Windows COM component classes (CLSIDs) and interfaces (IIDs) a binary instantiates / implements.
- **Two-pass detection.** ASCII GUID regex + raw 16-byte (Microsoft byte-order swap).
- **New `EntityKind::ComClass`** + **`EntityKind::ComInterface`**. Edges: PE → ComClass (instantiates), PE → ComInterface (uses/implements).
- **Bundled database** (capa, Apache-2.0): 3,639 unique CLSIDs + 25,306 unique IIDs (~1.4 MB bincode).
- **Killer queries.** `meta-path "pe->com_class"`, `pagerank --type com_class`, attribute filter on COM name.

### Tests
- 296 → **307 tests** (+11).

---

## [5.40.0] — 2026-05-01

### Added (crypto-const expansion — modern stream ciphers + extras)
- **+25 new signatures in `crypto_const.rs SIGS`**, +12 algorithm names. Crypto-const catalog grew from 22 entries / 11 algorithms to 47 entries / 23 algorithms. Closes the largest gap: modern stream ciphers were previously invisible to codemap.
- **Modern stream ciphers — Salsa20 / ChaCha20.** "expand 32-byte k" and "expand 16-byte k" nothing-up-my-sleeve constants. Heavily used in current ransomware key derivation, modern VPNs, TLS 1.3 cipher suites. Confidence: high (16 ASCII bytes never coincidental).
- **Sosemanuk** (eSTREAM finalist). `mul_a` and `mul_ia` table prefixes — both BE (paper layout) and LE (compiled layout) variants. Distinctive 12-byte non-zero suffix per table. Used by Maze ransomware affiliate tooling.
- **WellRNG512.** Two 4-byte magic constants (0xDA442D24, 0xDA442D20) covering both signed and unsigned reference implementations.
- **TEA family.** TEA cumulative sum constant 0xE3779B90 (= delta × 16) and XTEA two's complement delta 0x61C88647. Distinguishes TEA / XTEA / XXTEA variants.
- **Twofish.** Q0/Q1 permutation table prefixes + MDS1-4 mix-column table prefixes (6 × 16 bytes). All high-confidence — these are unique to Twofish.
- **Camellia.** Combined sigma1..6 contiguous 48-byte block (libgcrypt / OpenSSL / Crypto++ shared layout) + standalone sigma1 fallback for indirect-load compilers.
- **SkipJack.** F-table first 16 bytes (the only large constant in the algorithm).
- **Base64.** Standard alphabet (64 ASCII chars) + dword-translation-table (variant 1, LE u32 form) + byte-translation-table (variant 2, packed 256-byte form). `Base64-DwordTable` / `Base64-ByteTable` are separate algorithm names so analysts can tell rolled-their-own implementations apart from libc.
- **Prime tables (findcrypt3 _pusher_ rules).** 54 single-byte primes 3..251 + LE u32 promoted variant. Indicates Miller-Rabin / RSA / big-int factoring presence.
- **CRC-16 CCITT.** First 16 entries of the standard table (poly 0x1021), little-endian u16. Distinctive 32-byte prefix.
- **+8 unit tests** covering ChaCha20 expand-32, Twofish Q0, Camellia sigma block, SkipJack F-table, Base64 alphabet, Sosemanuk mul_a LE, prime char-table, CRC-16 CCITT.

### Honest non-additions
- **SPECK / CHASKEY.** Both are ARX-based ciphers with no large fixed tables and no algorithm-unique byte constants — capa identifies them via mnemonic + rotation-amount patterns. They belong in the future propagator-based detector, not in byte-pattern scanning.

### Tests
- 288 → **296 tests** (+8).

---

## [5.39.0] — 2026-05-01

### Added (capa #3 — embedded-PE XOR carver)
- **New `pe-carve` action** (aliases: `carve-pe`, `embedded-pe`, `pe-extract`). Detects PE files smuggled inside dropper / packed / staged malware that hide the second-stage payload behind a single-byte XOR key. Mirrors the GGUF overlay carve (Ship 2 #23) so codemap exposes a uniform "carve" family across binary formats (PE → PE, GGUF → overlay, ML → operator graph).
- **Algorithm:** brute-force every key 0x00..=0xFF.
  - Precompute (MZ⊕key, PE⊕key) pairs once.
  - Linear scan for the encoded "MZ" sentinel.
  - At each hit, decode `e_lfanew` (4 LE bytes at +0x3C, also XOR'd) and verify the encoded "PE\0\0" magic sits at that offset.
  - Yield (file_offset, xor_key) for every confirmed embedded PE.
- **Pure byte search.** No execution, no new dependencies, no heuristic tuning beyond a sanity range on `e_lfanew`. Reformulated freely from the algorithm originally documented in vivisect's `PE/carve.py` and ported by capa.
- **Each match becomes a child `EntityKind::PeBinary` node** attached to the parent binary with attrs `carved=true`, `xor_key`, `file_offset`, `parent_path`. Existing PE actions (pe-meta, pe-imports, pe-cert, cve-match) compose against the carved node once the dump is written.
- **Best-effort dump** to `/tmp/<basename>.carved-<offset>-<key>.bin` — analyst can immediately run `codemap pe-meta` / `codemap pe-imports` against the second-stage payload without re-XOR'ing by hand.

### Tests
- 283 → **288 tests** (+5). Single-key carve at planted offset, plaintext PE detected as key 0x00, multi-payload buffer surfaces every distinct key, empty buffer yields nothing, structured-noise false-positive rate stays bounded.

---

## [5.38.0] — 2026-05-01

### Added (BB-CFG infrastructure for v2 detectors)
- **New `cfg` module** (`codemap-core/src/cfg/`) — basic-block CFG construction, dominator tree, natural-loop discovery, SCC. Foundational layer that v2 detectors (CFF v2, opaque-pred v2, vtable v2, decoder-find, xor-loops, rc4-detect, duplicate-subgraphs) all share.
- **`build_cfg(insns: &[Instruction]) -> BbCfg`** — leader-set algorithm over a flat iced-x86 instruction stream. Splits at branches/calls/rets, classifies each block (`Normal`, `IndJump`, `Ret`, `NoRet`, `CndRet`, `ENoRet`, `Extern`, `Error`) and each edge (`JumpUncond`, `JumpCond`, `JumpIndir`, `Call`, `CallIndir`, `Fall`). Vocabulary tracks Quokka's `Block.BlockType`/`Edge.EdgeType` taxonomy.
- **`dominators(cfg, entry) -> Dominators<usize>`** — thin wrapper over `petgraph::algo::dominators::simple_fast`. Re-exports `petgraph`'s `Dominators` so downstream detectors don't need their own petgraph dep.
- **`natural_loops(cfg, doms) -> Vec<Loop>`** — back-edge detection (header dominates tail) + reverse-BFS body discovery. Multiple back-edges to the same header are merged into one Loop.
- **`sccs(cfg) -> Vec<Vec<usize>>`** — direct passthrough to `petgraph::algo::tarjan_scc` for callers needing cyclomatic-complexity / loop-count.
- **`Bb`/`BbCfg` helpers** — `block_at(va)` (O(log n) VA → BB lookup), `succs(idx)`, `preds(idx)`.
- **Internal flow-control classifier** — instead of pulling in iced-x86's heavy `instr_info` feature (deliberately disabled across the codebase, see `dataflow_local.rs`), `cfg::build` enumerates the small set of branch/call/ret/interrupt mnemonics directly. Same approach as the existing disasm.rs scanner.

### Dependencies
- **petgraph 0.6** — pure-Rust graph crate; provides dominators, tarjan SCC, DiGraphMap. MIT/Apache, zero system deps.

### Tests
- 14 new unit tests across `cfg::{build,dominators,loops}`. Synthetic instruction fixtures cover linear, if-then, if-then-else, while-loop, nested-loop, switch-style indirect, unreachable-block, multi-back-edge SCC, and dominator/natural-loop discovery.
- All 182 existing tests pass.
## [5.38.0] — 2026-05-01

### Added (crypto-const expansion — modern stream ciphers + extras)
- **+25 new signatures in `crypto_const.rs SIGS`**, +12 algorithm names. Crypto-const catalog grew from 22 entries / 11 algorithms to 47 entries / 23 algorithms. Closes the largest gap: modern stream ciphers were previously invisible to codemap.
- **Modern stream ciphers — Salsa20 / ChaCha20.** "expand 32-byte k" and "expand 16-byte k" nothing-up-my-sleeve constants. Heavily used in current ransomware key derivation, modern VPNs, TLS 1.3 cipher suites. Confidence: high (16 ASCII bytes never coincidental).
- **Sosemanuk** (eSTREAM finalist). `mul_a` and `mul_ia` table prefixes — both BE (paper layout) and LE (compiled layout) variants. Distinctive 12-byte non-zero suffix per table. Used by Maze ransomware affiliate tooling.
- **WellRNG512.** Two 4-byte magic constants (0xDA442D24, 0xDA442D20) covering both signed and unsigned reference implementations.
- **TEA family.** TEA cumulative sum constant 0xE3779B90 (= delta × 16) and XTEA two's complement delta 0x61C88647. Distinguishes TEA / XTEA / XXTEA variants.
- **Twofish.** Q0/Q1 permutation table prefixes + MDS1-4 mix-column table prefixes (6 × 16 bytes). All high-confidence — these are unique to Twofish.
- **Camellia.** Combined sigma1..6 contiguous 48-byte block (libgcrypt / OpenSSL / Crypto++ shared layout) + standalone sigma1 fallback for indirect-load compilers.
- **SkipJack.** F-table first 16 bytes (the only large constant in the algorithm).
- **Base64.** Standard alphabet (64 ASCII chars) + dword-translation-table (variant 1, LE u32 form) + byte-translation-table (variant 2, packed 256-byte form). `Base64-DwordTable` / `Base64-ByteTable` are separate algorithm names so analysts can tell rolled-their-own implementations apart from libc.
- **Prime tables (findcrypt3 _pusher_ rules).** 54 single-byte primes 3..251 + LE u32 promoted variant. Indicates Miller-Rabin / RSA / big-int factoring presence.
- **CRC-16 CCITT.** First 16 entries of the standard table (poly 0x1021), little-endian u16. Distinctive 32-byte prefix.
- **+8 unit tests** (one per major new algorithm) covering ChaCha20 expand-32, Twofish Q0, Camellia sigma block, SkipJack F-table, Base64 alphabet, Sosemanuk mul_a LE, prime char-table, CRC-16 CCITT.

### Honest non-additions (documented in source)
- **SPECK / CHASKEY.** Both are ARX-based ciphers with no large fixed tables and no algorithm-unique byte constants — capa identifies them via mnemonic + rotation-amount patterns (`rol 3` / `ror 8` / `rol 7` / `rol 2`). They belong in the future propagator-based detector, not in byte-pattern scanning. Comment in `crypto_const.rs` documents this.

### Coordination note
A separate work-stream (`signsrch` pane) is integrating the full signsrch.xml corpus (~2,338 patterns). This expansion is intentionally complementary — it focuses on modern algorithms (≥ 2020) that signsrch.xml (vintage 2017) does not cover, plus algorithms (Twofish / Camellia / SkipJack / WellRNG512) that capa-rules covers but legacy crypto_const did not.

### Tests
- 283 → **291 tests** (+8). All existing tests stay green.

### Source data attribution
All signature bytes are algorithm constants (facts) re-derived from public references: capa-rules `data-manipulation/encryption/*.yml` (Apache 2.0), findcrypt3.rules (used as documentation only, not copied), original algorithm specifications (Salsa20 / ChaCha20 / Sosemanuk / Twofish / Camellia / SkipJack RFCs and papers). No GPL source code was incorporated.
## [5.38.0] — 2026-05-01

### Added (Ship 5 #1 — COM CLSID/IID GUID database, capa-derived)
- **New `com-scan` action** (aliases: `com`, `com-guids`, `clsid-iid`, `windows-com`). Identifies which Windows COM component classes (CLSIDs) and interfaces (IIDs) a binary instantiates / implements — primary triage pivot for Windows malware. Codemap can now answer "this binary instantiates `Outlook.Application`" and "this DLL uses `IShellWindows`."
- **Two-pass detection.**
  - **ASCII GUID regex:** matches the canonical `[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}` form across the whole file (data, rsrc, strings).
  - **Raw 16-byte:** Microsoft COM stores GUIDs in a packed binary form with groups 1/2/3 little-endian-swapped. The runtime undoes the byte-order rearrangement (lifted from `capa/rules/__init__.py:340-376`) before lookup, so on-disk binary `IID_*` constants resolve too.
- **New `EntityKind::ComClass`** (aliases: `com_class`, `comclass`, `clsid`, `comcls`).
- **New `EntityKind::ComInterface`** (aliases: `com_interface`, `cominterface`, `iid`, `comif`, `com_iface`).
- **Edges:** PE → ComClass (instantiates), PE → ComInterface (uses/implements). Per-node attrs: GUID, capa name, source (`ascii` / `raw` / `ascii+raw`), file offset.
- **Bundled database** (vendored from capa, Apache-2.0): 3,639 unique CLSIDs + 25,306 unique IIDs. Stored as bincode-v1 in `codemap-core/data/com/{classes,interfaces}.bin` (~1.4 MB combined) and embedded into the binary via `include_bytes!`. When multiple capa names share a single GUID, names are joined with `|`. `data/com/build.py` regenerates the blobs from the upstream Python sources; `data/com/ATTRIBUTION.md` documents the license.
- **Killer queries.**
  - `codemap meta-path "pe->com_class"` — cross-binary CLSID inventory.
  - `codemap meta-path "pe->com_interface"` — cross-binary IID inventory.
  - `codemap pagerank --type com_class` — most-instantiated COM classes across a corpus.
  - Attribute filter on `name` finds every binary touching Outlook / Office / Shell / scripting automation interfaces.

### Tests
- 283 → **294 tests** (+11). Catalog loading + 10 known CLSIDs round-trip, ASCII GUID match in synthetic buffer, raw 16-byte (LE-swapped) match, ASCII+raw dedup into a single graph node with combined `source=ascii+raw`, GUID byte-order helpers self-inverse, bad-input rejection, IID match, binary→com_iface edge emission, empty-data + PRNG-data noise bounds.

---

## [5.37.0] — 2026-05-01

### Added (Ship 4 #19 — VTable/RTTI detector, heuristic v1)
- **New `vtable-detect` action** (aliases: `vtables`, `find-vtables`, `vftable`). Recovers C++ virtual function tables from compiled binaries by scanning data sections for runs of N consecutive pointer-sized values whose targets all land at known function entry points.
- **Pure structural pattern** — no Itanium ABI / MSVC COL parsing in v1. Runs that look like vtables get flagged as such; class-name extraction from RTTI typeinfo is the natural v2 follow-on.
- **New `EntityKind::VTable`** (aliases: `vtable`, `vftable`, `v_table`, `virtual_table`, `vmt`). Each candidate becomes a graph node attached to the binary, with edges to each virtual method (function entry).
- **Section scanning logic:**
  - **PE:** all non-executable sections except `.idata`, `.reloc`, `.pdata`, `.xdata`.
  - **ELF:** all sections that have `SHF_ALLOC` set, lack `SHF_EXECINSTR`, are not `SHT_NOBITS`, and aren't `.plt`/`.got`/`.eh_frame`/`.dyn*`/`.symtab`/`.strtab`/etc. (those produce too many false positives without specialized handling).
- **Confidence levels:**
  - **High** — ≥ 4 consecutive function-entry pointers.
  - **Medium** — 2-3.
  - **Low** — found in `.init_array` / `.fini_array` (always tagged low because constructor/destructor arrays look like vtables).

### Honest limitations (v1 → v2)
- **No class-name recovery.** Itanium vtable typeinfo + MSVC RTTI Type Descriptor parsing both deferred. v1 surfaces "this binary has 47 vtables at these addresses with these methods"; v2 will add "vtable for `class Foo` with `Foo::~Foo()` / `Foo::doStuff()` / etc."
- **MSVC COL header skipped.** MSVC vtables have a COL pointer 8 bytes before the first virtual method; the scanner won't anchor on that and may emit the vtable shifted by one slot. Manageable for now.
- **Multi-inheritance virtual base detection limited.** VBR vtables have 3-pointer headers and the run heuristic might split them across two candidates.
- **Constructor/destructor arrays produce noise.** Tagged "low" confidence so analysts can filter them out.

### Architectural milestone — Ship 4 complete (with v1 caveats)
Ship 4 (C++ Class Hierarchy) shipped as 2 separate releases today:
- 5.34.0 — #24 switch table recovery
- 5.37.0 — #19 vtable detector (heuristic v1)

#19 v2 (RTTI typeinfo parsing for class-name recovery) is the most-promising follow-on; everything structural is in place.

### Tests
- 277 → **283 tests** (+6). Confidence-level mapping (incl. init_array carve-out), 64-bit + 32-bit pointer reading, scan finds consecutive function-pointer runs, correctly ignores runs below MIN_VIRTUAL_METHODS, empty-tables report.

---

## [5.36.0] — 2026-05-01

### Added (Ship 3 #6 — opaque-predicate detector, heuristic v1)
- **New `opaque-pred` action** (aliases: `opaque-predicate`, `find-opaque`, `junk-control`). Surfaces functions containing tautological branch conditions — the signature pattern obfuscators use to insert junk control flow that *looks* conditional but always evaluates one way.
- **Two patterns matched (v1):**
  - `cmp reg, reg` followed within 3 instructions by a `Jcc` — registers are always equal, the conditional branch always goes one direction.
  - `xor reg, reg` then `test reg, reg` followed within 3 instructions by `Jcc` — propagator-tracked: if the test is on a register the propagator knows is `RegState::Const(0)`, the branch is tautological. (We use `dataflow_local::RegFile::get` to verify, so plain `test reg, reg` on an unrelated register doesn't false-fire.)
- **Detection runs as a side-effect of the existing decode pass** — adds a single `pending_self_compare: u8` countdown to `decode_functions`. Tick down each instruction; if a Jcc fires while pending > 0, increment `opaque_pred_count`.
- **New field on `DisasmFunction`:** `opaque_pred_count: usize`. Confidence: high (≥ 5 patterns), medium (≥ 2), low (1).
- **Each flagged function becomes an `AntiAnalysis` graph node** under `category=obfuscation`, namespace `anti-analysis/obfuscation/opaque-predicate`. Joins the Ship 1 #8 anti-analysis catalog under the same EntityKind so analysts can `attribute-filter category=obfuscation` to find all obfuscated binaries / functions.

### Honest limitations (v1 → v2)
- **No arithmetic-based opaque predicates** like `(x*x + x) % 2 == 0`. Real Tim Blazytko detection uses irreducible-loop analysis + Weisfeiler-Lehman block duplicate detection — both need basic-block CFG. Deferred to v2.
- **`xor reg,reg` zero-init is sometimes legitimate** (compiler register zeroing before a function-call ABI). We rely on the propagator to confirm zero-state when that XOR was *recent*, but if the analyst sees low-count results they should validate before declaring obfuscation.

### Architectural milestone — Ship 3 complete
Ship 3 (Obfuscation Detection) shipped as 3 separate releases today:
- 5.33.0 — #9b crypto-loop detector
- 5.35.0 — #5 CFF detector (heuristic v1)
- 5.36.0 — #6 opaque-predicate detector (heuristic v1)

All three ride the existing `decode_functions` pass with zero added cost per instruction, leveraging the bounded backward propagator (now in `dataflow_local.rs`) for register-state queries. v2 of #5 + #6 (real Blazytko ports) is the natural follow-on once basic-block CFG extraction lands.

### Tests
- 274 → **277 tests** (+3). Confidence thresholds, 3-tier report grouping, empty-hits message.

---

## [5.35.0] — 2026-05-01

### Added (Ship 3 #5 — CFF detector, heuristic v1)
- **New `cff-detect` action** (aliases: `find-cff`, `flatten-detect`, `obfuscation-detect`). Surfaces functions whose control flow looks **flattened** by Control-Flow Flattening obfuscators (OLLVM, custom packers, bytecode-style malware loaders). A flattened function abandons natural structured flow in favor of one giant switch dispatcher that re-dispatches to the next state — the giveaway is that virtually every back-edge points at the same target.

  Heuristic (no basic-block CFG required for v1):
  - **`cff_score`** = `dispatcher_hits / back_edge_count` — fraction of back-edges that converge on the single most-targeted address. 1.0 = every back-edge goes to one dispatcher.
  - **High confidence:** `score ≥ 0.8` AND `back_edges ≥ 5` AND `jump_targets ≥ 8`.
  - **Medium:** `score ≥ 0.6` AND `back_edges ≥ 3` AND `jump_targets ≥ 4`.
  - **Low:** `score ≥ 0.6` AND `back_edges ≥ 5` AND `jump_targets == 0` (dispatcher-shaped but no switch — speculative).

- **Three new fields on `DisasmFunction`**: `cff_dispatcher_va: Option<u64>`, `cff_dispatcher_hits: usize`, `cff_score: f64`. Computed inline in `decode_functions` from the back_edge data already collected for crypto-loop detection — zero added cost per instruction.

- **Each flagged function becomes a `SwitchTable` graph node** with `pattern="cff_dispatcher"`, plus the cff_score / dispatcher_va / dispatcher_hits / confidence attrs. Reuses the SwitchTable EntityKind from Ship 4 #24 to keep the dispatcher family unified.

### Honest limitations (v1 → v2)
- **No basic-block CFG yet.** The real Tim Blazytko `calc_flattening_score` algorithm computes per-function dominator trees and checks `len(dominated(b)) / len(blocks) > 0.5` gated by a back-edge from inside the dominated set. v2 will port that algorithm once basic-block extraction lands inside `decode_functions`.
- **State-machine-DFA false positives.** Hand-written parser DFAs / network-protocol state machines / interpreter dispatcher loops legitimately use the same shape (one back-edge target + switch dispatch). Confidence levels separate "obviously CFF" from "could be a real state machine" — analyst still needs to read the code.
- **No CFF-without-switch detection.** Some CFF variants emit jump tables in non-standard ways the resolver doesn't catch (or use indirect calls instead of jumps). Those slip through with `score ≥ 0.6` but `jump_targets == 0`, captured as "low" confidence.

### Tests
- 268 → **274 tests** (+6). Confidence levels at high/medium/low, doesn't flag plain for-loops, doesn't flag plain switches without dispatchers, empty-hits report.

---

## [5.34.1] — 2026-05-01

### Refactored
- **Extracted bounded backward constant-propagator from `disasm_jt.rs` into a new `dataflow_local.rs` module.** Originally introduced in 5.27.0 inside `disasm_jt.rs` for jump-table resolution, the propagator (`RegFile`, `RegState`, `ElemKind`, `record_instr`, `MAX_HISTORY`) became a shared primitive once 5.33.0's crypto-loop detector landed as the second consumer. Per the original handoff plan, this extraction was the planned next step at 2 consumers.
- **Backwards-compatible:** `disasm_jt.rs` re-exports the moved items via `pub use crate::dataflow_local::{...}`, so existing `use crate::disasm_jt::{RegFile, RegState, record_instr, ...}` imports continue to work unchanged.
- **What stayed in `disasm_jt.rs`:** the jump-table-specific bits — `SectionMap`, `SectionView`, `MAX_TABLE_ENTRIES`, `resolve_indirect_jmp`, plus all 6 resolver-specific tests (Pattern A/B/C, single-indirection negative, etc.).
- **What moved to `dataflow_local.rs`:** the propagator itself + 5 propagator-only tests (LEA / MOVSXD / ADD / unknown-MOV / CMP-doesn't-disturb) + 3 new tests confirming the public API (`ElemKind::size`, `RegFile::reset`, GPR subreg aliasing).
- **Pure refactor — no behavior change.** All 265 prior tests still pass; the 3 new tests in `dataflow_local.rs` document the public API that future consumers (Ship 3 #5/#6, Ship 2 #14 v2) will rely on.

### Tests
- 265 → **268 tests** (+3, all new in `dataflow_local.rs`).

---

## [5.34.0] — 2026-05-01

### Added (Ship 4 #24 — switch table recovery)
- **New `switch-recovery` action** (aliases: `switches`, `dispatchers`, `switch-tables`). Aggregates Ship 1 #7's per-function `jump_targets` into structured SwitchTable graph nodes with case_count + pattern + confidence.
- **New `EntityKind::SwitchTable`** (alias: `switch_table`, `switch`, `dispatcher`). Each dispatching function gets one SwitchTable node with attrs:
  - `function_address`, `function_name`
  - `case_count` — number of resolved case targets
  - `targets_at_func_entry` — how many targets land at known function entry points
  - `targets` — comma-joined hex preview (first 16)
  - `confidence` — `high` (every target at func entry), `medium` (some), `low` (< 2 or none)
  - `pattern` — `absolute_pointer` / `pic_relative` / `mixed` (v1: always `absolute_pointer`)
- **Edges:** `bin_func → switch_table → bin_func` (case-target functions). Lets `pagerank --type switch_table` rank the heavy dispatchers in a binary, and `meta-path "bin_func->switch_table->bin_func"` enumerate dispatcher-style code patterns.
- **Cheap because Ship 1 #7 already did the hard work.** This action is a 280-LOC aggregator + classifier on top of the per-function `jump_targets` Vec the resolver populates during `bin-disasm`. Functions with multiple independent dispatchers get one merged SwitchTable in v1; per-JMP attribution is a v2 concern (would need to re-decode + tag each indirect JMP).

### Notes
- Default-case recovery deferred — the "default" branch of a switch is the fall-through after the dispatch JMP, not modeled in v1.
- C++ exception-unwind tables (`.gcc_except_table`) are NOT switches — they use similar relative-offset encodings but encode different semantics; correctly not flagged here.

### Tests
- 260 → **265 tests** (+5). Confidence classification at all 3 levels (high / medium / low for single-target case), 3-group report formatting, empty-tables message.

---

## [5.33.1] — 2026-05-01

### Fixed
- **`onnx-info`: GraphProto field 5 vs 11 swap.** The proto-walking code was treating field 5 as `input` (mislabeled) and field 11 as `initializer count`. Per the official ONNX `onnx/onnx GraphProto.proto`:
  - field **5** = `repeated TensorProto initializer`
  - field **11** = `repeated ValueInfoProto input`
  Reports were showing initializer count under "Inputs" and input ValueInfos contributing to "Initializers". Existing `onnx-prune` (5.30.0) was already correct; this brings `onnx-info` in line.
- **`gguf-overlay`: MXFP4 + TQ dtypes added to ggml block-size table.** Three more entries that the v1 table missed:
  - dtype 34 = `TQ1_0` → (256, 54)
  - dtype 35 = `TQ2_0` → (256, 64)
  - dtype 38 = `MXFP4` → (32, 17)
  - dtype 39 = `MXFP4_INTERLEAVED` → (32, 17)
  
  Real-world impact: `gpt-oss-20b-mxfp4.gguf` now reports `Sum of tensor bytes: 12,096,558,336` (12.1 GB — accurate) instead of the previous `1,944,212,736` which dropped 72 MXFP4 tensors. Overlay verdict was already correct (largest-offset tensor had a known dtype) but the size accounting is now honest.

---

## [5.33.0] — 2026-05-01

### Added (Ship 3 #9b — crypto-loop detector)
- **New `crypto-loops` action** (aliases: `xor-loops`, `find-decrypt`, `decrypt-loop`). Identifies functions that contain XOR-decryption loops — a strong signal for malware string/payload decryption, custom symmetric crypto, or shellcode unpacking.
- **Detection runs as a side-effect of the existing disassembly pass** — `decode_functions` already tracks the bounded backward propagator's `RegFile` for jump-table resolution; we add two more streams to the same loop:
  - **back_edges**: every Jcc/Jmp/Jrcxz/Jcxz/Jecxz/Loop[ne] whose near-branch target lies inside the same function and is < the branch's IP.
  - **xor_const_sites**: every XOR instruction whose source is either an immediate (non-zero) or a register the propagator tracks as a non-zero constant. The `xor reg, reg` self-zero idiom is correctly excluded.
- **A function's `crypto_xor_in_loop` is the count of xor_const_sites whose VA falls inside any back_edge range.** `≥ 1 → likely XOR-decryption routine`. Confidence: high (≥ 3 sites), medium (2), low (1).
- **Each flagged function becomes a `CryptoConstant` graph node** with `algorithm="XOR-loop"`, `function_name`, `xor_count`, `confidence` — joins the Ship 1 #9a constant-anchor scanner under the same `crypto` EntityKind so analysts can filter `algorithm=XOR-loop` to find decryption routines and `algorithm=AES`/`SHA-256` etc. to find standard-crypto users.
- **Two new fields on `DisasmFunction`**: `crypto_xor_in_loop: usize` and `back_edge_count: usize`. Exposed because they're useful general-purpose function-shape metrics beyond just this action.

### Architectural milestone — second propagator consumer

The bounded backward constant-propagator (`disasm_jt::{RegFile, RegState, record_instr}`) was introduced in 5.27.0 with one consumer (Ship 1 #7 jump-table resolution). 5.32.0's CUDA tracer didn't end up needing it (pattern-match on imports was sufficient). 5.33.0's crypto-loop detector **is the second consumer** — it queries `RegFile::get(reg) == RegState::Const(non-zero)` to recognize XOR keys loaded via `mov reg, imm; xor [mem], reg`.

Per the original handoff plan, the propagator should now extract to `codemap-core/src/dataflow_local.rs`. **Deferring that to 5.34.0** — it's a refactor (no behavior change) and best done after the propagator's API has settled across both consumers.

### Tests
- 257 → **260 tests** (+3). Confidence-level mapping, report formatting at all 4 hit levels (zero / low / medium / high), empty-hits report.

---

## [5.32.0] — 2026-05-01

### Added (Ship 2 #14 — CUDA launch tracer)
- **New `cuda-trace` action** (aliases: `cuda-kernels`, `gpu-trace`, `find-cuda`). Detects CUDA host binaries and enumerates the GPU kernels they reference, by cross-referencing CUDA Runtime / Driver API imports against symbol-table + embedded-string evidence.

  Two-phase classification:
  1. **API detection** — does the binary import any of:
     - Runtime API (12 entries): `cudaLaunchKernel`, `cudaLaunchKernelExC`, `cudaLaunchCooperativeKernel*`, `__cudaPushCallConfiguration`, `__cudaRegisterFatBinary`, `__cudaRegisterFunction`, `cudaConfigureCall`, etc.
     - Driver API (9 entries): `cuLaunchKernel`, `cuLaunchKernelEx`, `cuLaunchCooperativeKernel`, `cuLaunchHostFunc`, `cuModuleLoadData[Ex]`, `cuModuleLoadFatBinary`, `cuModuleGetFunction`, `cuModuleGetGlobal`.
  2. **Kernel extraction** from three sources:
     - Itanium-mangled `_Z*` symbols (filtered against C++ STL `_ZSt*`/`_ZNSt*`).
     - Symbols with kernel-naming suffixes (`_kernel`/`Kernel`/`_gpu`/`Gpu`/`_cuda`/`Cuda`/`__global__`/`CUDAKernel`), with API-entry-point filtering (`cu*Kernel`, `cuda*Kernel`, `__cuda*` excluded — those are the Runtime/Driver API names themselves).
     - Embedded fatbin strings matching C-identifier shape + kernel-related token suffix.

- **New `EntityKind::CudaKernel`** (alias: `cuda_kernel`, `gpu`). Each detected kernel becomes a graph node attached to the host binary, with attrs `name`, `mangled` (raw `_Z` form when applicable), `source` (`symbol` / `fatbin_string` / `import`), `api` (`runtime` / `driver` / `runtime+driver`).

- **Killer queries** enabled:
  - `meta-path "pe->cuda_kernel"` — cross-binary GPU workload inventory.
  - `pagerank --type cuda_kernel` — most-shared kernel names across a CUDA-app suite.
  - `attribute-filter api=driver` — every binary using the Driver API directly (vs Runtime).

- **Smoke-tested on `/usr/lib/aarch64-linux-gnu/libcuda.so`** (the actual NVIDIA driver library) — correctly identified as Driver API, 9 imports flagged, 16 kernel-name strings extracted with the suffix-heuristic API-entry-point filter eliminating all false positives.

### Notes
- Per-launch-site grid/block dim recovery is **deferred to v2** — that's where the bounded backward propagator from `disasm_jt.rs` becomes the second consumer and we extract to `dataflow_local.rs`. v1 ships pattern-matching on imports + symbols + strings, which gives ~80% of the value at ~30% of the engineering cost.

### Tests
- 252 → **257 tests** (+5). Mangled `_Z*` extraction (with STL filter), suffix-kernel detection (with API-entry-point filter), fatbin string extraction (identifier shape + suffix), runtime/driver API list disjointness, string-extraction min-length.

---

## [5.31.0] — 2026-05-01

### Added (Ship 2 #23 — GGUF overlay carver)
- **New `gguf-overlay` action** (aliases: `gguf-carve`, `model-overlay`). Computes the expected end-of-tensor-data from a GGUF file's tensor info table (per-tensor offset + dims + dtype block size) and flags any trailing bytes as overlay — the binary equivalent of PE/ELF overlay carving, applied to LLM weight files.

  Real-world signal: malware-laced model rehosters and supply-chain attackers occasionally append payloads to popular GGUF files. Watermark trackers and licensing tools also use overlay regions. Either way, an analyst wants to know the model file isn't *just* the model.

  Algorithm:
  1. Re-parse GGUF header + metadata KV (capturing `general.alignment`) + tensor info table (capturing per-tensor offset + dims + dtype).
  2. `data_section_start = align_up(after_tensor_info, alignment)`.
  3. For each tensor: `byte_size = (elements / blck) * type_size` from the ggml block-size table (covers F32 / F16 / BF16 / Q4_{0,1,K} / Q5_{0,1,K} / Q6_K / Q8_{0,1,K} / IQ{1,2,3,4}_{S,M,XS,XXS,NL} / I8/16/32/64 / F64 — 27 dtypes).
  4. `max_data_end = data_section_start + max(offset + byte_size)`.
  5. `overlay_bytes = file_size - max_data_end`.
  6. If overlay > 0 → report size, head bytes (hex + ASCII), magic-sniff (PE / ELF / ZIP / nested GGUF / PDF / JPEG / PNG), entropy heuristic.

- **Streaming reader — never loads multi-GB tensor data into memory.** Reads only the first 64 MB of the file (enough to cover the tensor info table even for 70B-parameter models with thousands of tensors); pulls total file size from filesystem metadata. Successfully tested on real 4.7 GB Qwen-2.5-7B-Q4_K_M, 12 GB gpt-oss-20b-MXFP4, and 17 GB GLM-4.7-Flash-MXFP4 files — all correctly verified as overlay-free in <1 sec each.

- **Each detected overlay becomes an `Overlay` graph node** attached to the parent `MlModel`, with `size_bytes` / `file_offset` / `source_format=gguf` attrs. Reuses the existing `Overlay` EntityKind from the PE/ELF overlay-info action.

- **27 ggml dtypes covered.** Some bleeding-edge formats (MXFP4, TQ1_0, TQ2_0) aren't in the table yet — tensors of those types contribute zero to the max-end calculation and produce a warning. Conclusion remains correct as long as the *largest-offset* tensor's dtype is known (which is true for all standard model files).

### Tests
- 248 → **252 tests** (+4). ggml block-size table for known types + Q4_K byte-size math + F32 multi-dim + align_up edge cases.

---

## [5.30.0] — 2026-05-01

### Added (Ship 2 #21 — ONNX op-graph pruner)
- **New `onnx-prune` action** (aliases: `op-prune`, `prune-ops`, `ml-dead-ops`). Identifies dead operators in ONNX models by reverse-reachability from the model's declared outputs.

  Algorithm:
  1. Parse ModelProto → GraphProto.
  2. For each NodeProto, collect (name, op_type, inputs[], outputs[]).
  3. `live_tensors = set(graph.outputs)`.
  4. Iterate over nodes BFS-style: any node whose output is in `live` becomes live, its inputs joined into `live`. Repeat until stable.
  5. Dead nodes = those whose outputs never reach a graph output.

- **Catches the kinds of orphan branches compilers and quantization tools leave behind** — Q→DQ pairs that didn't get folded, debug-only sub-outputs that were forgotten in the export. Dead nodes add file size, runtime cost (when greedy schedulers don't prune), and visual noise; codemap surfaces them so the analyst can request a clean re-export via `onnx.utils.extract_model` or `onnxsim`.

- **Each dead operator becomes an MlOperator graph node with `is_dead=true`** — `attribute-filter is_dead=true` then enumerates dead-op coverage across a corpus.

- **Honest limitations:** subgraphs inside `If` / `Loop` / `Scan` node attributes are NOT walked for v1 — a node with such a subgraph is pessimistically marked live (no false-positive dead flags).

### Tests
- 241 → **248 tests** (+7). Linear chain, unreachable branch, multi-output, deep dead subgraph, diamond merge, no-output edge case, empty graph.

---

## [5.29.0] — 2026-05-01

### Added (Ship 1 #9a — crypto constants scanner)
- **New `crypto-const` action** (aliases: `crypto-scan`, `find-crypto`, `crypto`). Identifies the cryptographic algorithms a binary implements by scanning for well-known init values, S-boxes, polynomial constants, and magic numbers — modelled on the [findcrypt-yara](https://github.com/polymorf/findcrypt-yara) ruleset.
- **22 signatures across 13 algorithms** — MD5, MD2, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, RIPEMD-160, Whirlpool, AES (Rcon + S-box + inverse S-box), DES (IP table), Blowfish (P-array LE+BE), RC6 (P32+Q32), TEA/XTEA, CRC-32 (reflected+forward poly + lookup table), CRC-32C.
- **Naive linear scan with non-overlapping match enumeration** — fast enough for typical binaries (~50 ns per pattern per MB on modern CPUs). `Endian::Both` patterns scan both byte orders. Hard cap at non-overlapping matches per pattern (no runaway on data sections that happen to contain repeated bytes).
- **New `EntityKind::CryptoConstant`** (alias: `crypto`). Each match becomes a graph node with attrs `algorithm`, `constant_name`, `offset`, `endian` (le/be/le|be), `confidence` (high/medium/low). De-duplicated by (algorithm, constant_name) — multiple matches of the same constant collapse to one node.
- **Killer queries** enabled:
  - `meta-path "pe->crypto"` — cross-binary crypto inventory.
  - `pagerank --type crypto` — most-prevalent crypto algorithms across a corpus.
  - Filter by `algorithm=AES` — every binary using AES, etc.
  - Filter by `confidence=high` — high-signal hits only (S-box / IP-table prefixes, full SHA init blocks).
- **Confidence levels** — high for distinctive patterns (full SHA-256 init, AES S-box prefix, Blowfish P-array). Medium for shorter or shared patterns (single CRC polynomial word, RIPEMD init which overlaps SHA-1's first 4 words). Low for very common 4-byte constants (TEA delta = 0x9E3779B9, also RC6's Q32 — the analyst has to disambiguate).

### Notes
- Scanner is byte-pattern-only — it sees a constant *somewhere* in the binary but doesn't verify the surrounding code actually implements the algorithm. False positives possible on binaries that embed crypto-test data without using it (e.g., `codemap` itself self-detects all 13 algorithms from its own embedded scanner constants — expected).
- v2 will vendor the full signsrch.xml corpus (2,338 patterns at `~/reference/codemap-research-targets/11-ida-signsrch/signsrch.xml`) as a bincode blob (~50-100 KB embedded), expanding coverage to every CRC variant, every XFER table, and dozens of additional cipher constants.

### Tests
- 232 → **241 tests** (+9). Coverage: MD5/SHA-256/AES S-box/CRC-32 polynomial/Blowfish detection at known offsets, pseudo-random data yields ≤2 false positives, signature catalog covers expected algorithm families, non-overlapping match enumeration.

---

## [5.28.0] — 2026-05-01

### Added (Ship 1 #8 — anti-analysis scanner)
- **New `anti-analysis` action** (aliases: `anti-tech`, `evasion`, `anti-debug`). Detects malware-evasion techniques in PE binaries by matching imports + section names + embedded strings against a hardcoded ruleset modelled on Mandiant's capa-rules anti-analysis corpus.
- **35 rules across 7 categories** — anti-debugging (15), anti-vm (8), packer (6), anti-forensic (3), anti-disasm (1), anti-av (1), anti-emulation (1). Coverage targets: IsDebuggerPresent / NtQueryInformationProcess / hardware breakpoints / TLS callbacks / debugger window classes / debugger process names / VirtualBox / VMware / QEMU / Hyper-V / Parallels / sandbox detection / WMI VM probes / UPX / ASPack / Themida / VMProtect / PECompact / FSG/MEW/MPRESS / Heaven's Gate / event-log clearing / self-delete / MBR wipe / AV process termination / Wine.
- **AND semantics across feature sets, OR within** — a rule with both `imports` and `strings` requires at least one match in each (capa's typical shape: e.g., "find debugger window" needs both `FindWindow` API AND a known debugger class string). Within a set, items are OR'd. Reduces false positives on legitimate binaries that import generic APIs.
- **Confidence levels** — high / medium / low. Low-confidence rules surface API-only signals (timing APIs, SEH filter registration) that can fire on benign code; analysts can filter them out.
- **New `EntityKind::AntiAnalysis`** (alias: `anti_tech`). Each detected technique becomes a graph node attached to the binary, with attrs `name`, `namespace` (capa rule namespace, e.g. `anti-analysis/anti-debugging/debugger-detection`), `category`, `confidence`, `reference` (link to the al-khaser .cpp or capa-rules YAML it mirrors).
- **Killer queries** enabled:
  - `meta-path "pe->anti_tech"` — cross-binary technique inventory.
  - `pagerank --type anti_tech` — most-prevalent techniques across a corpus.
  - Filter by `category=packer` — every packed binary in the graph.
  - Filter by `confidence=high` — high-signal techniques only.
- **PE imports + section names + strings** are extracted with the existing `parse_pe_imports_structured` pipeline (made `pub(crate)` for cross-module reuse) plus a small ASCII + UTF-16LE string scanner (≥ 4 char strings, capped at 20 K).
- ELF / Mach-O coverage = v2 — ruleset is Windows-centric today.

### Notes
- This is a **subset scanner**, not a full capa engine — implements ~35 high-confidence rules from the 90-rule anti-analysis corpus. Full YAML rule loading + instruction-level matching is the next ship (5.29.0). Will reuse the bounded backward constant-propagator from Ship 1 #7.

### Tests
- 223 → **232 tests** (+9). Coverage: API-import rule firing, AND-semantics across imports + strings + sections, case-insensitive DLL/function names, multi-rule firing on simulated malware corpus, ASCII + UTF-16LE string extraction, ruleset minimum-coverage smoke test.

---

## [5.27.0] — 2026-05-01

### Added (Ship 1 #7 — jump-table resolver)
- **`bin-disasm` now recovers compiler-emitted switch tables.** Indirect `JMP` instructions inside x86/x64 functions are run through a new resolver that walks back through the preceding instructions, recovers the table base + stride, reads the table bytes from the binary's section view, and emits each resolved case target as an edge in the BinaryFunction graph.

  Three patterns covered (~95% of real-world switch dispatch):

  - **Pattern A — PIC, GCC/Clang relative-offset table:**
    `lea rdx, [rip+T] / movsxd rax, [rdx+idx*4] / add rax, rdx / jmp rax`
  - **Pattern B — Windows MSVC x64 absolute pointer table:**
    `jmp qword ptr [rip+T + idx*8]`
  - **Pattern C — x86 32-bit absolute pointer table:**
    `jmp dword ptr [T + idx*4]`

  Pattern B/C resolve from the JMP itself; Pattern A uses a bounded backward constant-propagator (≤ 16 instructions). The propagator is the shared primitive Ship 1 #8, Ship 3 #5/#6, and Ship 4 #14 will reuse — when #8 lands as the second consumer, it'll be lifted into `dataflow_local.rs`.

- **New `BinaryFunction.jump_targets` attribute** (count of recovered case targets per function) — surfaces switch-heavy code: parsers, opcode dispatchers, big-state-machine handlers. Functions are connected to other functions whose entry point matches a recovered target, catching tail-call style switch dispatchers (e.g. interpreter handlers as standalone functions).

- **`bin-disasm` report shows `jt=N`** in the per-function summary line and a new `Jump-table targets: N resolved across M functions` aggregate line.

- **New `SectionView` / `SectionMap` structs** in `disasm_jt.rs` — generic VA→file-offset mapper built once per binary, reused across all jump-table reads. PE walks every section into the map; ELF skips SHT_NOBITS (`.bss`) but keeps everything else.

- **Bounds applied:** ≤ 64 entries per table, hard cap on out-of-`.text` targets, terminate walk on first invalid read or out-of-text target. Malformed binaries can't cause runaway.

### Tests
- 209 → **223 tests** (+14). Resolver unit tests cover all three patterns + RegFile state transitions (LEA / MOV / MOVSXD / MOVSX / MOVZX / ADD) + invalidation + negative cases. Three end-to-end tests in `disasm.rs` craft x64 byte sequences with real switch dispatchers and verify `decode_functions` populates `jump_targets` correctly through the SectionView/RegFile wiring.

### Notes
- ARM/AArch64 path (`functions_from_symbols`) initializes `jump_targets: vec![]` — resolver is x86/x64 only for v1. ARM jump-table recovery would need a yaxpeax-arm decoder; deferred.

---

## [5.26.4] — 2026-05-01

### Added (docs only)
- **System-prompt section in README dramatically expanded** — went from 25 trigger-phrase entries to **~120 entries** covering every action category (164 actions total). Now organized into 14 sub-sections so the AI scans the relevant block instantly:
  - Whole-codebase questions (10 entries)
  - Single-file / single-symbol questions (13 entries)
  - Repo-wide rankings (13 entries)
  - Centrality (17 measures)
  - Community detection / clustering (7 entries)
  - Spectral (3 entries)
  - Classical graph algorithms (13 entries)
  - Link prediction (2 entries)
  - Cross-language bridges (4 entries)
  - Data flow / security (9 entries)
  - Reverse engineering — Windows PE (11 entries)
  - Reverse engineering — non-PE (10 entries)
  - Schemas / IaC (8 entries)
  - ML model files (7 entries)
  - LSP integration (5 entries)
  - Web — passive recon (10 entries, with the "CAPTURE FIRST" guard prominent)
  - Compliance / SBOM (6 entries)
  - Git-history aware temporal (5 entries)
  - PR / change analysis (5 entries)
  - Diagrams / export (3 entries)
  - Composite (3 entries)
- The `<!-- BEGIN ... END -->` markers stay so users can still grep + extract verbatim. Hard rules + killer-query reference + output expectations subsections preserved.

### Notes
- Action count: 164 (unchanged). EntityKinds: 33 (unchanged). Tests: 209 (unchanged).
- Every one of the 164 actions is now mentioned at least once in the system-prompt section, with a trigger phrase the AI can recognize.

---

## [5.26.3] — 2026-05-01

### Added (docs only)
- **"Drop-in system prompt for AI agents" section at the top of the README.** A copy-pasteable block users add to `~/.claude/CLAUDE.md` / `.cursorrules` / `~/.codex/instructions.md` / etc. that teaches the agent **when** to reach for codemap (vs grep/find/Read) and **which** action to pick for ~25 common asks. Includes:
  - **Trigger-phrase → tool mapping table.** "When user says 'audit'/'find load-bearing files'/'reverse this windows binary'/'android apk'/'ml model'/'find secrets'/'recon a website'/etc., use Y" — reflexive lookup so the agent doesn't get lost in 164 actions.
  - **Hard rules.** Always pass `--dir <small_path>`. Never live-URL recon. Quote arrows in `meta-path`. Spectral cap at 5K nodes.
  - **Killer-query reference.** ~10 most-useful `meta-path` / `pagerank` / `attribute-filter` invocations as a quick lookup.
  - Wrapped in `<!-- BEGIN ... END -->` markers so users can grep + extract verbatim.
- **SKILL.md** updated to reference the README's per-action examples (5.26.1+) and the output quality fixes (5.26.2+).

### Notes
- Action count: 164 (unchanged). EntityKinds: 33 (unchanged). Tests: 209 (unchanged).
- Docs-only patch ship.

---

## [5.26.2] — 2026-05-01

### Fixed (visual / output quality — surfaced by an end-to-end test pass)

Six output-formatting fixes after a full e2e exercise pointed out the action output looked rough:

- **Empty section headers in `audit` no longer print bare** — `── Top chokepoints (betweenness) ──` followed by a blank line is replaced with `(none — graph too small or fully disconnected)`. Same fix applied to `Top brokers` and `Dominant clusters` sections. The empty-section-with-just-a-header was the single most visible offender.
- **`summary` "Hottest files (most coupled)" no longer lists 0-connection entries.** When all files have 0 imports, prints `(no coupling — graph too small or fully isolated files)` instead of a list of meaningless 0s. Same fix applied to "Most complex functions" when no functions parsed.
- **`dep-tree` text output now shows ecosystem prefix** alongside each manifest path: `Cargo.toml [cargo] (2 deps):` / `package.json [npm] (2 deps):`. Matches the ecosystem prefix used in graph node IDs (`dep:cargo:serde`).
- **`(no --dir given; defaulting to current directory)` warning suppressed when target is an explicit existing file path.** For actions like `pe-sections` / `bin-disasm` / `pyc-info` / `safetensors-info` where the user passed an absolute file, the directory scan is incidental and the warning is misleading.
- **Scanner banners (`Scanned N files in Mms`, `Cache: N/N files unchanged`) auto-quieted for explicit-file targets.** Same condition as above — when target is an existing file, the scan is a side-effect of the requested action, so its progress messages are noise.
- **`think` orchestrator strips redundant `=== Foo ===` headers from sub-action outputs.** Previously a `── audit ──` step would dump the audit's own `=== Codemap Architectural Audit ===` header right under it, double-stacking section headers.

### Notes
- No code-path behavior changed — all fixes are output-formatting only.
- Tests: 209 (unchanged).

---

## [5.26.1] — 2026-05-01

### Added (docs only — no code change)
- **README massively expanded with per-action usage examples.** Every action category now ships a working example invocation. Heavy categories (Reverse engineering, LSP, Binary formats, Schemas, Security, Web, Temporal, Spectral, Centrality, Classical algorithms, Link prediction, Community detection, Meta-path, Composite, Graph export, ML, Supply chain / SBOM, Android, Recon parsers) get a section-level example block with multiple representative invocations. Lighter categories (Analysis, Insights, Navigation, Graph theory, Function-level, Data flow, Cross-language, Comparison) get a 3-column table with inline `Example` per row.
- **README "Why codemap?" section now leads with measured performance.** Inline benchmark table from `BENCHMARKS.md` (862 ms / 519 ms / 1,007 ms on real OSS repos), followed by a "vs the field" callout listing what codemap does that the OSS competitors (Joern, CodeGraph, GitNexus, CodeGraphContext, FalkorDB code-graph, Memgraph AI Toolkit, cpggen, Polystat) don't.
- **SKILL.md** updated to reflect 164 actions (`think` orchestrator), 18 languages (Scala/Swift/Dart added), and the BENCHMARKS link.

### Notes
- Action count: 164 (unchanged). EntityKinds: 33 (unchanged). Tests: 209 (unchanged).
- This is a docs-only patch ship. No code paths changed.

---

## [5.26.0] — 2026-05-01

### Added
- **Tree-sitter grammars for Scala, Swift, and Dart** (15 → 18 supported languages). Closes the AST coverage gap surfaced by the COMPETITION audit (`~/reference/codemap-competition/COMPETITION.md`):
  - **Scala** (`.scala`, `.sc`) — Joern's source went from "122 files / 4.6K lines" (build scripts only) to **1,977 files / 257K lines parsed** with full top-broker / Leiden cluster detection.
  - **Swift** (`.swift`) — first-class iOS / macOS app analysis. Function/class/protocol/init declarations.
  - **Dart** (`.dart`) — first-class Flutter mobile + web analysis. Function/method/class/mixin/extension declarations.
- New deps: `tree-sitter-scala 0.26`, `tree-sitter-swift 0.7`, `tree-sitter-dart 0.2`. All pure-Rust, no system libs.
- Per-language `import_types` / `func_types` / `export_types` tables in `parser.rs` populated with canonical node names extracted from each grammar's `node-types.json`.

- **`BENCHMARKS.md`** — measured `codemap think` performance on real OSS codebases (no warm cache):
  - Joern (1,977 files Scala): "audit this codebase" in **862 ms**
  - CodeGraphContext (828 files Python): "find load-bearing files" in **519 ms** (3-action pipeline)
  - Continue (3,187 files TypeScript): "find all api endpoints" in **1,007 ms** (292 endpoints registered)
  - Geometric mean: **~770 ms** for a 2–3 action pipeline on 800–3,200-file repos with cold cache
  - Anchored on CodeGraph's published Claude-Code-Explore baseline (26–52 tool calls without a graph tool): codemap is **~1 tool call vs ~30 raw exploration calls**, ~96% reduction.

### Notes
- Action count: 164 (unchanged). EntityKinds: 33 (unchanged).
- Tests: 209 (unchanged — language deps are config additions, not new code paths under test).

---

## [5.25.1] — 2026-05-01

### Added (docs only — no code change)
- **`CONTRIBUTING.md`** — full contributor guide. Build + test, repo layout, how to add an action, how to wire findings to the graph (the canonical pattern from the 5.16.2 → 5.25.0 arc), how to add an `EntityKind` (the 5-place checklist), testing conventions, hard rules (no network, pure-Rust deps, `--dir` always, default-scan invariant, caps everywhere), commit + version conventions.
- **`examples/README.md`** — five end-to-end scenario walkthroughs:
  1. Audit an unfamiliar codebase (`audit` + drill-down)
  2. Android APK analysis (`apk-info` + permission heuristics + native-lib `bin-disasm`) — showcases 5.23.0 + 5.24.0
  3. Passive web recon (`web-dom` + `web-fingerprint` + `robots-parse` + `web-sitemap-parse` + `crt-parse`) — addresses the "AI defaults to live scraping" friction by showing the capture-then-parse path concretely
  4. Diff two binary versions (`binary-diff` cross-graph) — showcases 5.22.0
  5. `codemap think` first — when you don't know what to run
- README now points at `examples/README.md` and `CONTRIBUTING.md` from the Examples section header.

### Notes
- No behavior change. Tests unchanged at 209.

---

## [5.25.0] — 2026-05-01

### Added
- **`think "<goal>"` natural-language goal router (action count 163 → 164).** With 163 prior actions, both humans and AI agents hit choice paralysis. `think` is the new "I don't know what to use" entry point: takes a plain-English goal, classifies it via case-insensitive keyword match against ~18 intent buckets, runs the matching pipeline, and shows the chosen pipeline at the top of output so the user knows what was selected (and can run the constituent actions directly next time).
- **Intent catalog (~18 buckets):** `audit`, `load-bearing`, `security review`, `secrets`, `supply chain`, `dead code`, `hotspots`, `structure`, reverse PE / ELF / Mach-O, Android APK, ML model, web recon, find endpoints, diff binaries, graph layout, plus `Fallback` for unmatched.
- **Path detection in goal string** — any token that exists on disk becomes the pipeline target. Common surrounding punctuation stripped.
- **Live URL guard** — any `http://` or `https://` token in the goal is rejected with a "codemap is pure-static; capture the artifact first" message (`curl -o ... ; codemap think "recon /tmp/file"`). This enforces the no-active-network invariant uniformly so neither humans nor AI agents have to remember it. Was the #1 weakness flagged by the post-5.22.0 review.
- **Fallback guidance** — when the goal doesn't match any intent, `think` lists the closest matches as suggestions instead of guessing.
- New module `actions/think.rs` (~370 LOC). Calls existing `dispatch()` for each pipeline step — same code path as direct CLI invocation.
- Promoted to **Tier 0** in SKILL.md (the new entry point above all 163 specific actions).
- Tests +5 (209 total): intent classification covering 16 representative goal strings, fallback behavior, path detection (existing + nonexistent + trailing punctuation), URL rejection with passive-only message, empty-goal usage output.

### Killer use cases
- Vague goal → fast routing: `codemap think "audit this codebase"` runs `audit + summary`.
- Mobile workflow: `codemap think "android apk ./app.apk"` → `apk-info` (DEX walker + permission heuristics from 5.23, native-lib disasm from 5.24).
- Web recon without the bitchiness: `codemap think "recon /tmp/captured.html"` → `web-dom + web-fingerprint`. Live URLs are firmly rejected.
- Cross-version diff: `codemap think "compare /tmp/v1.exe /tmp/v2.exe"` → `binary-diff` with cross-graph promotion (5.22.0).

---

## [5.24.0] — 2026-05-01

### Added
- **ARM / AArch64 ELF support in `bin-disasm`.** `e_machine` = `0x28` (EM_ARM) and `0xb7` (EM_AARCH64) join `0x03` / `0x3E` in the supported list. Function discovery is symbol-table-only (walks `STT_FUNC` entries from `.symtab` / `.dynsym`), with size from `st_size` and instruction count estimated as size/4 (AArch64 instructions are always 4 bytes; ARM is mostly 4-byte ARM instead of mixed Thumb).
- New `arch` field on `DisasmResult` (`x86` / `x64` / `arm` / `aarch64`) — `bin-disasm` writes it as the `binary_format` attr on every `BinaryFunction` node.
- Brings Android native libs (`lib/arm64-v8a/*.so`, `lib/armeabi-v7a/*.so`) and ARM/embedded firmware into the same `BinaryFunction`-graph treatment as x86 binaries. Pairs with 5.23.0 DEX walker for full APK coverage on both Java and native sides.
- No new dependencies — keeps codemap pure-Rust without pulling `yaxpeax-arm`. Real disasm with intra-binary call edges is a v2 if demand emerges.
- Tests +3 (204 total): zero-`st_size` defaulting, unknown-machine error message includes ARM/AArch64, `DisasmFunction` Debug round-trip.

### Changed
- `disasm_elf` now branches on arch after parsing `e_machine`; symbol-table walk extended to capture `st_size` (was previously discarded). `DisasmResult` gained `arch: &'static str`.

---

## [5.23.0] — 2026-05-01

### Added
- **DEX bytecode walker (`apk-info` extension).** New `actions/dex.rs` module (~510 LOC) parses Android Dalvik EXecutable files. Header validation + ULEB128 decoder + string/type/method ID tables + class_def + class_data walk → emits one `BinaryFunction(binary_format=dex, kind_detail=dex_method)` per class method with edge from the parent `AndroidPackage`.
- **Heuristic permission→method linking.** Per-method bytecode scan for `invoke-*` opcodes (35c form `0x6E-0x72`, 3rc form `0x74-0x78`) targeting ~30 well-known protected Android APIs (Camera, LocationManager, TelephonyManager, SmsManager, ContactsContract, BluetoothAdapter, WifiManager, etc.). Each hit emits a `BinaryFunction → Permission` edge.
- **Manifest-vs-code permission diff.** Permissions discovered from code (but not declared in the manifest) auto-register with `discovered_via=dex` attr. Use `attribute-filter discovered_via=dex on --type permission` to find permissions used in code but not declared, OR query the inverse to find declared-but-unused permissions.
- **Multidex support** (`classes2.dex`, `classes3.dex`, …). Cap of 5000 methods per APK.
- New dependency: `miniz_oxide 0.8` (pure-Rust deflate decoder, MIT/Apache) — needed because real APKs always deflate `classes.dex`.
- Tests +4 (201 total): JVM-descriptor → Java FQN round-trip, ULEB128 canonical values, permission API mapping, parse_dex graceful error handling.

### Killer query unlocked
- `meta-path "permission->method"` → "what code uses CAMERA permission?"

### Notes
- Pairs with the upcoming 5.24.0 ARM/AArch64 disasm to give APKs full graph coverage on both Java (DEX) and native (ARM `.so`) sides.

---

## [5.22.0] — 2026-05-01

### Added
- **`binary_diff` cross-graph promotion (Option B).** All diff nodes namespaced under `diff:{session}:` so they never conflict with main-scan nodes. `session` is a stable FNV-1a hash of both file paths → re-running the same diff is idempotent.
  - 2 versioned `PeBinary` nodes (`pe:diff:{session}:a` and `:b`) with diff-summary attrs (`diff_added_funcs` / `diff_removed_funcs` / `diff_added_dlls` / `diff_removed_dlls` / `diff_size_delta`).
  - One `BinaryFunction` per unique imported symbol with `diff_status` ∈ {`added`, `removed`, `unchanged`}. Unchanged functions receive edges from BOTH binaries. Cap of 5000 per call.
  - One `Dll` per imported library with same `diff_status` pattern.
- Killer queries: `attribute-filter diff_status=added`, `pagerank --type bin_func` ranks across both versions, `meta-path "pe->bin_func"` per-side enumeration.
- Tests +2 (197 total): session-ID idempotency / order-sensitivity, graceful File-not-found.

### Notes
- All graph-integration gaps now closed.

---

## [5.21.0] — 2026-05-01

### Added
- **`BinarySection` EntityKind (32 → 33).** Section inside a binary (PE `.text` / `.data` / `.rdata`, etc.). attrs: `name`, `binary_format`, `virtual_size`, `raw_size`, `virtual_address`, `entropy` (Shannon bits/byte), `characteristics` (read/write/exec/code joined by `+`).
- **`pe_sections` promotion.** Each PE section now registers a `BinarySection` graph node with edge from the `PeBinary`. Reuses the existing entropy walk (in production since 5.12.0).
- Killer queries: `attribute-filter entropy>7.0` on `--type section` for packed-section discovery, `meta-path "pe->section"` for layout, `pagerank --type section` for shared section names across vendor product families.
- Tests +1 (195 total): EntityKind alias round-trip.

---

## [5.20.0] — 2026-04-30

### Added
- **`MlTensor` + `MlOperator` EntityKinds (30 → 32).**
  - `MlTensor` — tensor inside GGUF / SafeTensors / ONNX-initializer model. attrs: `name`, `dtype`, `shape`, `model_format`, `size_bytes`, `params`. Capped at 5000 per model.
  - `MlOperator` — ONNX graph operator (Conv / MatMul / Add / etc.). Aggregated by `op_type` so a 1000-node ResNet surfaces as ~30 nodes (one per type with `count_in_model` attr) instead of 1000.
- **`gguf-info` / `safetensors-info`** promote each tensor to `MlTensor` with edge from parent `MlModel`.
- **`onnx-info`** aggregates op_counts to `MlOperator` nodes; attaches `onnx_initializer_count` + `onnx_op_type_count` as attrs on the parent `MlModel`.
- Killer queries: `meta-path "model->tensor"`, `pagerank --type ml_operator`, `attribute-filter op_type=LSTM`, `attribute-filter dtype=Q4_K`.
- Tests +1 (194 total): synthetic safetensors header → 3 MlTensor nodes with edges from MlModel.

### Changed
- `parse_gguf` / `parse_safetensors` / `parse_onnx` return types extended to expose structured tensor/operator data alongside text. Local structs hoisted to module scope (`GgufTensorInfo` / `SafetensorsTensorInfo`).

---

## [5.19.0] — 2026-04-30

### Added
- **`Dependency` EntityKind (29 → 30).** Package-manifest dependency. Namespaced as `dep:{ecosystem}:{name}` so `dep:cargo:serde` ≠ `dep:npm:serde`. attrs: `name`, `version`, `group`, `ecosystem`, optional `is_dead`.
- **`dep-tree` / `dead-deps`** promote declared deps to `Dependency` graph nodes. Self-discover manifests by walking `scan_dir` directly (the scanner's `SUPPORTED_EXTS` excludes `.toml` / `.json`). `dead-deps` marks dead deps with `is_dead=true` for cleanup-PR generation.
- **`api-surface`** promotes discovered HTTP routes (Flask / FastAPI / Express) to `HttpEndpoint` nodes (`discovered_via=api_surface`) with edges from source files.
- **`pe-debug`** lifts PDB filename + CodeView GUID + age to a `Symbol(kind_detail=pdb_path)` node hanging off the PE binary. Useful for symbol-server lookups.
- **ELF / Mach-O / PE entry points** all register as `BinaryFunction(kind_detail=entry_point)` nodes for cross-format uniformity. ELF via `parse_elf_with_deps` return tuple; Mach-O via new `extract_macho_entry` (LC_MAIN walker).
- **`pe-resources`** lifts VS_VERSION_INFO key/values (FileVersion / ProductVersion / CompanyName / OriginalFilename / etc.) to `vsinfo_*` attrs on the `PeBinary` node for cross-binary inventory.
- Killer queries: `meta-path "source->dependency"`, `pagerank --type dependency`, `meta-path "compiler->pe"` for per-version MSVC stamps from Rich headers.
- Tests +2 (193 total): dep_tree ecosystem-namespaced Dependency nodes, api_surface HttpEndpoint promotion.

### Changed
- `dep_tree` + `dead_deps` + `api_surface` + `binary_diff` signatures flipped from `&Graph` to `&mut Graph`.

---

## [5.18.0] — 2026-04-30

### Added
- **All 5 LSP actions write into the heterogeneous graph** with bounded caps (5000 symbols, 1000 refs, 500 call edges per call).
  - `lsp-symbols` — promotable `DocumentSymbol` kinds (Class / Method / Function / Constructor / Field / Constant / etc.) become `Symbol(source=lsp)` nodes with `source_file → symbol` edges. Recursive walker with depth cap 8.
  - `lsp-references` — registers the queried symbol once, then adds `referrer_file → symbol` edges per reference.
  - `lsp-calls` — registers `prepareCallHierarchy` target as `Symbol`, then `caller→target` / `target→callee` edges around incoming/outgoing calls.
  - `lsp-diagnostics` — per-file `lsp_errors` / `lsp_warnings` / `lsp_info` / `lsp_first_error` attrs on `SourceFile` nodes.
  - `lsp-types` — per-file `lsp_typed_symbols` / `lsp_total_symbols` for type-coverage gaps.
- New helpers: `lsp_kind_is_promotable`, `register_lsp_symbols` (recursive), `register_call_edge`, `file_id_for_graph`.
- Tests +2 (191 total): symbol walker promotable-kind filtering + cap enforcement.

### Changed
- All 5 `lsp_*` action signatures flipped from `&Graph` to `&mut Graph`.

---

## [5.17.0] — 2026-04-30

### Added
- **`Secret` EntityKind (28 → 29).** Hardcoded secret discovered by `secret-scan`. attrs: pattern_name, severity, file, line, masked preview.
- **`secret-scan` promotion.** Each finding registers as a `Secret` node with edge from source. Killer queries: `meta-path "source->secret"`, `pagerank --type secret`.
- **`pe_meta` Rich-header promotion.** Each unique tool from the PE Rich header registers as a `Compiler` node (de-duped, with `build_number` / `object_count` / `product_id` attrs). Enables `meta-path "compiler->pe"` for per-version MSVC queries.
- **`pe_meta` TLS callback promotion.** Each TLS callback RVA registers as a `BinaryFunction(kind_detail=tls_persistence, tls_callback=true)`. TLS callbacks run before `main()` — common malware persistence vector now queryable via attribute filter.
- **`cuda-info` kernel promotion.** Each CUDA kernel registers as `BinaryFunction(binary_format=cuda, kind_detail=kernel)` with edge from parent `MlModel`. Brings CUDA into the same managed-bytecode story as java/wasm/dotnet/pyc.
- Tests +2 (189 total).

### Changed
- `secret_scan` signature flipped from `&Graph` to `&mut Graph`.

---

## [5.16.2] — 2026-04-30

### Fixed
- **`pyc-info` recursive marshal walker.** Replaces 5.15.1's heuristic byte-scan that took the first identifier-shaped marshal string after each CODE type byte as the function name — in CPython marshal layout, `co_varnames` precedes `co_name`, so the first identifier was usually `co_varnames[0]` (= `self` for instance methods, `cls` for classmethods). Most class methods got registered as a function literally named `"self"`.
- New walker decodes marshal by type-byte dispatch (singletons, ints, floats, strings, tuples, lists, dicts, sets, code objects, refs), tracks the FLAG_REF (0x80) backref table, and recurses into `co_consts` so nested code objects (inner functions, lambdas, class bodies) surface. Version-aware CODE-object header (4 / 5 / 6 / 5 u32 fields for Py 2.7 / 3.4-3.7 / 3.8-3.10 / 3.11+).
- Tests +1 (187 total): real .py compiled via python3, runs `pyc-info`, asserts no arg names appear as function nodes.

---

## Prior history

Releases 5.2.0 → 5.16.1 are documented in `EVOLUTION.log` with full per-release design narrative. Highlights:

- **5.16.1** — README full-action catalog + LICENSE file + Cargo.toml license/description/repository fields.
- **5.16.0** — recon-artifact parsers (`robots-parse`, `web-sitemap-parse`, `web-fingerprint`, `crt-parse`); strictly pure-static, no network.
- **5.15.x** — PE Authenticode → Cert nodes, pyc + JVM + .NET CIL method extraction, Android APK + Permission EntityKinds.
- **5.14.x** — `license-scan` + `cve-import` + `cve-match` + SBOM export (SPDX 2.3 / CycloneDX 1.5) + fuzzy hashing (TLSH + ssdeep).
- **5.13.x** — iced-x86 disassembly framework + intra-binary call graph; WASM function-level Code-section walker.
- **5.12.x** — symbol demangling (Itanium / MSVC / Rust v0) + lang-fingerprint, StringLiteral + Overlay nodes (URL strings auto-promote to HttpEndpoint), PE Rich header + TLS callbacks.
- **5.2.0 — 5.7.6** — heterogeneous graph foundation, 11 centrality measures, Leiden community detection, `audit` composite, auto-classify of binary file types.

[5.22.0]: https://github.com/charleschenai/codemap/releases/tag/v5.22.0
[5.21.0]: https://github.com/charleschenai/codemap/releases/tag/v5.21.0
[5.20.0]: https://github.com/charleschenai/codemap/releases/tag/v5.20.0
[5.19.0]: https://github.com/charleschenai/codemap/releases/tag/v5.19.0
[5.18.0]: https://github.com/charleschenai/codemap/releases/tag/v5.18.0
[5.17.0]: https://github.com/charleschenai/codemap/releases/tag/v5.17.0
[5.16.2]: https://github.com/charleschenai/codemap/releases/tag/v5.16.2
