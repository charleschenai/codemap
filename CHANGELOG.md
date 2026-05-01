# Changelog

All notable changes to **codemap** are documented here. Older releases (5.2.0 → 5.16.1) are preserved in `EVOLUTION.log` with full design narrative.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
