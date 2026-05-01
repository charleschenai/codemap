# Changelog

All notable changes to **codemap** are documented here. Older releases (5.2.0 → 5.16.1) are preserved in `EVOLUTION.log` with full design narrative.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
