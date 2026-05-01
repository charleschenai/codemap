# codemap

Rust-native codebase dependency analysis and binary reverse engineering. A single binary that scans your repo with tree-sitter AST parsers, builds a file-level import graph and a function-level call graph, and exposes 163 analysis actions — PageRank, HITS, articulation points, 17 centrality measures, Leiden community detection, dominator trees, Tarjan SCC, link prediction, temporal graph evolution, spectral analysis (Fiedler bisection + Shi-Malik clustering + eigengap), backward slicing, taint analysis, cross-language bridges, binary format analysis (PE/ELF/Mach-O/Java/WASM), schema parsing (Protobuf/OpenAPI/GraphQL/Docker/Terraform), security scanning (secrets, dependencies), web scraper blueprinting, LSP integration, and more — through a flat CLI.

No servers. No databases. No API keys. One static binary, `.codemap/cache.bincode` next to your repo for incremental scans, and a `/codemap` Claude Code skill that wraps the same binary.

**Version:** 5.24.0 | **Workspace:** `codemap-core` (library) + `codemap-cli` (binary) + `codemap-napi` (Node.js bindings) | **License:** MIT

---

## Table of Contents

- [Why codemap?](#why-codemap)
- [Installation](#installation)
- [Usage](#usage)
- [Actions](#actions)
- [Examples](#examples)
- [Output formats](#output-formats)
- [Supported languages](#supported-languages)
- [Architecture](#architecture)
- [Performance](#performance)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Why codemap?

Most code-analysis tools are either language-specific (works great for one stack, useless for the rest of your repo), GUI-bound (point and click through a web app), or Python-based (slow on anything larger than a toy). codemap is the opposite: one Rust binary, one `--dir <path> <action>` invocation, multi-language, cache-accelerated, parallel.

**What makes it work:**

- **Tree-sitter AST for every supported language.** Imports, exports, function definitions, call sites, and data-flow nodes are all extracted from real parse trees. Not regex. Not heuristics. The regex path is a fallback only for YAML/CMake and for files tree-sitter fails to parse.

- **163 actions, one dispatch.** Every analysis is a single CLI verb. `codemap --dir src pagerank` ranks files. `codemap --dir src taint req.body db.query` traces taint. `codemap --dir src risk HEAD~3` scores a PR. No sub-commands, no flags trees to memorize.

- **Heterogeneous graph (5.2.0+).** One graph holds source files, PE/ELF/Mach-O binaries, DLL/dylib imports, function symbols, HTTP endpoints, web forms, schema tables/fields, Protobuf messages, GraphQL types, OpenAPI paths, Docker services, Terraform resources, ML model files, **(5.17.0+) hardcoded secrets**, **(5.19.0+) package-manifest dependencies**, **(5.20.0+) ML tensors + operators**, and **(5.21.0+) binary sections** — all as typed nodes. Every graph algorithm (PageRank, betweenness, Leiden, etc.) runs uniformly across kinds. `meta-path SourceFile->HttpEndpoint` finds every code file that ends in an API call. `pagerank --type pe` ranks the central binaries. `pagerank --type secret` ranks files by credential-risk concentration. `pagerank --type dependency` ranks the most-used deps in a monorepo. `pagerank --type ml_operator` ranks dominant op types across an ONNX-model corpus. `meta-path "model->tensor"` inventories tensor shapes across SafeTensors / GGUF model files. `attribute-filter entropy>7.0` on `--type section` finds packed/encrypted binaries across a corpus. `audit` synthesizes betweenness + brokers + clusters into a one-page architectural risk overview, flagging "load-bearing wall" nodes (chokepoint AND broker). 33 EntityKind variants modeled on GitHub stack-graphs; pass-based mutation modeled on Joern.

- **11 centrality measures (5.2.0+).** PageRank, HITS, betweenness (Brandes 2001), eigenvector, Katz, closeness, harmonic (Marchiori-Latora 2000, handles disconnected graphs), load (Newman 2001), structural-holes / brokers (Burt 1992 — finds nodes that broker between groups), VoteRank (Zhang 2016 — top-k spreaders), group centrality, percolation (Piraveenan 2013), current-flow betweenness (Newman 2005). Each accepts a kind filter for slicing the heterogeneous graph.

- **Leiden community detection (5.3.0+).** Faithful Traag-Waltman-van Eck 2019 implementation: local moving + refinement (the "well-connected-subset" criterion that distinguishes Leiden from Louvain) + aggregation. Default for `clusters`. Auto-named by longest common path prefix or homogeneous-kind: `Cluster 1 [src/algo/*]` / `Cluster 1 [endpoint cluster]`.

- **Temporal graph analysis (5.10.0+).** `node-lifespan` bucketizes the codebase by first-seen / last-modified age and surfaces young hotspots, active veterans, and ancient stable files. `edge-churn` counts co-change commits per import edge to separate true coupling from vestigial imports. `community-evolution` reconstructs cluster memberships at N evenly-spaced historical snapshots (filtering each to nodes that existed by then) and detects BIRTH / DEATH / SPLIT / MERGE events via Jaccard. All three operate on a single `git log` pass — no checkouts, no reparse loops.

- **Spectral analysis (5.11.0+).** `fiedler` computes the algebraic connectivity λ₂ and the Fiedler vector (Fiedler 1973), then bisects the graph at the sign-cut — the partition that approximately minimizes Cheeger's constant. λ₂ also detects bottlenecks: low value = near-cut. `spectral-cluster k` runs Shi-Malik 2000 spectral clustering — projects nodes via the top-k smallest eigenvectors of the symmetric normalized Laplacian, row-normalizes the embedding (Ng-Jordan-Weiss 2002), then k-means in that space. `spectral-gap` exposes the eigenvalue spectrum and applies von Luxburg's eigengap heuristic to recommend a community count automatically. Self-contained Lanczos eigensolver with full re-orthogonalization + Jacobi rotations on the resulting tridiagonal — no LAPACK or external linalg dep. Caps at 5000 nodes; 2000-node graphs eigendecompose in < 1 s.

- **Binary reverse engineering.** 11 actions for cracking compiled Windows binaries without source code: PE import/export/resource/debug/section analysis, string extraction with SQL categorization, .NET CLR metadata parsing, Clarion DDL and dBASE schema extraction, SQL query mining with table access maps, and binary diffing. Built from studying goblin, Ghidra, Falcon, and pe-parse source code.

- **Multi-platform binary analysis.** 4 more binary actions for non-PE formats: ELF (Linux), Mach-O (macOS, including fat/universal binaries), Java `.class`/`.jar` files, and WebAssembly modules. Section entropy, symbol tables, dynamic linking, and version detection.

- **Schema/config parsing.** 5 actions for infrastructure-as-code and API specs: Protobuf `.proto` files, OpenAPI/Swagger specs (JSON/YAML), GraphQL schemas, Docker Compose service graphs with topological startup order, and Terraform resource/module maps with cross-reference detection.

- **Security scanning.** 4 actions for supply-chain and code hygiene: secret detection (AWS keys, GitHub PATs, private keys, JWTs, passwords, connection strings) with severity grouping and value masking, dependency tree parsing across 8 manifest formats, dead dependency detection via cross-referencing manifests against actual imports, and public API surface extraction.

- **Web scraper blueprinting.** 5 actions for reverse-engineering web applications: HAR file parsing into API endpoint maps, HTML DOM analysis for forms/tables/selectors, sitemap building from saved HTML directories, combined HAR+HTML scraper blueprint generation (auth recipe, pagination, rate limits), and JavaScript bundle archaeology for extracting API endpoints from minified code.

- **LSP integration.** 5 actions that connect to any Language Server Protocol server to extract symbols, references, call hierarchies, diagnostics, and type information. Works with rust-analyzer, pylsp, typescript-language-server, clangd, or any LSP-compliant server. **(5.18.0+)** Every LSP action now writes into the heterogeneous graph: `lsp-symbols` registers `Symbol` nodes with `source=lsp` (capped 5K/call), `lsp-references` adds file→symbol usage edges (capped 1K/call), `lsp-calls` adds caller→target / target→callee edges (capped 500/call), `lsp-diagnostics` and `lsp-types` attach per-file attrs (`lsp_errors` / `lsp_warnings` / `lsp_typed_symbols`) for `pagerank` ranking by error density or type-coverage gaps.

- **Bash/shell support.** 13 languages now covered with tree-sitter AST parsing, including Bash/Shell scripts (`.sh`, `.bash`). Function definitions and `source` imports are extracted from real parse trees.

- **Cross-language bridge detection.** PyO3, pybind11, TORCH_LIBRARY, Triton, CUDA kernels, monkey-patches, and YAML native-function dispatch tables are all first-class edges. A Python function calling into a C++ op registered via TORCH_LIBRARY shows up in the call graph. Most tools quietly drop these edges.

- **Incremental cache.** First scan parses every file in parallel with rayon. Subsequent scans only re-parse files whose mtime changed, via a bincode-serialized cache at `.codemap/cache.bincode`. Re-running analyses across a warm cache is effectively free.

- **Function-level call graph.** Not just "file A imports file B" — `codemap call-graph` resolves call sites to exported function targets across the imported files. Powers `dead-functions`, `complexity`, `clones`, `diff-impact`, and `entry-points`.

- **Code property graph (CPG) for data flow.** `data-flow`, `taint`, `slice`, `trace-value`, and `sinks` run on a lazily-built CPG of def/use edges. Backward slicing finds everything that contributes to a value; forward tracing finds everything a value reaches.

- **Multi-repo scans.** Repeat `--dir` to scan several repos in one pass. Imports that cross the directory boundary become real edges in the merged graph.

- **Used by other tools.** The [auditor](https://github.com/charleschenai/auditor) plugin integrates codemap as of v2.2.0 to feed its reviewers real structural data instead of whatever they find by grep.

---

## Installation

### One-line install (Claude Code plugin + CLI)

```bash
git clone https://github.com/charleschenai/codemap.git \
  ~/.claude/plugins/marketplaces/codemap \
  && bash ~/.claude/plugins/marketplaces/codemap/install.sh
```

The installer clones the repo, verifies the plugin structure, merges entries into `~/.claude/settings.json` (non-destructive, requires python3), then auto-detects the host platform via `uname -s -m` and **downloads a pre-built binary** from the latest GitHub Release. Falls back to `cargo build --release` only if no matching pre-built archive exists or `CODEMAP_BUILD_FROM_SOURCE=1` is set. Drops the binary into `~/bin/codemap` (or `/usr/local/bin/codemap` if running as root).

Pre-built artifacts are produced by `.github/workflows/release.yml` on each `v*` tag for:

| Target                     | Runner             | Tarball                          | napi addon                       |
|----------------------------|--------------------|----------------------------------|----------------------------------|
| `x86_64-unknown-linux-gnu` | `ubuntu-latest`    | `codemap-Linux-x86_64.tar.gz`    | `codemap.linux-x64-gnu.node`     |
| `aarch64-unknown-linux-gnu`| `ubuntu-24.04-arm` | `codemap-Linux-aarch64.tar.gz`   | `codemap.linux-arm64-gnu.node`   |
| `aarch64-apple-darwin`     | `macos-14`         | `codemap-Darwin-arm64.tar.gz`    | `codemap.darwin-arm64.node`      |
| `x86_64-apple-darwin`      | `macos-13`         | `codemap-Darwin-x86_64.tar.gz`   | `codemap.darwin-x64.node`        |

Cross-host binary copying is no longer the right move — the auto-detect path eliminates the "Exec format error" trap when a binary built on one architecture lands on another.

### From source (CLI only)

```bash
git clone https://github.com/charleschenai/codemap.git
cd codemap
cargo build --release -p codemap-cli
ln -sf "$(pwd)/target/release/codemap" ~/bin/codemap
```

### Verify

```bash
bash install.sh --check    # verifies plugin files, settings.json, binary on PATH
codemap --help
```

### Uninstall

```bash
bash install.sh --uninstall
```

Removes the plugin directory, cache, and `~/bin/codemap`. `/usr/local/bin/codemap` is left alone (needs sudo).

---

## Usage

```
codemap [OPTIONS] <ACTION> [TARGET...]
```

### Options

| Flag | Purpose |
|------|---------|
| `--dir <PATH>` | Directory to scan. Repeat for multi-repo scans. Defaults to current working directory. |
| `--include-path <PATH>` | Extra C/C++ include search path. Repeatable. Used during import resolution. |
| `--json` | Emit a JSON envelope (`{action, target, files, result}`) instead of human text. |
| `--tree` | For data-flow actions, render results as an ASCII tree instead of a flat list. |
| `--no-cache` | Force a fresh scan. Ignores `.codemap/cache.bincode`. |
| `--watch [SECS]` | Re-run the action every N seconds (default 2). Clears the screen each tick. |
| `-q, --quiet` | Suppress scan/cache status messages on stderr. |

### Shape

```bash
codemap --dir /path/to/src stats
codemap --dir src call-graph some_function
codemap --dir src taint req.body db.query
codemap --dir src --include-path ./third_party/include trace src/main.cpp
codemap --dir ./service --dir ./shared hotspots   # multi-repo
```

Target arguments are joined with spaces, so `codemap why a.rs b.rs` and `codemap why a.rs -> b.rs` both work (the `->` separator is stripped).

---

## Actions

All 163 actions grouped by category. Every action runs against the full graph unless it takes a target. Targets are files, function names, git refs, or patterns depending on the action.

### Analysis (14)

| Action | What it does |
|--------|-------------|
| `stats` | File count, line count, import edges, external URLs, exports. Extension breakdown. |
| `trace <file>` | Imports, importers, URLs, and exports for one file. |
| `blast-radius <file>` | BFS over `imported_by` — every file transitively depending on the target. |
| `phone-home` | Files containing external URLs, grouped and sorted by URL count. |
| `coupling <substring>` | Files that import anything containing the substring. |
| `dead-files` | Files with zero importers, excluding common entry-point basenames (`index`, `main`, `cli`, `app`, `server`, `entry`). |
| `circular` | DFS-based cycle detection with canonical rotation dedup. Top 20. |
| `exports <file>` / `functions <file>` | List exported symbols for one file (same action, two names). |
| `callers <symbol>` | Word-boundary regex search across all scanned files, filtered to exclude export/definition lines. Caps at 5000 hits. |
| `hotspots` | Top 30 most-coupled files (`imports + imported_by`). |
| `size` | Top 30 largest files by line count, with percentage of codebase. |
| `layers` | BFS depth from roots. Labels `entry points / orchestration / services / utilities / leaf modules`. Flags cross-layer violations (deeper importing shallower, skipping layers). |
| `diff <git-ref>` | `git diff --name-only <ref>` intersected with scanned files + combined blast radius. |
| `orphan-exports` | Exported symbols never referenced in files that import them. Cached per-file reads. |

### Insights (5)

| Action | What it does |
|--------|-------------|
| `health` | 0-100 score across 4 dimensions (cycles, coupling, dead files, complexity), each 0-25. Letter grade A-F. Emits recommendations below 80. |
| `summary` | One-screen dashboard — file/line/fn/export counts, language mix, cycle count, top 5 coupled files, top 5 most-complex functions. Box-drawn. |
| `decorators <pattern>` | Find Python/TS `@decorator` and Rust `#[attribute]` usages matching the (case-insensitive) pattern, resolved to the symbol they annotate. |
| `rename <old> <new>` | Preview a word-boundary rename across all scanned files. Unified diff output. No files are modified. |
| `context [budget]` | PageRank-ranked, token-budgeted repo map (file, line count, short imports, function signatures). Budget accepts raw numbers or `Nk` suffix. Default 8000. |

### Navigation (5)

| Action | What it does |
|--------|-------------|
| `why <A> <B>` | BFS shortest path A->B via imports. Falls back to reverse edges (`imported_by`) if no forward path. |
| `paths <A> <B>` | DFS all paths A->B, depth <= 10, cap 20 paths. If none forward, tries B->A. |
| `subgraph <pattern>` | BFS (both directions) from every file matching the substring — full connected component around a keyword. |
| `similar <file>` | Top 20 files ranked by Jaccard similarity over local imports + importers. |
| `structure [pattern]` | File tree with per-function outlines (line, name, params, `[pub]` marker). |

### Graph theory (7)

| Action | What it does |
|--------|-------------|
| `pagerank` | 20 iterations, damping 0.85, with dangling-node redistribution. Top 30, scores x 1000. |
| `hubs` | HITS — 20 iterations, Jacobi update, L2 normalize. Top 20 hubs (orchestrators) + top 20 authorities (core). |
| `bridges` | Iterative Tarjan articulation-point detection on the undirected projection. Ranked by connections. |
| `clusters` | Label propagation, seeded LCG PRNG, Fisher-Yates shuffle, 15 iterations. Groups >= 2 members with internal-coupling %. |
| `islands` | BFS connected components, sorted by size. |
| `dot [target]` | Graphviz DOT. Full graph, or 2-hop BFS neighborhood when a target is given. |
| `mermaid [target]` | Mermaid `graph LR`, suitable for pasting into GitHub docs. 2-hop BFS when targeted. |

### Function-level (13)

| Action | What it does |
|--------|-------------|
| `call-graph [file]` | Cross-file function calls resolved via an export map. Top 50 grouped by source function. |
| `dead-functions` | Exported functions with no callers outside their own file. Top 100. |
| `fn-info <file>` | Per-function listing for one file — start/end line, exported marker, outgoing calls. |
| `diff-functions <git-ref>` | Added / removed / modified functions between working tree and `<ref>` via regex over `git show <ref>:<file>`. Covers JS/TS, Rust, Python, Go, Ruby, Java/PHP signatures. |
| `complexity [file]` | Cyclomatic complexity + max brace nesting depth per function. Top 30 or full listing for a target file. Flags `[moderate]` (>5) and `[HIGH]` (>10). |
| `import-cost <file>` | Transitive import weight — total files and lines pulled in, plus heaviest 15 dependencies. |
| `churn <git-ref>` | Files changed since `<ref>..HEAD` x coupling = churn risk score. Top 30. |
| `api-diff <git-ref>` | Added / removed exports vs `<ref>`. JS/TS export-declaration regex. |
| `clones` | Structural clone groups — functions fingerprinted by `(line_count, call_count, param_count, is_exported)`. Skips < 3-line functions. |
| `git-coupling [N]` | Co-change analysis over last N commits (default 200). Flags pairs as `import` (expected) or `HIDDEN` (co-change without an import link — the dangerous kind). |
| `risk <git-ref>` | Composite PR risk score 0-100 across blast radius (30), coupling (30), complexity (20), scope (20). Levels: LOW / MEDIUM / HIGH / CRITICAL. |
| `diff-impact <git-ref>` | `diff` + function-level changes + per-file blast radius with source attribution. |
| `entry-points` | Detects `main` / test / route entries — main patterns (`main`, `cli`, `run`, `serve`, ...), test file heuristics, Flask/FastAPI/Django-style `@route`/`@app.*`/`@router.*` decorators. |

### Data flow (5)

Backed by the CPG (code property graph). Built lazily on first data-flow action and kept in-memory for the process lifetime.

| Action | What it does |
|--------|-------------|
| `data-flow <file> [fn]` | Def/use edges per function. Params -> uses, local defs -> uses, return lines. |
| `taint <source> <sink>` | Forward trace from source nodes intersected with backward slice from sink nodes. If no path, falls back to the backward slice alone. Source/sink patterns configurable via `.codemap/dataflow.json`. |
| `slice <file>:<line>` | Backward slice — every CPG node that contributes to the target. Up to 20 hops. |
| `trace-value <file>:<line>:<name>` | Forward reachability from a def. Marks reached nodes that match sink patterns with `SINK`. |
| `sinks [file]` | All sink nodes grouped by category (`filesystem`, `database`, `xss`, etc.). Categories come from defaults + `.codemap/dataflow.json` overrides. |

Pass `--tree` to `taint` / `slice` / `trace-value` for ASCII-tree rendering instead of a flat list.

### Cross-language (4)

| Action | What it does |
|--------|-------------|
| `lang-bridges [file]` | Every bridge edge detected — `torch_library`, `torch_ops`, `pybind11`, `pyo3_class`, `pyo3_function`, `pyo3_methods`, `triton_kernel`, `triton_launch`, `cuda_kernel`, `cuda_launch`, `monkey_patch`, `autograd_func`, `yaml_dispatch`, `build_dep`, `dispatch_key`, `trait_impl`. |
| `gpu-functions` | Bridges tagged as GPU kernels — Triton JIT and CUDA `__global__`. |
| `monkey-patches` | Python `module.Class = Replacement` reassignments detected across files. |
| `dispatch-map` | Op name -> per-device implementations (TORCH_LIBRARY `m.impl` + YAML `native_functions.yaml`). |

### Comparison (1)

| Action | What it does |
|--------|-------------|
| `compare <other-dir>` | Re-scans `<other-dir>` as a second graph and diffs the two — file add/remove, line delta, coupling changes per common file, new / removed external URLs. |

### Reverse engineering (13)

For analyzing compiled binaries, legacy databases, and applications without source code. Built from studying [goblin](https://github.com/m4b/goblin), [Ghidra](https://github.com/NationalSecurityAgency/ghidra), [Falcon](https://github.com/falconre/falcon), and [pe-parse](https://github.com/trailofbits/pe-parse) source code. Symbol demangling (Itanium C++ / MSVC C++ / Rust legacy + v0) is auto-applied to PE exports / imports + ELF dynamic symbols — raw mangled names retained as `attrs["mangled"]`.

| Action | What it does |
|--------|-------------|
| `clarion-schema <file>` | Parse Clarion `.CLW` DDL files into tables, keys, fields, and inferred FK relationships. Handles ISO-8859-1 encoding from Windows servers. |
| `pe-strings <file>` | Extract ASCII strings from PE binaries. Each string becomes a `StringLiteral` graph node classified by intent (url / sql / path / registry / guid / base64 / hex / format-string / error-msg / email / envvar / user-agent). URL-classified strings auto-promote to `HttpEndpoint` so `meta-path "pe->string->endpoint"` works. |
| `pe-exports <file>` | Parse the PE export directory table. Demangled names register as `Symbol` nodes; raw mangled saved as `attrs["mangled"]`. |
| `pe-imports <file>` | Parse the PE import table — every DLL dependency + API call. Adds `Dll` nodes + `Symbol` nodes with edges. |
| `pe-resources <file>` | Parse the PE resource directory — version info, manifests, string tables, resource counts. **(5.19.0+)** VS_VERSION_INFO key/value pairs (FileVersion / ProductVersion / CompanyName / OriginalFilename / etc.) lift to `vsinfo_*` attrs on the `PeBinary` node so cross-binary inventory queries like "every binary signed by X" work via attribute filter. |
| `pe-debug <file>` | PDB paths, CodeView RSDS/NB10 records (GUID, age), build timestamps, POGO data. **(5.19.0+)** PDB filename promotes to a `Symbol` node (`kind_detail=pdb_path`) with edge from the PE binary; CodeView GUID + age land as attrs. Useful for matching a stripped binary to its symbol-server PDB. |
| `pe-sections <file>` | Section table with per-section Shannon entropy. Auto-flags packed binaries (any section H > 7.0) via `attrs["packed"]=true`. Detects + registers overlay (data past EOS) as `Overlay` node with `kind` classification (NSIS / Inno / PyInstaller / ZIP self-extract / Authenticode / high-entropy / generic). **(5.21.0+)** Each section promotes to a `BinarySection` graph node with edge from the PE binary; attrs include `name`, `virtual_size`, `raw_size`, `virtual_address`, `entropy`, `characteristics` (read/write/exec/code flags joined by `+`). Enables `attribute-filter entropy>7.0` on `--type section` for cross-corpus packed-section discovery, `meta-path "pe->section"` for layout, and section-name PageRank across vendor product families. |
| `pe-meta <file>` | **(5.12.2+)** Combined PE metadata triage: Rich header parse (Microsoft toolchain fingerprint — VS6 → VS2022 cl.exe / link.exe versions), TLS callback enumeration (run-before-main, common malware persistence), entry-point RVA. **(5.17.0+)** Each unique Rich header tool promotes to a `Compiler` graph node (with `binary→compiler` edge) so per-version queries work via `meta-path "compiler->pe"`. Each TLS callback promotes to a `BinaryFunction` node with `kind_detail=tls_persistence` so it participates in centrality + meta-path queries. |
| `pe-cert <file>` | **(5.15.0+)** PE Authenticode parsing. Walks the certificate-table data directory, decodes WIN_CERTIFICATE / PKCS#7 / X.509 DER, extracts subject CN + issuer CN + serial + validity per cert. Each becomes a `Cert` node with binary→cert edge. Recognizes Authenticode signatures as a benign overlay rather than misflagging. |
| `dbf-schema <file>` | Parse dBASE III/IV/FoxPro `.DBF` file headers — version, last-update date, record count, full field descriptors. |
| `dotnet-meta <file>` | .NET CLR metadata parser. **(5.15.2+)** Each MethodDef row registers as a `BinaryFunction` node with `attrs["binary_format"]=dotnet, kind_detail=method, rva=...` hanging off the `DotnetAssembly`. |
| `sql-extract <file\|dir>` | Smart SQL extraction. Parses operation types (SELECT/INSERT/UPDATE/DELETE/CREATE/ALTER/EXEC), builds a table-to-operation access matrix, extracts JOIN relationships. |
| `binary-diff <file1> <file2>` | Compare two PE binaries — imports / strings / version-info delta. **(5.22.0+)** Promotes the diff into a cross-graph: 2 versioned `PeBinary` nodes (`pe:diff:{session}:a` and `:b`), one `BinaryFunction` per unique imported symbol with `diff_status` attr (`added` / `removed` / `unchanged`), one `Dll` node per imported library with same status attr, all under a `diff:{session}:` namespace so they never conflict with main-scan nodes. Session ID is a stable hash of both file paths → re-running is idempotent. Killer queries: `attribute-filter diff_status=added` finds new functions across two versions, `pagerank --type bin_func` ranks by import-graph centrality across both sides, `meta-path "pe->bin_func"` enumerates per-side. |

### LSP (5)

Connect to any Language Server Protocol server to extract semantic analysis data. Each action takes a server command and a target.

| Action | What it does |
|--------|-------------|
| `lsp-symbols <server> <file>` | Extract document symbols (functions, classes, methods, variables) via `textDocument/documentSymbol`. **(5.18.0+)** Each promotable symbol (Class/Method/Function/Constructor/Field/Constant/etc.) becomes a `Symbol` graph node with `source=lsp` + `source_file → symbol` edge. Capped at 5000 symbols per call. |
| `lsp-references <server> <file:line:col>` | Find all references to a symbol via `textDocument/references`. **(5.18.0+)** Registers the queried symbol once, then adds `referrer_file → symbol` edges per reference. Capped at 1000 references per call. Enables "which files reference X" via outgoing-edge traversal. |
| `lsp-calls <server> <file:line:col>` | Get incoming and outgoing call hierarchy via `callHierarchy/incomingCalls` and `callHierarchy/outgoingCalls`. **(5.18.0+)** Registers target + each caller/callee as Symbol nodes with `caller→target` (incoming) and `target→callee` (outgoing) edges. Capped at 500 call edges per invocation. |
| `lsp-diagnostics <server> <file>` | Collect all diagnostics (errors, warnings) from `textDocument/publishDiagnostics` notifications. **(5.18.0+)** Counts attached as `lsp_errors` / `lsp_warnings` / `lsp_info` attrs on each `SourceFile` node, plus `lsp_first_error` for quick triage. Enables `pagerank --type source` ranking by error density. |
| `lsp-types <server> <file>` | Extract type signatures for each symbol via `textDocument/hover`. **(5.18.0+)** Per-file `lsp_typed_symbols` / `lsp_total_symbols` attrs surface type-coverage gaps (files with many untyped symbols rank low). |

### Binary formats (4)

For analyzing compiled binaries across platforms — ELF (Linux), Mach-O (macOS), Java bytecode, and WebAssembly. Each registers typed graph nodes in the heterogeneous graph (binaries link to DLL nodes; bytecode methods become BinaryFunction nodes).

| Action | What it does |
|--------|-------------|
| `elf-info <file>` | ELF analysis — sections + entropy, DT_NEEDED → `Dll` edges, demangled symbols. **(5.12.1+)** Free-form strings extracted from `.rodata` / `.data` register as `StringLiteral` nodes (capped 5000/binary); URL-classified strings auto-promote to `HttpEndpoint`. **(5.19.0+)** `e_entry` (entry point) promotes to a `BinaryFunction` node (`kind_detail=entry_point`) with edge from the ELF binary, parity with PE/Mach-O. |
| `macho-info <file>` | Mach-O analysis — load commands, segments, dylib deps via LC_LOAD_DYLIB → `Dll` edges, rpaths, UUID, symbols. Handles fat/universal binaries. **(5.19.0+)** `LC_MAIN` entryoff promotes to a `BinaryFunction` node (`kind_detail=entry_point`) with edge from the Mach-O binary, parity with PE/ELF. |
| `java-class <file>` | Java .class / .jar analysis — constant pool, class hierarchy, fields, methods. **(5.15.2+)** Each method registers as a `BinaryFunction` node with `attrs["binary_format"]=jvm, kind_detail=method`. JAR files unpack to per-class summaries. |
| `wasm-info <file>` | WebAssembly module analysis — sections + entropy, imports/exports, type/function counts. **(5.13.1+)** Walks the Code section: each function (import or defined) becomes a `BinaryFunction` node with intra-module call edges via the `call` opcode (0x10). `meta-path "wasm->bin_func->bin_func"` traces module-internal call graphs. |

### Binary disassembly (1) — x86 / x86-64

| Action | What it does |
|--------|-------------|
| `bin-disasm <file>` | **(5.13.0+)** Full disassembly of PE / ELF x86 / x86-64 binaries via [iced-x86](https://github.com/icedland/iced) (pure Rust, no system libs). Symbol-table-driven function boundary detection — each function becomes a `BinaryFunction` node with name (auto-demangled), address, size, instruction count, indirect-call count, is_entry flag. Direct call targets emit `bin_func → bin_func` edges (intra-binary call graph). After running, every graph algorithm — PageRank / Leiden / Fiedler / betweenness / spectral-cluster — works at the function-within-binary level. Cached across CLI runs via the bincode cache. **(5.24.0+)** ARM / AArch64 ELFs (e_machine = 0x28 / 0xb7) supported via symbol-table-only function discovery — function size from `STT_FUNC` `st_size`, instruction count estimated as size/4. Brings Android native libs (`lib/arm64-v8a/*.so`) and ARM/embedded firmware into the same `BinaryFunction`-graph treatment. No new deps (real disasm with intra-binary call edges deferred to a v2 if needed — would add `yaxpeax-arm`). MIPS / RISC-V still deferred. `binary_format` attr on each node = `x86` / `x64` / `arm` / `aarch64`. |

### Binary triage / fingerprinting (4)

Lightweight first-pass triage that doesn't need disasm.

| Action | What it does |
|--------|-------------|
| `lang-fingerprint <file>` | **(5.12.0+)** Detect compiler / language / runtime via section names + signature strings. Recognizes Go (`runtime.morestack` / `.gopclntab`), Rust (`__rust_alloc` / `RUST_BACKTRACE`), .NET (`BSJB` / `mscorlib`), PyInstaller (`_MEIPASS`), Nuitka, Electron, Delphi, MinGW vs MSVC vs GCC, Swift, JNI. Registers a `Compiler` node with binary→compiler edge. Confidence 0–100 based on anchor count. Scans up to 64 MB to catch signatures in `.rodata`. |
| `overlay-info <file>` | **(5.12.1+)** Detect data appended past the official end of a PE / ELF binary. Format-aware (recognizes Authenticode signatures as benign rather than misflagging). Classifier: `nsis_installer`, `inno_setup`, `pyinstaller`, `py2exe`, `self_extract` (PK / 7z), `authenticode_sig`, `high_entropy_blob`, `generic`. Registers `Overlay` node + binary→overlay edge with offset / size / entropy / kind. |
| `fuzzy-hash <file>` | **(5.14.2+)** Compute TLSH (Trend Locality-Sensitive Hash) + ssdeep (CTPH) for a binary. Stores both as `attrs["tlsh"]` / `attrs["ssdeep"]` on the binary node. Pure Rust, no deps. |
| `fuzzy-match [tlsh-threshold=70]` | **(5.14.2+)** Walk every binary node with fuzzy hashes, compute pairwise TLSH distance + ssdeep similarity. Adds symmetric `similar_binary` edges for pairs with TLSH ≤ threshold OR ssdeep ≥ 50. PageRank / Leiden then auto-cluster variants — useful for finding repackaged or slightly-modified malware across a fleet. |

### Schemas (5)

Parse infrastructure-as-code and API specification files into structured summaries.

| Action | What it does |
|--------|-------------|
| `proto-schema <file>` | Parse Protobuf `.proto` files — packages, imports, messages with fields, enums, services with RPC methods. Recursive directory scan. |
| `openapi-schema <file>` | Parse OpenAPI/Swagger specs (JSON/YAML) — endpoints, methods, operation IDs, request/response schemas, auth schemes, tags. |
| `graphql-schema <file>` | Parse GraphQL schema files — types, inputs, enums, interfaces, unions, scalars, queries, mutations, subscriptions, directives. |
| `docker-map <file>` | Parse docker-compose.yml — services with image/build/ports/volumes/env, dependency graph, topological startup order, port map. |
| `terraform-map <file>` | Parse Terraform .tf files — resources, data sources, variables, outputs, modules with sources, providers. Cross-reference detection. |

### Security (4)

Supply-chain hygiene and secret detection.

| Action | What it does |
|--------|-------------|
| `secret-scan` | Scan all files for hardcoded secrets — AWS keys, GitHub PATs, private keys, JWTs, passwords, API keys, connection strings, IPs. Groups by severity (critical/high/medium), masks values. **(5.17.0+)** Each finding promotes to a `Secret` graph node with edge from its source file. Enables `meta-path "source->secret"` for credential inventory and `pagerank --type secret` for files concentrating credential risk. |
| `dep-tree [manifest]` | Parse package manifests (package.json, Cargo.toml, requirements.txt, go.mod, pyproject.toml, pom.xml, Gemfile, Pipfile) and show dependency trees. **(5.19.0+)** Each declared dep promotes to a `Dependency` graph node (namespaced by ecosystem: `dep:cargo:serde` ≠ `dep:npm:serde`) with edge from its manifest. Self-discovers manifests by walking scan_dir (the scanner's SUPPORTED_EXTS doesn't index .toml/.json). Enables `meta-path "source->dependency"` and `pagerank --type dependency`. |
| `dead-deps` | Cross-reference declared dependencies against actual imports — find packages in manifests that no source file references. **(5.19.0+)** Marks each dead `Dependency` node with `is_dead=true` attr for cleanup-PR generation via attribute filter. |
| `api-surface [file]` | Extract the public API surface — all exported functions grouped by file, plus HTTP routes, GraphQL resolvers, and CLI commands. **(5.19.0+)** Discovered HTTP routes (Flask / FastAPI / Express patterns) promote to `HttpEndpoint` nodes (`discovered_via=api_surface`) with edges from their source file, joining the same graph surface as `openapi-schema` / `web-blueprint` / `robots-parse`. |

### Web (5)

Reverse-engineer web applications from captured traffic and saved pages.

| Action | What it does |
|--------|-------------|
| `web-api <har-file>` | Parse HAR files — API endpoint map with methods, query params, body fields, response status codes, auth detection, CRUD coverage matrix, static asset summary. |
| `web-dom <html-file>` | Parse saved HTML — forms with fields and selectors, tables with headers, navigation structure, click handlers, inline JS API references, script sources. |
| `web-sitemap <html-dir>` | Build sitemap from HTML files — page relationships, hub pages, dead ends, external link domains. |
| `web-blueprint <har> [html-dir]` | Combine HAR + HTML into a scraper blueprint — auth recipe, API endpoints, data table selectors, pagination patterns, rate limit hints. |
| `js-api-extract <file\|dir>` | Parse JavaScript bundles for API endpoints — fetch/axios/XHR calls, base URL constants, header configurations, auth patterns. Automates "bundle archaeology." |

### Temporal (3)

Treat git history as a sequence of graph states. Single `git log` pass — no checkouts.

| Action | What it does |
|--------|-------------|
| `node-lifespan` | Per-file first-seen / last-modified / commit count. Bucketizes the codebase by age. Surfaces young hotspots (high commits/day, < 1y old), active veterans (> 1y but touched recently), and ancient stable files (> 1y, dormant > 90d). |
| `edge-churn [N=500]` | For every import edge in the graph, count co-change commits across the last N. High co-change = true coupling. Zero co-change with both files having history = vestigial import. |
| `community-evolution [N=4]` | Run LPA clustering at N evenly-spaced snapshots between the first commit and HEAD (filtering each snapshot to nodes that existed by then). Compares cluster memberships across snapshots via Jaccard to detect BIRTH / DEATH / SPLIT / MERGE events. |

### Spectral (3)

Eigenstructure of the graph Laplacian. Self-contained Lanczos solver — no LAPACK dep. Capped at 5000 nodes.

| Action | What it does |
|--------|-------------|
| `fiedler` | Algebraic connectivity λ₂ + Fiedler vector. Sign-cut bisection (Fiedler 1973, Pothen-Simon-Liou 1990) approximates min-cut. λ₂ ≈ 0 ⇒ disconnected; small λ₂ ⇒ bottleneck. Reports λ₁/λ₂, the cut size, and top files on each side ranked by Fiedler magnitude. |
| `spectral-cluster [k=8]` | Shi-Malik 2000 normalized-cut spectral clustering. Projects nodes via top-k smallest eigenvectors of the symmetric normalized Laplacian, row-normalizes (Ng-Jordan-Weiss 2002), then k-means. Captures community structure that modularity-based methods (Leiden / LPA) sometimes miss. |
| `spectral-gap` | Top-25 eigenvalues of L. Applies von Luxburg's eigengap heuristic to recommend a community count automatically — the k where λ_{k+1} − λ_k is largest. Also reports the connected-component count from λ₁ multiplicity. |

### Centrality (17)

Full NetworkX coverage. Every measure accepts a kind filter as its target — e.g. `pagerank bin_func` ranks functions inside disassembled binaries, `betweenness endpoint` chokepoints among HTTP endpoints.

| Action | What it does |
|--------|-------------|
| `pagerank` | Classical PageRank with damping. Default top-30. |
| `hubs` | Kleinberg HITS — two-axis (hub + authority) ranking. |
| `betweenness` | Brandes' O(VE) algorithm. Continuous chokepoint score (vs binary `bridges`). |
| `eigenvector` | Power iteration. PageRank without damping. |
| `katz` | Eigenvector + attenuation factor (α=0.1, β=1.0). |
| `closeness` | 1 / Σ shortest-path distance. Disconnected graphs return 0 for unreachable. |
| `harmonic` | Marchiori-Latora 2000. Σ 1/distance — handles disconnected graphs cleanly. |
| `load` | Newman 2001. Like betweenness but counts dependent paths, not just shortest. |
| `brokers` (alias `structural-holes`) | Burt 1992. Files that bridge otherwise-disconnected groups. |
| `voterank` | Zhang 2016 top-k spreaders. |
| `group <kind>` | Group centrality — importance of an entire kind class as a unit. |
| `percolation` | Piraveenan 2013. Removal-resilience scoring. |
| `current-flow` | Newman 2005. Random-walk-flow betweenness. |
| `subgraph-centrality` | Estrada-Rodriguez-Velazquez 2005. exp(A) diagonal — counts closed walks. |
| `second-order` | Kermarrec et al. 2011. Variance of cover time — finds nodes "off the beaten path." |
| `dispersion` | Lou-Strogatz triadic embeddedness. How spread out a node's connections are. |
| `reaching` | Asymmetric forward-reach. "What fraction of files does X reach?" entry-point detector. |
| `trophic` | Levine 1980 food-web hierarchy. 1 = entry, higher = deeper utility. |
| `current-flow-closeness` | Brandes-Fleischer random-walk closeness. |

### Classical algorithms (14)

petgraph parity for general graph algorithms, all running on the heterogeneous graph.

| Action | What it does |
|--------|-------------|
| `bellman-ford <src>` | Single-source shortest paths. Detects negative cycles. |
| `astar <src> <tgt>` | A* with binary heap. |
| `floyd-warshall` | All-pairs shortest paths. Capped at n > 2000. |
| `diameter` | Longest shortest path via BFS-from-each-node. |
| `mst` | Minimum spanning tree (Kruskal + union-find). |
| `cliques` | Maximum cliques (Bron-Kerbosch with pivoting). Top 20 by size. |
| `kshortest <src> <tgt> [k]` | Yen's k-shortest paths (default k=5). |
| `max-flow <src> <sink>` | Edmonds-Karp BFS Ford-Fulkerson. |
| `feedback-arc` | DFS-based feedback arc set heuristic. Suggests edges to break to make graph acyclic. |
| `scc` | Tarjan's strongly-connected components — iterative form to avoid stack overflow on deep graphs. Reports cyclic-dependency clusters by size. |
| `topo-sort` | Kahn's algorithm. Errors with helpful pointer to `scc` if graph isn't acyclic. |
| `dominator-tree [entry]` | Cooper-Harvey-Kennedy iterative dominator algorithm. Auto-detects entry node by max-fanout, or accepts a target. |
| `steiner <a,b,c,...>` | Minimum-edge subgraph connecting N terminal nodes. MST 2-approximation heuristic. |
| `subgraph-iso "<k1>-><k2>->..."` | VF2-style subgraph isomorphism for kind-sequence patterns. Capped at 100 matches. |

### Link prediction (3)

For finding *missing* edges — files that should know about each other but don't.

| Action | What it does |
|--------|-------------|
| `common-neighbors` | \|N(u) ∩ N(v)\| for unconnected pairs. Top 30. |
| `jaccard` | Common-neighbors normalized for degree: \|shared\| / \|union\|. |
| `adamic-adar` | Hub-discounted: Σ 1 / log(degree(shared neighbor)). |

### Community detection (5)

`clusters` is the umbrella; `[leiden\|lpa]` selects the algorithm. The other four are standalone.

| Action | What it does |
|--------|-------------|
| `clusters [leiden\|lpa]` | Default `leiden` — Traag-Waltman-van Eck 2019 with refinement step (guarantees well-connected communities, fixes Louvain's disconnection bug). `lpa` for fast label-propagation. Auto-named clusters via path prefix or homogeneous kind. |
| `k-core <k>` | Iteratively remove nodes with degree < k. Find the dense skeleton. |
| `k-clique <k>` | Palla et al. 2005 k-clique percolation. Overlapping communities. |
| `modularity-max` | Clauset-Newman-Moore greedy modularity maximization. |
| `divisive` | Girvan-Newman edge-betweenness. Refuses on n > 500 (cubic cost). |

### Meta-path (1) — heterogeneous graph traversal

| Action | What it does |
|--------|-------------|
| `meta-path "<k1>-><k2>->..."` | DFS through typed edges following a kind sequence. The killer feature: cross-domain queries spanning every EntityKind. Examples: `"source->endpoint"` (which code calls APIs), `"pe->dll->symbol"` (binary-internal call resolution), `"source->binary->dll->cve"` (vulnerable transitive deps after `cve-match`), `"apk->permission"` (Android attack surface), `"elf->bin_func->string"` (function-to-string xrefs after `bin-disasm`). Capped at 200 paths. **Quote the arrow** in bash to avoid `>` redirection. |

### Composite (5)

Higher-level workflows that chain multiple actions.

| Action | What it does |
|--------|-------------|
| `audit` | One-page architectural risk overview. Top chokepoints (betweenness) + top brokers + 🚨 dual-risk nodes (chokepoint AND broker = "load-bearing walls") + Leiden cluster summary + per-EntityKind census. The first action to run on any unfamiliar codebase. |
| `validate` | Pass/fail health check for CI. Exits non-zero if health < threshold. |
| `changeset <ref>` | Full PR/change analysis. Diff + risk + impact + dead-function check in one report. |
| `handoff [budget]` | Resume-where-you-left-off summary fitted to a token budget. |
| `pipeline "act1:t1,act2:t2,..."` | Chain multiple actions in a single CLI invocation. e.g. `pipeline "web-blueprint:capture.har,meta-path:source->endpoint"`. |

### Graph export (3)

Round-trip the heterogeneous graph into dedicated viz / analysis tools.

| Action | What it does |
|--------|-------------|
| `to-json` | Codemap-native JSON dump. Round-trip-safe full graph. |
| `to-graphml` | XML for **yEd / Cytoscape / NetworkX** (`networkx.read_graphml`). Standard graph-export format. |
| `to-gexf` | Gephi format with **per-EntityKind viz colors** included. Force-directed layouts + interactive filtering + time-series. |

### ML / model files (5)

Read-only metadata extraction from common ML model file formats. No GPU, no inference — pure file structure.

| Action | What it does |
|--------|-------------|
| `gguf-info <file>` | Parse GGUF (llama.cpp / GGML) — metadata key-value, tensor shapes, quantization scheme, context length. **(5.20.0+)** Each tensor promotes to an `MlTensor` graph node (capped 5000/model) with `name` / `dtype` / `shape` / `params` attrs and edge from the parent `MlModel`. |
| `safetensors-info <file>` | Parse SafeTensors header — tensor list with shapes + dtype, total parameter count. **(5.20.0+)** Each tensor promotes to an `MlTensor` graph node with `name` / `dtype` / `shape` / `size_bytes` / `params` attrs and edge from the parent `MlModel`. Enables `meta-path "model->tensor"` for cross-model architecture inventory. |
| `onnx-info <file>` | Parse ONNX protobuf — graph operators, inputs / outputs, opset version. **(5.20.0+)** Each unique operator type (Conv, MatMul, Add, etc.) promotes to an `MlOperator` graph node with `count_in_model` attr. Aggregated by op_type to keep the graph tractable on large models. Initializer count + op-type-count attached as attrs on the parent `MlModel`. Enables `pagerank --type ml_operator` to find dominant ops across a corpus. |
| `pyc-info <file>` | Parse Python `.pyc` — magic + version (Python 2.7 → 3.14), marshal-stream string extraction (URLs / SQL / paths from constants). **(5.15.1+)** Code-object scan registers each found function as a `BinaryFunction` node with `binary_format=pyc`. **(5.16.2+)** Heuristic byte-scan replaced with a proper recursive marshal walker — version-aware CODE-object header decoding (Py 2.7 / 3.4-3.7 / 3.8-3.10 / 3.11+), reads `co_name` from its actual marshal position rather than guessing the first nearby identifier (which previously caught `co_varnames[0]` = `self`/`cls` as false positives). |
| `cuda-info <file>` | Parse CUDA cubin / fatbin — SM target, kernel symbol names. **(5.17.0+)** Each kernel promotes to a `BinaryFunction` node (`binary_format=cuda, kind_detail=kernel`) with edge from the parent model — kernels now participate in centrality / meta-path queries the same way java/wasm/dotnet/pyc functions do. |

### Supply chain / SBOM (5)

Compliance + vulnerability + signing — the supply-chain dimension. Pairs with the `Cve` + `License` + `Cert` EntityKinds to enable `meta-path "source->binary->dll->cve"` queries.

| Action | What it does |
|--------|-------------|
| `license-scan` | **(5.14.0+)** Scan the directory for SPDX-License-Identifier comments in source headers, license fields in 7 manifest formats (Cargo.toml, package.json, pyproject.toml, pom.xml, go.mod, gemspec, composer.json), and LICENSE / COPYING / NOTICE files matched against 15 known-license templates (MIT, Apache-2.0, GPL family, MPL-2.0, BSD-2/3, ISC, Unlicense, 0BSD, EPL-2.0, BSL-1.0, CC0-1.0, etc.). Each detection registers a `License` node with `family` classification (permissive / weak_copyleft / strong_copyleft / proprietary / unknown) + edges from each declaring source. Flags strong-copyleft + proprietary licenses with ⚠. |
| `cve-import <nvd.json>` | **(5.14.0+)** Parse an offline NVD JSON dump (1.1 or 2.0 schema, auto-detected). Each CVE record registers as a `Cve` node with id / severity (CRITICAL/HIGH/MEDIUM/LOW) / CVSS / year / CWE / description / CPE products. **No network — strictly offline.** |
| `cve-match` | **(5.14.0+)** Walk every Dll node in the graph, normalize its name (strip `lib` prefix + extension + version), match against each Cve's CPE products. Adds `dll → cve` edges on match. Together with the existing `source → binary → dll` edges, enables the killer query `meta-path "source->binary->dll->cve"`. |
| `to-spdx` | **(5.14.1+)** Emit SPDX 2.3 JSON. Linux Foundation standard, required for US federal procurement (Executive Order 14028). Source files / binaries / DLLs become packages with `primaryPackagePurpose` per EntityKind. License nodes populate `licenseConcluded`; Cve edges become `HAS_ASSOCIATED_VULNERABILITY` relationships. Graceful degradation — writes `NOASSERTION` if no License/Cve nodes present. |
| `to-cyclonedx` | **(5.14.1+)** Emit CycloneDX 1.5 JSON. OWASP standard. Components include CPE refs; vulnerabilities are first-class with CVSS + affected components; dependencies section mirrors the heterogeneous graph's import edges. |

### Android (1)

| Action | What it does |
|--------|-------------|
| `apk-info <apk>` | **(5.15.3+)** APK structure walker — parses ZIP local file headers, categorizes entries (DEX files, manifest, resources, native libs, signing files), best-effort permission extraction via pattern-scanning `AndroidManifest.xml` bytes for `android.permission.*` prefixes (UTF-8 + UTF-16). Registers `AndroidPackage` + `Permission` nodes with apk → permission edges. Flags dangerous permissions (CAMERA, READ_SMS, FINE_LOCATION, etc.) with ⚠. **(5.23.0+)** Full DEX bytecode walker — for each `classes*.dex` (deflated via pure-Rust miniz_oxide), enumerates every method as `BinaryFunction(binary_format=dex, kind_detail=dex_method)` with edge from the `AndroidPackage`. Per-method bytecode scan for `invoke-*` opcodes targeting ~30 protected Android APIs (Camera, Location, Telephony, Bluetooth, etc.) emits `BinaryFunction → Permission` heuristic edges. Permissions used in code but NOT declared in the manifest auto-register with `discovered_via=dex` so the diff between manifest-declared and code-referenced becomes queryable — answers "did I ship a permission I'm not actually using?" and "did I forget to declare a permission I AM using?" Capped at 5000 methods per APK. Killer query: `meta-path "permission->method"` answers "what code uses CAMERA?" |

### Recon-artifact parsers (4)

Pure-static parsers consuming captured artifacts. **Codemap never makes network requests.** The user does the curl / playwright / nuclei / etc. and feeds the result here. Same line `wget` draws — codemap parses one named file at a time; no crawling, no recursion, no scope expansion. Active recon belongs in separate tools (nuclei / subfinder / gobuster / Burp).

| Action | What it does |
|--------|-------------|
| `robots-parse <robots.txt>` | **(5.16.0+)** Classify each Disallow / Allow rule (admin / sensitive / api / auth / search / asset / generic). Promote each path to an `HttpEndpoint` node with `attrs["discovered_via"]=robots, category=...`. **Flag leaky rules** that advertise sensitive paths (admin / sensitive / api categories). Sitemap directives captured separately. |
| `web-sitemap-parse <sitemap.xml>` | **(5.16.0+)** Extract every `<loc>` entry, promote to `HttpEndpoint` nodes, group URLs by path pattern with `{ID}` substitution for numeric / UUID segments. **Auto-detects ID-enumerable patterns** — the killer "this sitemap exposes a complete enumeration" finding. (Gunzip first if `.xml.gz`.) |
| `web-fingerprint <html-or-bundle>` | **(5.16.0+)** Wappalyzer-style tech detection via 50+ signature rules covering CMSes (WordPress, Drupal, Ghost, Sanity, Strapi, Contentful), backend frameworks (JHipster, Spring Boot, Django, Rails, Laravel, ASP.NET, FastAPI, Phoenix), frontend (Next.js, React, Vue, Angular, Svelte, Nuxt, Gatsby, Remix), servers (nginx / Apache / IIS / Caddy / OpenResty), CDNs (Cloudflare / CloudFront / Fastly / Akamai / Vercel / Netlify), libs (jQuery, lodash, Bootstrap, Tailwind, Algolia, Elasticsearch), analytics (GA, Segment, Mixpanel). Each match registers a `Compiler` node with category + anchor count + confidence (25–100). |
| `crt-parse <crt.sh-json>` | **(5.16.0+)** Parse a `crt.sh ?output=json` response. Extract subdomains from `name_value` fields (split on `\n`, strip wildcards). Track earliest `not_before` per host. Register `HttpEndpoint` per host + `Cert` per issuer. Subdomain-harvest from Certificate Transparency logs without ever touching the target. |

---

## Examples

### Quick codebase health check

```bash
codemap --dir src health
```

```
=== Project Health: 82/100 (B) ===

  Circular deps   [████████████████████] 25/25  0 cycles
  Coupling        [████████████████░░░░] 20/25  hottest file touches 42% of codebase
  Dead code       [████████████████░░░░] 20/25  8% dead files
  Complexity      [█████████████░░░░░░░] 17/25  12% high-complexity fns

  Files: 143  Functions: 891  Exports: 312
```

### What breaks if I change this file?

```bash
codemap --dir src blast-radius src/parser.rs
```

Every file that transitively depends on `parser.rs`.

### Rank files by importance before refactoring

```bash
codemap --dir src pagerank
codemap --dir src hubs
```

PageRank gives importance; `hubs` separates orchestrators (depend on many) from authorities (depended on by many).

### Trace user input into the database

```bash
codemap --dir src taint req.body db.query
codemap --dir src taint req.body db.query --tree
```

CPG forward-from-source intersected with backward-from-sink. The tree form is usually what you want when showing this to someone.

### Is this PR risky?

```bash
codemap --dir src risk HEAD~1
codemap --dir src diff-impact main
```

`risk` returns a composite score and severity. `diff-impact` adds function-level change detail and per-file blast-radius attribution.

### Reverse engineer a compiled Windows application

```bash
# Extract the full database schema from a Clarion DDL file
codemap --dir . clarion-schema /path/to/sql_var.clw

# Extract SQL queries and table references from a compiled EXE
codemap --dir . pe-strings /path/to/app.exe

# See what DLLs and APIs the binary calls
codemap --dir . pe-imports /path/to/app.exe

# Get version info, string tables, and UI structure
codemap --dir . pe-resources /path/to/app.exe

# Mine SQL queries across all EXEs in a directory, build table access map
codemap --dir . sql-extract /path/to/app-directory/

# Compare two versions of a binary
codemap --dir . binary-diff old_version.exe new_version.exe

# Parse a dBASE/FoxPro database file
codemap --dir . dbf-schema /path/to/data.dbf

# Crack a .NET assembly
codemap --dir . dotnet-meta /path/to/app.dll
```

### Use LSP for semantic analysis

```bash
# Extract all symbols from a Rust file via rust-analyzer
codemap --dir . lsp-symbols rust-analyzer src/main.rs

# Find all references to a symbol at a specific location
codemap --dir . lsp-references rust-analyzer src/main.rs:42:10

# Get call hierarchy
codemap --dir . lsp-calls rust-analyzer src/main.rs:42:10

# Get diagnostics
codemap --dir . lsp-diagnostics pylsp src/
```

### Scan for hardcoded secrets

```bash
codemap --dir src secret-scan
```

Finds AWS keys, GitHub PATs, private keys, JWTs, passwords, API keys, and connection strings. Groups by severity (critical/high/medium) and masks values in the output.

### Parse infrastructure schemas

```bash
# Parse Protobuf definitions
codemap --dir . proto-schema api/v2.proto

# Parse an OpenAPI spec
codemap --dir . openapi-schema openapi.yaml

# Map Docker Compose service dependencies
codemap --dir . docker-map docker-compose.yml

# Map Terraform resources and modules
codemap --dir . terraform-map infra/
```

### Analyze non-PE binaries

```bash
# ELF binary (Linux)
codemap --dir . elf-info /usr/local/bin/myapp

# Mach-O binary (macOS)
codemap --dir . macho-info /usr/local/bin/myapp

# Java class or JAR
codemap --dir . java-class app.jar

# WebAssembly module
codemap --dir . wasm-info module.wasm
```

### Build a web scraper blueprint

```bash
# Combine captured traffic + saved pages into a scraper config
codemap --dir . web-blueprint traffic.har ./pages/

# Extract API endpoints from a minified JavaScript bundle
codemap --dir . js-api-extract dist/app.bundle.js
```

### Build an LLM-ready repo map

```bash
codemap --dir src context 8k
```

PageRank-ranked file + function signatures, fitted to an 8000-token budget. Drop into a prompt for orientation.

### Export a dependency diagram

```bash
codemap --dir src dot > graph.dot && dot -Tsvg graph.dot -o graph.svg
codemap --dir src mermaid parser > graph.mmd       # 2-hop around "parser"
```

### Find hidden dependencies via git history

```bash
codemap --dir src git-coupling 500
```

Files that co-change but have no import link — the most dangerous class of coupling, because nothing in the code tells you the two files are related.

### Watch a metric while you work

```bash
codemap --dir src --watch 5 health
codemap --dir src --watch complexity src/parser.rs
```

### Multi-repo scan

```bash
codemap --dir ./service --dir ./shared-libs hotspots
```

Imports that cross the boundary become real edges in the merged graph.

---

## Output formats

### Human text (default)

Category headers, fixed-width columns, Unicode box drawing where it helps. Stable enough to grep.

### JSON

```bash
codemap --dir src pagerank --json
```

```json
{
  "action": "pagerank",
  "target": null,
  "files": 143,
  "result": "=== PageRank (top 30 most important files) ===\n\n  123.45 rank  src/parser.rs\n  ..."
}
```

The envelope is stable (`action`, `target`, `files`, `result`). The `result` field currently holds the human-readable rendering as a string — this is a simple wrapper for scripting, not a structured data export. For real data extraction, parse the human output (it's designed to be grep-stable) or use `dot` / `mermaid` for graph formats.

### DOT / Mermaid

`dot` and `mermaid` emit pure graph text. Pipe to Graphviz or paste into a GitHub markdown block.

### Tree (data-flow only)

Pass `--tree` to `taint`, `slice`, or `trace-value` for ASCII-tree rendering of the CPG backward or forward walk.

---

## Supported languages

Tree-sitter grammars are in use for every language marked AST. YAML/CMake are scanned with regex for URLs and bridge-detection patterns (they have no functions or imports in the same sense).

| Language | Extensions | Parser | Notes |
|----------|-----------|--------|-------|
| TypeScript | `.ts` | tree-sitter-typescript | |
| TSX | `.tsx` | tree-sitter-typescript (TSX grammar) | |
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs` | tree-sitter-javascript | |
| Python | `.py` | tree-sitter-python | |
| Rust | `.rs` | tree-sitter-rust | |
| Go | `.go` | tree-sitter-go | |
| Java | `.java` | tree-sitter-java | |
| Ruby | `.rb` | tree-sitter-ruby | |
| PHP | `.php` | tree-sitter-php | |
| C | `.c`, `.h` | tree-sitter-c | |
| C++ | `.cpp`, `.cc`, `.cxx`, `.hpp`, `.hxx` | tree-sitter-cpp | |
| CUDA | `.cu`, `.cuh` | tree-sitter-cpp | Parsed as a C++ superset. |
| Bash/Shell | `.sh`, `.bash` | tree-sitter-bash | Functions, source imports |
| YAML | `.yaml`, `.yml` | regex | URLs + YAML dispatch tables (e.g. `native_functions.yaml`). |
| CMake | `.cmake` | regex | URLs + build-dep detection. |

Directories skipped during walk: `node_modules`, `.git`, `dist`, `build`, `.codemap`, `target`. Symlinks are not followed. Files larger than 10 MB are skipped. Recursion depth capped at 50.

---

## Architecture

```
codemap/
├── Cargo.toml                     # Workspace root
├── codemap-cli/                   # CLI binary
│   └── src/main.rs                # Clap parsing, dispatch, --watch, --json
├── codemap-core/                  # Library (all analysis lives here)
│   └── src/
│       ├── lib.rs                 # scan() + execute() public API
│       ├── scanner.rs             # Walk -> cache -> parallel parse -> resolve -> bridge edges
│       ├── parser.rs              # ext_to_grammar + AST extractors + regex fallback
│       ├── resolve.rs             # Import specifier -> file path resolution
│       ├── types.rs               # Graph, GraphNode, FunctionInfo, Bridge*, DataFlowConfig
│       ├── cpg.rs                 # Code property graph — def/use edges, forward/backward, tree render
│       ├── utils.rs               # format_number, truncate, pad_end
│       └── actions/
│           ├── mod.rs             # dispatch(action, target) -> String (163 actions)
│           ├── analysis.rs        # 14 file-level actions + health
│           ├── insights.rs        # summary, decorators, rename, context
│           ├── navigation.rs      # why, paths, subgraph, similar, structure
│           ├── graph_theory.rs    # pagerank, hubs, bridges, clusters, islands, dot, mermaid
│           ├── functions.rs       # 13 function-level actions
│           ├── dataflow.rs        # data-flow, taint, slice, trace-value, sinks
│           ├── bridges.rs         # lang-bridges, gpu-functions, monkey-patches, dispatch-map
│           ├── compare.rs         # compare two repos
│           ├── binary.rs          # 4 binary format actions (ELF, Mach-O, Java, WASM)
│           ├── schemas.rs         # 5 schema actions (Protobuf, OpenAPI, GraphQL, Docker, Terraform)
│           ├── security.rs        # 4 security actions (secret-scan, dep-tree, dead-deps, api-surface)
│           ├── reverse/           # 11 reverse engineering actions (PE, Clarion, DBF, .NET, SQL)
│           │   ├── mod.rs         # dispatch for RE actions
│           │   ├── common.rs      # shared PE/binary parsing utilities
│           │   ├── pe.rs          # PE-specific actions (imports, exports, resources, debug, sections)
│           │   ├── schema.rs      # Clarion DDL, dBASE, dotnet-meta, sql-extract
│           │   └── web.rs         # web-api, web-dom, web-sitemap, web-blueprint, js-api-extract
│           └── lsp.rs             # 5 LSP client actions
├── codemap-napi/                  # Node.js bindings (same core, napi-rs wrapper)
├── plugin/skills/codemap/SKILL.md # The /codemap Claude Code skill
├── .claude-plugin/marketplace.json
└── install.sh
```

### Scan pipeline

1. **Walk.** `walk_dir` recursively enumerates supported extensions, skipping common build/junk dirs and symlinks. Depth cap 50.
2. **Cache lookup.** Load `.codemap/cache.bincode` (bincode-encoded `CacheData`). Entries with matching mtime (+/-1 ms) reuse cached imports, exports, functions, data-flow, bridges. Cache version stamp forces invalidation on schema changes (currently `CACHE_VERSION = 8`).
3. **Parallel parse.** Misses are parsed with rayon across all cores. `parse_file` dispatches on extension -> tree-sitter grammar -> AST extractors (`extract_imports_from_ast`, `extract_exports_from_ast`, `extract_functions_from_ast`, `extract_data_flow_from_ast`). Parser instances are thread-local and cached per grammar to amortize setup.
4. **Import resolution.** Each import specifier is resolved against the scan directory, `--include-path` list, and sibling files via `resolve::resolve_import`. Unresolved specifiers stay as strings (still visible via `trace` and `phone-home`).
5. **Reverse edges.** `imported_by` is populated after all nodes are built.
6. **Bridge resolution.** Cross-language bridge registrations (TORCH_LIBRARY ops, pybind11 defs, PyO3 `#[pymodule]`, YAML dispatch rows, Triton/CUDA kernel launches, monkey-patches) are matched across files and added as extra import edges so graph-theory actions see them too.
7. **Save cache.** Atomic write via `.bincode.tmp` -> rename.

### CPG (code property graph)

Built lazily the first time a data-flow action runs (`cpg::ensure_cpg`). Nodes are typed (`Def`, `Use`, `Call`, `Return`, `Param`, ...) with file/line/name/expr. Edges are def->use chains plus param->use. Backward slicing and forward tracing are BFS on those edges, capped at 20 hops by default. `build_tree` + `render_tree` give the `--tree` output.

Source/sink/sanitizer patterns for `taint` and `sinks` come from a sensible default list in `types.rs` (`process.env`, `req.body`, `exec`, `eval`, `fs.writeFile`, `db.query`, ...) and can be extended per-repo via `.codemap/dataflow.json`:

```json
{
  "sinks":      [{ "pattern": "myLogger.send",  "category": "logging" }],
  "sources":    [{ "pattern": "request.form",   "category": "user-input" }],
  "sanitizers": [{ "pattern": "sanitize_html" }]
}
```

Patterns support trailing wildcards (`foo.*`) and last-segment matching.

### Multi-repo merge

When `--dir` is repeated, each directory is scanned independently (its own cache), then merged. Cross-repo imports are re-resolved against the merged node set so a file in one repo importing a file in another becomes a real edge.

---

## Performance

Measurable from the code and `EVOLUTION.log`:

- **Parallel parse.** `rayon::par_iter` over cache misses. Parse throughput scales with cores.
- **Incremental cache.** Warm runs reparse only modified files. On codemap's own source (~8k lines of Rust) a warm `stats` runs in well under a second.
- **Thread-local parser pool.** `tree_sitter::Parser` instances are created once per grammar per thread and reused (`PARSER_CACHE` thread-local).
- **Regex hoisting.** All analysis regexes are compiled once per action, not per file or per line. Security-scan regexes use `LazyLock` for zero-cost reuse across invocations.
- **O(1) cross-repo linking.** Multi-repo merges use hash-based lookups for cross-boundary import resolution instead of linear scans.
- **Vec buffer swap for graph algorithms.** PageRank and HITS alternate between two pre-allocated Vec buffers instead of cloning, halving allocation pressure per iteration.
- **Zero clippy warnings** at v5.1.2. **53 integration tests** (self-referential — codemap scans its own `codemap-core/src/`).
- **Walk safety guards (5.1.1+).** Refuses default scans of `$HOME`, hard-caps walks at 50,000 supported files, warns at 10,000. Override via `CODEMAP_NO_FILE_LIMIT=1`. Prevents the OOM cascade that can reap a parent process scope on systemd hosts when a scan accidentally rooted at `~` walked 192K+ files.
- **Ecosystem-wide skip-dirs (5.1.2).** Walk excludes Python venvs (`.venv`, `venv`, `__pycache__`, `.tox`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `site-packages`), JS framework caches (`.next`, `.nuxt`, `.svelte-kit`, `.turbo`, `.parcel-cache`, `.cache`, `bower_components`, `jspm_packages`, `out`), Go/PHP/Ruby `vendor/`, JVM `.gradle`, iOS `Pods`, IDE caches (`.idea`, `.vscode`), and coverage dirs — in addition to the existing `node_modules`, `target`, `dist`, `build`, `.git`, `.codemap` set.
- **Cache sanity.** Load caps bincode file at 256 MB and rejects entries with path traversal (`..`, leading `/`). Files > 10 MB are skipped at parse time.

If you want real numbers on your codebase, `codemap --dir <path> stats` prints file and line counts; time it with `time` for baseline throughput.

---

## Configuration

codemap is stateless except for two per-repo files, both under `.codemap/` in the scanned directory:

| File | Purpose | Required? |
|------|---------|-----------|
| `.codemap/cache.bincode` | Bincode-encoded scan cache. Auto-managed. Delete or pass `--no-cache` to force a fresh scan. | No. |
| `.codemap/dataflow.json` | Per-repo sink / source / sanitizer patterns layered on top of defaults. Shape shown in the CPG section above. | No — defaults cover the common web framework / ORM patterns. |

Add `.codemap/` to `.gitignore`.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `codemap: command not found` | Binary not on PATH | Add `~/bin` (or `/usr/local/bin`) to PATH, or pass `bash install.sh` again with a Rust toolchain installed. |
| `Unknown action: foo` | Typo or old version | `codemap --help` prints every action. |
| `File not found: src/main.rs` | Target path is not relative to the scan dir | Paths are resolved relative to `--dir`. If `--dir` is `/home/me/proj`, use `src/main.rs`, not the full path. `find_node` also accepts the basename if it's unique. |
| Results feel stale | Cache didn't invalidate | `--no-cache`, or `rm -rf .codemap/`. Cache invalidation is mtime-based — if your build tool preserves mtimes, it can fool the cache. |
| `lang-bridges` shows nothing in a PyTorch repo | You only scanned Python or only scanned C++ | Scan both with multiple `--dir`, or one directory that contains both. Bridge resolution matches registrations to call sites across the merged graph. |
| `taint`: "Source not found" / "Sink not found" | Pattern doesn't match any call site in the CPG | Check `codemap --dir src sinks` to see what sinks were actually detected. Extend `.codemap/dataflow.json`. |
| C/C++ imports resolve to nothing | Missing include paths | `--include-path /path/to/include`, repeat for each. |
| Slow first scan, large repo | First pass parses everything | Subsequent scans use the cache. If you expect to run many actions in a row, the first is the cost; the rest are cheap. |
| `git diff` / `churn` / `risk` fail | Not a git repo, or ref doesn't exist | codemap shells out to `git` in the scan dir. Make sure the ref resolves: `git rev-parse HEAD~3`. |
| `/codemap` not appearing in Claude Code | Plugin not enabled | `bash install.sh --check` — verifies plugin files, settings.json entries, binary on PATH. |
| PE actions return "Not a PE file" | Target is not a Windows binary | PE actions only work on Windows EXE/DLL files (MZ header). |
| `lsp-*` hangs or times out | LSP server not installed or not responding | Ensure the server command works standalone (e.g. `rust-analyzer --version`). Timeout is 5 seconds per request. |
| `Refusing to scan $HOME` | You ran `codemap` from `~` without `--dir` | Pass `--dir <smaller_path>` (e.g. `--dir ~/Desktop/myrepo`) or set `CODEMAP_NO_FILE_LIMIT=1` to override. The refuse is intentional — a `$HOME`-rooted walk on a fleet host previously OOM-killed itself reaping a tmux session. |
| `Scan hit the safety cap of 50000 supported files` | Scan dir contains too many supported files (likely a parent of many projects) | Pass `--dir <smaller_path>`, or `CODEMAP_NO_FILE_LIMIT=1` to override (use only with plenty of free RAM). Most often triggered by a `vendor/` or undeclared deps tree — see if `SKIP_DIRS` is missing your ecosystem's convention. |
| `Exec format error` running `codemap` | Wrong-architecture binary (e.g. ARM binary copied to x86_64 host) | Re-run `bash install.sh` — the installer auto-detects via `uname -s -m` and pulls the correct pre-built binary from GitHub Releases. Override the auto-detect with `CODEMAP_BUILD_FROM_SOURCE=1 bash install.sh` to force a local cargo build. |

---

## Contributing

The core library (`codemap-core/`) is where all the work is. Adding an action is:

1. Implement `pub fn my_action(graph: &Graph, target: &str) -> String` in the appropriate file under `codemap-core/src/actions/`.
2. Wire it into the `match` in `codemap-core/src/actions/mod.rs::dispatch`.
3. Add a line to the `after_help` block in `codemap-cli/src/main.rs` so `codemap --help` advertises it.
4. Add an integration test in `codemap-core/tests/integration.rs` (the suite scans codemap's own `src/` — self-referential testing keeps the feedback loop fast).
5. Add an entry to `EVOLUTION.log`.

For new languages: add the tree-sitter crate to `codemap-core/Cargo.toml`, extend `SUPPORTED_EXTS` in `scanner.rs`, wire `ext_to_grammar` + `grammar_to_language` in `parser.rs`, and teach the AST extractors the language's node types.

---

## License

MIT.
