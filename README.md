# codemap

Rust-native codebase dependency analysis and binary reverse engineering. A single binary that scans your repo with tree-sitter AST parsers, builds a file-level import graph and a function-level call graph, and exposes 70 analysis actions — PageRank, HITS, articulation points, community detection, backward slicing, taint analysis, cross-language bridges, PE binary analysis, .NET metadata extraction, LSP integration, and more — through a flat CLI.

No servers. No databases. No API keys. One static binary, `.codemap/cache.bincode` next to your repo for incremental scans, and a `/codemap` Claude Code skill that wraps the same binary.

**Version:** 5.1.0 | **Workspace:** `codemap-core` (library) + `codemap-cli` (binary) + `codemap-napi` (Node.js bindings) | **License:** MIT

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

- **70 actions, one dispatch.** Every analysis is a single CLI verb. `codemap --dir src pagerank` ranks files. `codemap --dir src taint req.body db.query` traces taint. `codemap --dir src risk HEAD~3` scores a PR. No sub-commands, no flags trees to memorize.

- **Binary reverse engineering.** 11 actions for cracking compiled binaries without source code: PE import/export/resource/debug/section analysis, string extraction with SQL categorization, .NET CLR metadata parsing, Clarion DDL and dBASE schema extraction, SQL query mining with table access maps, and binary diffing. Built from studying goblin, Ghidra, Falcon, and pe-parse source code.

- **LSP integration.** 5 actions that connect to any Language Server Protocol server to extract symbols, references, call hierarchies, diagnostics, and type information. Works with rust-analyzer, pylsp, typescript-language-server, clangd, or any LSP-compliant server.

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

The installer clones the repo, verifies the plugin structure, merges entries into `~/.claude/settings.json` (non-destructive, requires python3), then builds the `codemap` binary with `cargo build --release` and drops it into `~/bin/codemap` (or `/usr/local/bin/codemap` if running as root). Requires a Rust toolchain.

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

All 70 actions grouped by category. Every action runs against the full graph unless it takes a target. Targets are files, function names, git refs, or patterns depending on the action.

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

### Reverse engineering (11)

For analyzing compiled binaries, legacy databases, and applications without source code. Built from studying [goblin](https://github.com/m4b/goblin), [Ghidra](https://github.com/NationalSecurityAgency/ghidra), [Falcon](https://github.com/falconre/falcon), and [pe-parse](https://github.com/trailofbits/pe-parse) source code.

| Action | What it does |
|--------|-------------|
| `clarion-schema <file>` | Parse Clarion `.CLW` DDL files into tables, keys, fields, and inferred FK relationships. Handles ISO-8859-1 encoding from Windows servers. |
| `pe-strings <file>` | Extract and categorize ASCII strings from PE binaries — SQL statements, `dbo.*` table references, URLs, file paths, identifiers. |
| `pe-exports <file>` | Parse the PE export directory table. Falls back to heuristic name extraction if no export table. |
| `pe-imports <file>` | Parse the PE import table — every DLL dependency and every API function called. Categorizes imports by type: Database/SQL, Network, Registry, File I/O, Crypto, COM/OLE. |
| `pe-resources <file>` | Parse the PE resource directory — version info (company, description, file/product version), embedded manifests, string tables, and resource type counts (dialogs, menus, icons, bitmaps). |
| `pe-debug <file>` | Parse the PE debug directory — PDB file paths, CodeView RSDS/NB10 records (GUID, age), build timestamps, VC Feature counters, POGO data. |
| `pe-sections <file>` | Dump the PE section table with Shannon entropy analysis per section. Flags high-entropy sections (>7.0) as potentially packed or encrypted. Shows section characteristics (CODE, EXEC, READ, WRITE, etc.). |
| `dbf-schema <file>` | Parse dBASE III/IV/FoxPro `.DBF` file headers — version, last update date, record count, and full field descriptors (name, type, size, decimal count). |
| `dotnet-meta <file>` | Parse .NET CLR metadata from PE binaries — runtime version, CLR flags, metadata streams (#~, #Strings, #US, #GUID, #Blob), TypeDef/MethodDef/TypeRef/AssemblyRef tables, and user string literals. |
| `sql-extract <file\|dir>` | Smart SQL extraction from binaries. Parses operation types (SELECT/INSERT/UPDATE/DELETE/CREATE/ALTER/EXEC), builds a table-to-operation access matrix, extracts JOIN relationships. In directory mode, produces per-binary table usage maps. |
| `binary-diff <file1> <file2>` | Compare two PE binaries — diff imports (added/removed DLLs and functions), diff strings (new/removed SQL statements and table references), compare version info. |

### LSP (5)

Connect to any Language Server Protocol server to extract semantic analysis data. Each action takes a server command and a target.

| Action | What it does |
|--------|-------------|
| `lsp-symbols <server> <file>` | Extract document symbols (functions, classes, methods, variables) via `textDocument/documentSymbol`. |
| `lsp-references <server> <file:line:col>` | Find all references to a symbol via `textDocument/references`. |
| `lsp-calls <server> <file:line:col>` | Get incoming and outgoing call hierarchy via `callHierarchy/incomingCalls` and `callHierarchy/outgoingCalls`. |
| `lsp-diagnostics <server> <file>` | Collect all diagnostics (errors, warnings) from `textDocument/publishDiagnostics` notifications. |
| `lsp-types <server> <file>` | Extract type signatures for each symbol via `textDocument/hover`. |

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
│           ├── mod.rs             # dispatch(action, target) -> String
│           ├── analysis.rs        # 14 file-level actions + health
│           ├── insights.rs        # summary, decorators, rename, context
│           ├── navigation.rs      # why, paths, subgraph, similar, structure
│           ├── graph_theory.rs    # pagerank, hubs, bridges, clusters, islands, dot, mermaid
│           ├── functions.rs       # 13 function-level actions
│           ├── dataflow.rs        # data-flow, taint, slice, trace-value, sinks
│           ├── bridges.rs         # lang-bridges, gpu-functions, monkey-patches, dispatch-map
│           ├── compare.rs         # compare two repos
│           ├── reverse.rs         # 11 reverse engineering actions (PE, Clarion, DBF, .NET, SQL)
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
- **Regex hoisting.** All analysis regexes are compiled once per action, not per file or per line.
- **Zero clippy warnings** at v5.1.0. **31 integration tests** (self-referential — codemap scans its own `codemap-core/src/`).
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
