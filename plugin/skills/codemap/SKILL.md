---
name: codemap
description: Analyze codebase structure with 70 actions — AST-powered function-level call graphs, PageRank, HITS hubs/authorities, bridges, clusters, community detection, similarity, subgraphs, DOT/Mermaid export, A/B compare, data-flow CPG, taint analysis, backward slicing, clone detection, risk scoring, reverse engineering (PE sections/imports/resources/debug/strings/exports, .NET metadata, SQL extraction, binary diff, Clarion/DBF schema), LSP integration, and more. Use when asked to understand code structure, audit dependencies, or prepare for refactoring.
user-invocable: true
allowed-tools:
  - Bash(codemap *)
  - Bash(~/bin/codemap *)
  - Bash(~/Desktop/codemap/target/release/codemap *)
  - Read
  - Grep
---

# /codemap — Codebase Dependency Analysis

70 actions. Native tree-sitter AST across 12 languages. Rayon parallel parsing. Bincode mtime cache. Rust.

## Usage

```bash
codemap [--dir <path>] <action> [target]
```

Or point at multiple repos:
```bash
codemap --dir ~/project-a --dir ~/project-b stats
```

## Actions

### Analysis
| Action | What |
|--------|------|
| `stats` | Codebase overview |
| `trace <file>` | Imports and importers of a file |
| `blast-radius <file>` | All files affected if this changes |
| `phone-home` | Files with external URLs |
| `coupling <pattern>` | Files importing a package/pattern |
| `dead-files` | Files nothing imports |
| `circular` | Circular dependency chains |
| `exports <file>` | Exports in a file |
| `callers <name>` | Where a function is used |
| `hotspots` | Most coupled files |
| `size` | Files ranked by line count |
| `layers` | Auto-detect architectural layers |
| `diff <ref>` | Blast radius of git changes |
| `orphan-exports` | Exports nothing uses |
| `health` | Codebase health score |
| `summary` | High-level codebase summary |
| `decorators` | List decorators/attributes usage |
| `rename <old> <new>` | Preview rename impact |
| `context [budget]` | PageRank-ranked repo map fitted to a token budget (e.g. `8k`, `16000`) |

### Navigation
| Action | What |
|--------|------|
| `why <A> <B>` | Shortest import path |
| `paths <A> <B>` | ALL import paths between files |
| `subgraph <pattern>` | Connected component around a target |
| `similar <file>` | Files with similar import profiles |
| `structure` | Directory structure with module boundaries |

### Graph Theory
| Action | What |
|--------|------|
| `pagerank` | Recursive importance ranking |
| `hubs` | Hub/authority analysis (HITS) |
| `bridges` | Articulation points (critical files) |
| `clusters` | Community detection (module boundaries) |
| `islands` | Disconnected components |
| `dot [target]` | Graphviz DOT export |
| `mermaid [target]` | Mermaid diagram export |

### Function-Level (AST)
| Action | What |
|--------|------|
| `call-graph [file]` | Cross-file function call graph |
| `dead-functions` | Exported functions nothing calls |
| `fn-info <file>` | Functions in a file with their calls |
| `diff-functions <ref>` | Functions added/removed since a git ref |
| `complexity [file]` | Cyclomatic complexity per function |
| `import-cost <file>` | Transitive import size (files + lines) |
| `churn <ref>` | Git churn * coupling = risk hotspots |
| `api-diff <ref>` | Exports added/removed since a git ref |
| `clones` | Detect duplicate/similar code blocks |
| `git-coupling` | Files that change together in git |
| `risk [file]` | Risk score (complexity + churn + coupling) |
| `diff-impact <ref>` | Impact analysis of git changes |
| `entry-points` | Detect main/test/route entry points |

### Data Flow (CPG)
| Action | What |
|--------|------|
| `data-flow <file> [fn]` | Data dependencies for a file or function |
| `taint <source> <sink>` | Trace data pipeline between two points |
| `slice <file>:<line>` | Backward slice — what feeds this line |
| `trace-value <f>:<l>:<n>` | Forward trace — where does this value go |
| `sinks [file]` | List all detected sinks |

### Cross-Language
| Action | What |
|--------|------|
| `lang-bridges [file]` | Show cross-language bridge edges (pybind11, PyO3, TORCH_LIBRARY, Triton, CUDA) |
| `gpu-functions` | List all GPU-tagged functions (CUDA __global__, @triton.jit) |
| `monkey-patches` | Show Python module-level class/function replacements |
| `dispatch-map` | Show op→implementation mappings per device |

### Comparison
| Action | What |
|--------|------|
| `compare <dir>` | Structural A/B diff |

### Reverse Engineering
| Action | What |
|--------|------|
| `clarion-schema <file>` | Parse Clarion .CLW DDL — tables, keys, fields, FK relationships |
| `pe-strings <file>` | Extract categorized strings from PE binaries (SQL, tables, URLs, paths) |
| `pe-exports <file>` | Dump DLL/EXE export table |
| `pe-imports <file>` | DLL import table — every API call the binary makes |
| `pe-resources <file>` | Version info, manifests, string tables, dialogs, menus |
| `pe-debug <file>` | PDB paths, build timestamps, CodeView, compiler info |
| `dbf-schema <file>` | Parse dBASE/FoxPro .DBF headers — fields, types, record counts |
| `pe-sections <file>` | Section table with entropy analysis (detect packing/encryption) |
| `dotnet-meta <file>` | .NET CLR metadata — types, methods, assembly refs, user strings |
| `sql-extract <file\|dir>` | Smart SQL extraction — table access map, JOINs, per-binary usage |
| `binary-diff <file1> <file2>` | Compare two binaries — import/string/version changes |

### LSP
| Action | What |
|--------|------|
| `lsp-symbols <server> <file>` | Extract document symbols via LSP server |
| `lsp-references <server> <file:line:col>` | Find all references to a symbol |
| `lsp-calls <server> <file:line:col>` | Incoming/outgoing call hierarchy |
| `lsp-diagnostics <server> <file>` | Errors and warnings from language server |
| `lsp-types <server> <file>` | Type signatures via hover |

## Options

| Flag | What |
|------|------|
| `--dir <path>` | Directory to scan (repeatable for multi-repo) |
| `--include-path <path>` | C/C++ include search path (repeatable) |
| `--json` | Output JSON instead of text |
| `--tree` | Show full dependency tree (data-flow actions) |
| `--no-cache` | Force fresh scan |
| `--watch [<secs>]` | Watch mode: re-run every N seconds (default 2) |
| `-q, --quiet` | Suppress scan/cache status messages |

## How Parsing Works

- **Native tree-sitter** — Compiled Rust grammars, no WASM overhead
- **12 languages** — TypeScript, TSX, JavaScript, Python, Rust, Go, Java, Ruby, PHP, C, C++, CUDA
- **CUDA** — Parsed as C++ superset, kernel launches (`<<<>>>`) detected as call edges
- **URLs** — Regex across all languages (credentials stripped)
- **Fallback** — Regex for any extension without a tree-sitter grammar
- **Parallel** — Rayon par_iter across files, ~23x faster cold scan than TS version

## When to Use

- Understanding architecture — `stats`, `hotspots`, `layers`, `pagerank`, `hubs`
- Finding critical code — `bridges`, `call-graph`, `fn-info`, `complexity`
- Cleaning up — `dead-files`, `dead-functions`, `orphan-exports`
- Before refactoring — `blast-radius`, `bridges`, `similar`, `import-cost`
- Debugging breakage — `why`, `paths`, `call-graph`
- Security audit — `phone-home`, `sinks`, `taint`
- Data flow analysis — `data-flow`, `slice`, `trace-value`
- Comparing versions — `compare`, `api-diff`, `diff-functions`
- Risk assessment — `churn`, `complexity`, `risk`
- Health check — `health`, `summary`
- Clone detection — `clones`, `git-coupling`
- Cross-language GPU analysis — `--dir cuda-project stats`, multi-repo merge
- Visualizing — `dot [target] | dot -Tpng -o graph.png`, `mermaid [target]`
- Reverse engineering — `clarion-schema`, `pe-strings`, `pe-exports`, `pe-imports`, `pe-resources`, `pe-debug`, `pe-sections`, `dbf-schema`, `dotnet-meta`, `sql-extract`, `binary-diff`
- LSP integration — `lsp-symbols`, `lsp-references`, `lsp-calls`, `lsp-diagnostics`, `lsp-types`
