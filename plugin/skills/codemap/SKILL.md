---
name: codemap
description: Analyze codebase structure with 42 actions — AST-powered function-level call graphs, PageRank, HITS hubs/authorities, bridges, clusters, community detection, similarity, subgraphs, DOT export, A/B compare, data-flow CPG, taint analysis, backward slicing, and more. Use when asked to understand code structure, audit dependencies, or prepare for refactoring.
user-invocable: true
allowed-tools:
  - Bash(codemap *)
  - Bash(~/bin/codemap *)
  - Bash(~/Desktop/codemap/target/release/codemap *)
  - Read
  - Grep
---

# /codemap — Codebase Dependency Analysis

42 actions. Native tree-sitter AST across 12 languages. Rayon parallel parsing. Bincode mtime cache. Rust.

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

### Navigation
| Action | What |
|--------|------|
| `why <A> <B>` | Shortest import path |
| `paths <A> <B>` | ALL import paths between files |
| `subgraph <pattern>` | Connected component around a target |
| `similar <file>` | Files with similar import profiles |

### Graph Theory
| Action | What |
|--------|------|
| `pagerank` | Recursive importance ranking |
| `hubs` | Hub/authority analysis (HITS) |
| `bridges` | Articulation points (critical files) |
| `clusters` | Community detection (module boundaries) |
| `islands` | Disconnected components |
| `dot [target]` | Graphviz DOT export |

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

## Options

| Flag | What |
|------|------|
| `--dir <path>` | Directory to scan (repeatable for multi-repo) |
| `--include-path <path>` | C/C++ include search path (repeatable) |
| `--json` | Output JSON instead of text |
| `--tree` | Show full dependency tree (data-flow actions) |
| `--no-cache` | Force fresh scan |

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
- Risk assessment — `churn`, `complexity`
- Cross-language GPU analysis — `--dir cuda-project stats`, multi-repo merge
- Visualizing — `dot [target] | dot -Tpng -o graph.png`
