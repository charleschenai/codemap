---
name: codemap
description: Analyze codebase structure with 28 actions — AST-powered function-level call graphs, PageRank, HITS hubs/authorities, bridges, clusters, community detection, similarity, subgraphs, DOT export, A/B compare, and more. Use when asked to understand code structure, audit dependencies, or prepare for refactoring.
user-invocable: true
allowed-tools:
  - Bash(bun *)
  - Bash(codemap *)
  - Bash(~/bin/codemap *)
  - Read
  - Grep
---

# /codemap — Codebase Dependency Analysis

28 actions. AST-powered for TS/JS, scope-aware for Python/Rust/Go/Java/Ruby/PHP. Zero dependencies. Single file.

## Usage

```bash
bun ~/bin/codemap [--dir <path>] <action> [target]
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
| `functions <file>` | Exports in a file |
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

### Comparison
| Action | What |
|--------|------|
| `compare <dir>` | Structural A/B diff |

## How Parsing Works

- **TS/JS** — Bun.Transpiler AST for accurate imports/exports (strips type-only), scope-aware function extraction
- **Python** — Indentation-based scope tracking for function boundaries
- **Rust/Go/Java/PHP** — Brace-delimited scope tracking with language-specific patterns
- **Ruby** — `def`/`end` block tracking
- **URLs** — Regex across all languages
- **Fallback** — Regex for any edge case Bun can't handle

## When to Use

- Understanding architecture — `stats`, `hotspots`, `layers`, `pagerank`, `hubs`
- Finding critical code — `bridges`, `call-graph`, `fn-info`
- Cleaning up — `dead-files`, `dead-functions`, `orphan-exports`
- Before refactoring — `blast-radius`, `bridges`, `similar`
- Debugging breakage — `why`, `paths`, `call-graph`
- Security audit — `phone-home`
- Comparing versions — `compare`
- Visualizing — `dot [target] | dot -Tpng -o graph.png`
