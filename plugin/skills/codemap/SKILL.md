---
name: codemap
description: Analyze codebase structure with 25 actions — trace imports, blast radius, PageRank, HITS hubs/authorities, bridges, clusters, community detection, similarity, subgraphs, DOT export, A/B compare, and more. Use when asked to understand code structure, audit dependencies, or prepare for refactoring.
user-invocable: true
allowed-tools:
  - Bash(bun *)
  - Bash(codemap *)
  - Bash(~/bin/codemap *)
  - Read
  - Grep
---

# /codemap — Codebase Dependency Analysis

Scan a codebase and answer structural questions about it. 25 actions, zero dependencies, single file.

## Usage

```bash
bun ~/bin/codemap [--dir <path>] <action> [target]
```

## Actions

### Analysis
| Action | What | Example |
|--------|------|---------|
| `stats` | Codebase overview | `codemap stats` |
| `trace <file>` | Imports and importers of a file | `codemap trace src/utils/auth.ts` |
| `blast-radius <file>` | All files affected if this changes | `codemap blast-radius src/api/client.ts` |
| `phone-home` | Files with external URLs | `codemap phone-home` |
| `coupling <pattern>` | Files importing a package/pattern | `codemap coupling @anthropic-ai/sdk` |
| `dead-files` | Files nothing imports | `codemap dead-files` |
| `circular` | Circular dependency chains | `codemap circular` |
| `functions <file>` | Exports in a file | `codemap functions src/utils/auth.ts` |
| `callers <name>` | Where a function is used | `codemap callers getApiKey` |
| `hotspots` | Most coupled files | `codemap hotspots` |
| `size` | Files ranked by line count | `codemap size` |
| `layers` | Auto-detect architectural layers | `codemap layers` |
| `diff <ref>` | Blast radius of git changes | `codemap diff HEAD~5` |
| `orphan-exports` | Exports nothing uses | `codemap orphan-exports` |

### Navigation
| Action | What | Example |
|--------|------|---------|
| `why <A> <B>` | Shortest import path | `codemap why src/cli.ts src/utils/auth.ts` |
| `paths <A> <B>` | ALL import paths (up to 20) | `codemap paths src/main.tsx src/Tool.ts` |
| `subgraph <pattern>` | Connected component around a target | `codemap subgraph utils/auth` |
| `similar <file>` | Files with similar import profiles | `codemap similar src/Tool.ts` |

### Graph Theory
| Action | What | Example |
|--------|------|---------|
| `pagerank` | Recursive importance ranking | `codemap pagerank` |
| `hubs` | Hub/authority analysis (HITS) | `codemap hubs` |
| `bridges` | Articulation points (critical files) | `codemap bridges` |
| `clusters` | Community detection (module boundaries) | `codemap clusters` |
| `islands` | Disconnected components | `codemap islands` |
| `dot [target]` | Graphviz DOT export | `codemap dot src/services` |

### Comparison
| Action | What | Example |
|--------|------|---------|
| `compare <dir>` | Structural A/B diff | `codemap compare ~/Desktop/old-version` |

## When to Use

- Before deleting or refactoring — `blast-radius`, `bridges`
- Auditing security — `phone-home`
- Understanding architecture — `stats`, `hotspots`, `layers`, `pagerank`, `hubs`
- Cleaning up — `dead-files`, `orphan-exports`
- Removing a dependency — `coupling`
- Debugging unexpected breakage — `why`, `paths`
- Finding related code — `similar`, `subgraph`, `clusters`
- Before/after refactors — `compare`
- Visualizing structure — `dot [target] | dot -Tpng -o graph.png`
- Identifying critical infrastructure — `bridges`, `pagerank`

## Process

1. Run `stats` first to understand scope
2. Use the appropriate action for your question
3. Scans <500ms for most codebases — run freely
