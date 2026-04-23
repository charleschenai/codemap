# codemap

**Know your codebase before you touch it.**

codemap builds a full import graph of any project and answers 25 structural questions about it — in under 500ms. One file. Zero dependencies. No config.

```
$ codemap stats
Scanned 1946 files in 128ms

=== Codemap Stats ===
Files: 1946
Lines: 495,552
Import edges: 14,267
External URLs: 103
Exports: 12,841
```

## Why

Every codebase has hidden structure: files that silently break 500 others when changed, exports nobody uses, circular dependencies buried three layers deep, and external URLs phoning home to services you forgot about.

codemap finds all of it. Instantly.

## Quick Start

```bash
# requires bun (https://bun.sh)
git clone https://github.com/charleschenai/codemap.git
cd codemap && bun link

# or just run it
bun codemap.ts --dir /path/to/project stats
```

## What It Can Do

### Understand Structure

| Command | What it tells you |
|---------|-------------------|
| `codemap stats` | Files, lines, imports, URLs — the 10-second overview |
| `codemap trace <file>` | What a file imports, and everything that imports it |
| `codemap layers` | Auto-detects architectural layers (entry points → orchestration → services → utilities) |
| `codemap hotspots` | Most coupled files — where complexity concentrates |
| `codemap size` | Largest files ranked with percentages — find what needs splitting |

```
$ codemap hotspots
=== Hotspots (top 5 most coupled files) ===

   496 coupling  src/ink.ts  (45→ 451←)
   347 coupling  src/utils/debug.ts  (10→ 337←)
   286 coupling  src/commands.ts  (110→ 176←)
   275 coupling  src/screens/REPL.tsx  (267→ 8←)
   258 coupling  src/Tool.ts  (18→ 240←)
```

### Find What Matters

| Command | What it tells you |
|---------|-------------------|
| `codemap pagerank` | Which files are *structurally* most important (recursive, not just edge count) |
| `codemap hubs` | Separates orchestrators (import many) from authorities (imported by many) |
| `codemap bridges` | Articulation points — files whose removal disconnects parts of the graph |
| `codemap clusters` | Natural module boundaries via community detection |
| `codemap islands` | Disconnected subgraphs — isolated subsystems |

```
$ codemap bridges
=== Bridge Files (94 articulation points) ===
Removing any of these disconnects parts of the graph:

   496 connections  src/ink.ts
   286 connections  src/commands.ts
   275 connections  src/screens/REPL.tsx
```

### Navigate Dependencies

| Command | What it tells you |
|---------|-------------------|
| `codemap why <A> <B>` | Shortest import path between two files |
| `codemap paths <A> <B>` | ALL import paths (up to 20, depth-limited) |
| `codemap subgraph <pattern>` | Full connected component around a file or pattern |
| `codemap similar <file>` | Files with the most similar import profile (Jaccard similarity) |

```
$ codemap why src/main.tsx src/Tool.ts
Shortest path (1 hops):

  src/main.tsx
  → src/Tool.ts
```

### Audit and Clean

| Command | What it tells you |
|---------|-------------------|
| `codemap blast-radius <file>` | Everything affected if a file changes |
| `codemap phone-home` | Every file with external URLs (security audit) |
| `codemap coupling <pkg>` | Files importing a specific package |
| `codemap dead-files` | Files nothing imports |
| `codemap orphan-exports` | Exports that nothing in the codebase uses |
| `codemap circular` | Circular dependency chains |
| `codemap diff <ref>` | Blast radius of everything changed since a git ref |
| `codemap functions <file>` | Exports in a file |
| `codemap callers <name>` | Where a function/class is referenced |

### Compare and Visualize

| Command | What it tells you |
|---------|-------------------|
| `codemap compare <dir>` | Structural A/B diff — files, imports, coupling, URLs |
| `codemap dot [target]` | Graphviz DOT output (pipe to `dot -Tpng -o graph.png`) |

```
$ codemap compare ~/Desktop/old-version
=== Compare: current vs /Users/you/Desktop/old-version ===

           Current    Other    Delta
Files:        1946     1946        0
Lines:      495552   495552        0
Imports:     14267    14267        0
URLs:          103      103        0

Added files (30):
  + src/services/api/newClient.ts
  ...
```

## How It Works

1. Walks the directory tree (skips `node_modules`, `.git`, `dist`, `build`)
2. Regex-extracts all `import`/`export`/`require`/dynamic `import()` statements
3. Resolves imports (relative paths, tsconfig path aliases, `.js` → `.ts` swaps)
4. Builds a directed graph with reverse edges (importedBy)
5. Runs the requested analysis on the graph

No AST parsing. No tree-sitter. No dependencies to install. The tradeoff is precision on edge cases — but for structural analysis, regex catches 99% of real imports and runs 100x faster.

### Algorithms

- **PageRank** — 20-iteration power method, 0.85 damping factor
- **HITS** — Iterative hub/authority scoring, L2-normalized
- **Bridges** — Tarjan's articulation point algorithm, fully iterative (no recursion)
- **Clusters** — Label propagation with convergence detection
- **Similarity** — Jaccard coefficient on combined import + importer sets
- **Layers** — BFS from entry points with cycle-safe first-visit depth assignment

## Supported Languages

TypeScript, JavaScript, Python, Rust, Go, Java, Ruby, PHP — anything with `import`, `from`, or `require` statements.

## Plugin

Available as a Claude Code plugin with `/codemap`. See `skills/codemap/SKILL.md` for the skill definition.

## License

MIT
