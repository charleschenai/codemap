# codemap

Codebase dependency analysis. 25 actions. Zero dependencies. Single file.

Scans source files, builds an import graph, answers structural questions — from basic tracing to PageRank, HITS hub/authority analysis, Tarjan's bridge detection, and community clustering. Works on any codebase in under 500ms.

## Install

```bash
# Requires Bun (https://bun.sh)
curl -fsSL https://bun.sh/install | bash
git clone https://github.com/charleschenai/codemap.git
cd codemap && bun link
```

Or just run directly:

```bash
bun codemap.ts --dir /path/to/project stats
```

## Usage

```bash
codemap [--dir <path>] <action> [target]
```

### Analysis

```bash
codemap stats                              # codebase overview
codemap trace src/utils/auth.ts            # imports + importers of a file
codemap blast-radius src/api/client.ts     # all files affected if this changes
codemap phone-home                         # find all external URLs
codemap coupling @some/package             # files importing a package
codemap dead-files                         # files nothing imports
codemap circular                           # circular dependency chains
codemap functions src/utils/auth.ts        # exports in a file
codemap callers getApiKey                  # find function usage
codemap hotspots                           # most coupled files
codemap size                               # files ranked by line count
codemap layers                             # auto-detect architectural layers
codemap diff HEAD~5                        # blast radius of git changes
codemap orphan-exports                     # exports nothing uses
```

### Navigation

```bash
codemap why src/cli.ts src/utils/auth.ts   # shortest import path
codemap paths src/main.tsx src/Tool.ts     # ALL import paths between files
codemap subgraph utils/auth                # connected component around a target
codemap similar src/Tool.ts               # files with similar import profiles
```

### Graph Theory

```bash
codemap pagerank                           # recursive importance ranking
codemap hubs                               # hub/authority analysis (HITS)
codemap bridges                            # articulation points (critical files)
codemap clusters                           # community detection (module boundaries)
codemap islands                            # disconnected components
codemap dot src/services                   # Graphviz DOT export
```

### Comparison

```bash
codemap compare ~/Desktop/old-version     # structural A/B diff
```

## How It Works

Regex-based import scanning. No AST, no tree-sitter, no dependencies. Scans any language that uses import/require/from statements. Builds the full import graph in memory, answers structural queries instantly.

- **PageRank**: 20-iteration power method with 0.85 damping factor
- **HITS**: Iterative hub/authority scoring with L2 normalization
- **Bridges**: Tarjan's articulation point algorithm (iterative, handles cycles)
- **Clusters**: Label propagation community detection
- **Similarity**: Jaccard coefficient on import/importer profiles

## Supported Languages

TypeScript, JavaScript, Python, Rust, Go, Java, Ruby, PHP — anything with string-based imports.

## As a Claude Code Plugin

codemap is available as a Claude Code plugin with the `/codemap` skill. Install via the plugin marketplace or point to this repo.

## License

MIT
