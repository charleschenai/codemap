---
name: codemap
description: Analyze codebase structure with 145 actions on a heterogeneous graph (source files, binaries, schema tables, HTTP endpoints, ML models, IaC resources — all in one graph). 17 NetworkX centrality measures (PageRank, betweenness, eigenvector, katz, closeness, harmonic, load, brokers, voterank, group, percolation, current-flow, subgraph-centrality, second-order, dispersion, reaching, trophic, current-flow-closeness), Leiden community detection + 4 more (k-core, k-clique, modularity-max, divisive), classical algorithms (Bellman-Ford, A*, Floyd-Warshall, MST, max-flow, k-shortest, Tarjan SCC, topological sort, Cooper-Harvey-Kennedy dominator tree, Steiner tree, VF2 subgraph isomorphism, feedback arc set, cliques, diameter), link prediction (common-neighbors, jaccard, adamic-adar), temporal graph evolution (node-lifespan, edge-churn, community-evolution from git history without checkouts), spectral analysis (Fiedler bisection, Shi-Malik spectral clustering, eigengap heuristic via self-contained Lanczos eigensolver), graph exports (JSON, GraphML for yEd/Cytoscape/NetworkX, GEXF for Gephi), meta-path queries across kinds, audit composite report, kind-aware dot/mermaid viz, AST-powered call graphs, binary reverse engineering (PE/ELF/Mach-O/Java/WASM with library deps as graph nodes), ML model analysis (GGUF/SafeTensors/ONNX/CUDA), schema parsing, security scanning, web scraper blueprinting, LSP integration, composite CI checks. TRIGGER when asked to understand code structure, run an architectural audit, find load-bearing files, trace cross-domain dependencies (source→endpoint, binary→dll), find graph bottlenecks (Fiedler), bisect or k-cluster a codebase spectrally, surface young hotspots / vestigial imports / cluster-evolution events from git history, find missing-import bugs via link prediction, recommend a community count via the eigengap heuristic, reverse engineer binaries, map APIs, scan for secrets, or prepare for refactoring.
user-invocable: true
allowed-tools:
  - Bash(codemap *)
  - Bash(~/bin/codemap *)
  - Bash(~/Desktop/codemap/target/release/codemap *)
  - Read
  - Grep
---

# /codemap — Heterogeneous-Graph Codebase Analysis & Reverse Engineering (145 actions)

Single Rust binary. **One graph, many node types**: source files share a graph with PE/ELF/Mach-O binaries + their imported DLLs + symbol tables, HTTP endpoints (auto-promoted from URL strings), schema tables (Clarion/SQL/dBASE), GraphQL/Proto/OpenAPI types, Docker services, Terraform resources, ML model files. All graph algorithms (PageRank, Leiden, betweenness, Fiedler, etc.) run uniformly across mixed kinds.

15 languages via tree-sitter AST. Rayon parallel. Bincode cache (typed-node mutations persist across CLI runs). No external services.

## Quick Start

```bash
codemap [--dir <path>] <action> [target]
codemap --dir ~/project stats              # overview
codemap --dir ~/project audit              # one-page architectural risk overview
codemap --dir ~/project fiedler            # find bottleneck / natural bisection
codemap --dir ~/project node-lifespan      # find young hotspots from git history
codemap --dir . pe-imports /path/to.exe    # reverse engineer a binary
```

Options: `--json` (JSON envelope with ok/error), `--tree` (ASCII tree for data-flow), `--no-cache`, `--watch [secs]`, `-q` (quiet), `--dir` (repeatable for multi-repo), `--include-path` (C/C++ includes).

---

## When to Use Each Action

### "I need an architectural risk overview" (start here for unfamiliar code)
| Trigger | Action | Example |
|---------|--------|---------|
| One-page audit before refactoring | `audit` | `codemap --dir src audit` → chokepoints + brokers + 🚨 dual-risk + clusters + per-kind census |
| Find chokepoints (continuous score) | `betweenness` | Brandes 2001. Files that lie on many shortest paths. |
| Find integration brokers | `brokers` (alias `structural-holes`) | Burt 1992. Files that bridge otherwise-disconnected groups. |
| Find core nodes by importance | `pagerank` / `eigenvector` / `katz` | Random-walk / spectral / attenuated-walk variants. |
| Distance-based importance | `closeness` / `harmonic` | Use `harmonic` if graph is disconnected (Marchiori-Latora 2000). |
| Edge-traffic-based load | `load` | Newman 2001. Like betweenness but counts dependent paths, not just shortest. |
| Influence/diffusion ranking | `voterank` | Zhang 2016. Top-k spreaders if you had to "infect" the codebase. |
| Group centrality (kind-filtered) | `group <kind>` | Importance of a whole kind class as a group. |
| Endpoint criticality under attack | `percolation` | Piraveenan 2013. Removal-resilience scoring. |
| Random-walk-flow betweenness | `current-flow` | Newman 2005. Like betweenness but counts every random walk, not just shortest paths. |
| Random-walk closeness | `current-flow-closeness` | Closeness analog of current-flow. |
| **NEW (5.8+) — extra centrality** | | |
| Walk-based centrality with eigenvalue weighting | `subgraph-centrality` | Estrada-Rodriguez-Velazquez. Counts closed walks weighted by length. |
| Second-order centrality | `second-order` | Kermarrec et al. — variance of cover time, finds nodes "off the beaten path." |
| Triadic embeddedness | `dispersion` | Backstrom-Kleinberg. How spread out a node's connections are. |
| Reach (downstream coverage) | `reaching` | "What fraction of files does X reach via outgoing edges?" entry-point detector. |
| Trophic level (DAG depth) | `trophic` | Levine 1980 — "how deep is this in the abstraction stack?" |
| Detect modules (Leiden default) | `clusters [leiden\|lpa]` | Traag-Waltman-van Eck 2019. Auto-named by path prefix. |
| Hub vs authority ranking | `hubs` | Kleinberg HITS. Two-axis importance. |
| Critical single-points-of-failure | `bridges` | Tarjan articulation-point algorithm. |

### "I need to find graph bottlenecks / natural partitions" (NEW 5.11 — spectral)
| Trigger | Action | Example |
|---------|--------|---------|
| Algebraic connectivity + best bisection | `fiedler` | Computes λ₂ + Fiedler vector, sign-cuts the graph. λ₂ ≈ 0 ⇒ disconnected; λ₂ < 0.05 ⇒ near-bottleneck. Approximates Cheeger min-cut. |
| K-way clustering different from Leiden | `spectral-cluster [k=8]` | Shi-Malik 2000 normalized-cut. Top-k smallest eigenvectors of L_sym, row-normalized, then k-means. Captures structure modularity-based methods (Leiden/LPA) miss. |
| Auto-recommend a community count | `spectral-gap` | von Luxburg 2007 eigengap heuristic. Top-25 eigenvalues + finds the largest gap → suggests k. |

Capped at 5000 nodes; 2000-node graphs eigendecompose in < 1 s.

### "I need git-history-aware structural analysis" (NEW 5.10 — temporal)
| Trigger | Action | Example |
|---------|--------|---------|
| Per-file age + commit velocity | `node-lifespan` | First-seen / last-modified / commit count from one `git log --name-status -M` pass. Surfaces young hotspots (< 1y old, high commits/day), active veterans, ancient stable. |
| Detect vestigial imports | `edge-churn [N=500]` | Per-edge co-change count across last N commits. Zero co-change with both files in history = likely dead structural import. |
| Track cluster evolution over time | `community-evolution [N=4]` | LPA at N evenly-spaced snapshots (filtering each to nodes that existed by then). Detects BIRTH / DEATH / SPLIT / MERGE events via Jaccard. No git checkouts. |

### "I need cross-domain queries (heterogeneous graph)"
| Trigger | Action | Example |
|---------|--------|---------|
| Find source files that hit APIs | `meta-path "source->endpoint"` | URL strings auto-promote to HttpEndpoint nodes. |
| Trace binary→DLL→symbol chains | `meta-path "pe->dll->symbol"` | PE/ELF/Mach-O imports become real graph edges. |
| Find code that touches schema tables | `meta-path "source->table"` | SQL/Clarion/dBASE schemas become typed nodes. |
| Filter centrality by kind | any centrality action with `<kind>` target | `codemap --dir src betweenness table` |
| Run multiple actions in one process | `pipeline` | `codemap pipeline "js-api-extract:src/,meta-path:source->endpoint"` |

Entity kinds: `source pe elf macho jclass wasm dll symbol endpoint form table field proto gql oapi docker tf model asm`. Auto-classified during scan: `.exe/.dll/.so/.dylib → binary`, `.gguf/.safetensors/.onnx/.pyc → model`, `.proto/.tf/.clw/.dbf → schema`. URL strings in source code → HttpEndpoint nodes (filtered to drop test/template/credential/xmlns URLs).

### "I need to understand this codebase" (orientation)
| Trigger | Action | Example |
|---------|--------|---------|
| First look at a project | `stats` | File count, line count, edges, URLs, exports, extension breakdown. |
| Quick dashboard | `summary` | Box-drawn project health card. |
| Health check / code quality | `health` | 0-100 score with letter grade. |
| What does this file do? | `trace <file>` | Imports / importers / URLs / exports for one file. |
| What are the main files? | `pagerank` | Top 30 by importance. |
| What are the layers? | `layers` | BFS depth → entry / orchestration / service / utility / leaf. Flags cross-layer violations. |
| Build an LLM context map | `context [budget]` | `codemap --dir src context 8k` — fits in a prompt. |
| Directory overview with functions | `structure` | Tree view per directory with function lists. |
| Detect entry points | `entry-points` | Files with no incoming imports + main/index/cli basenames. |
| Find decorators/attributes by pattern | `decorators <pattern>` | `decorators test` finds all @test/#[test]/@pytest decorations. |

### "I need shortest paths / classical graph algorithms" (NEW 5.8-5.9)
| Trigger | Action | Example |
|---------|--------|---------|
| Negative-weight shortest paths | `bellman-ford <file>` | Detects negative cycles. |
| Heuristic shortest path A→B | `astar <A> <B>` | A* with admissible heuristic. |
| All-pairs shortest paths | `floyd-warshall` | O(V³). Caps for large graphs. |
| Graph diameter | `diameter` | Longest shortest path. |
| Minimum spanning tree | `mst` | Kruskal across the union edge set. |
| Find max cliques | `cliques` | Bron-Kerbosch with pivoting. Top-20 by size. |
| Top-K shortest paths A→B | `kshortest <A> <B>` | Yen's algorithm. |
| Min-cut / max-flow | `max-flow <S> <T>` | Edmonds-Karp BFS Ford-Fulkerson. |
| Break dependency cycles | `feedback-arc` (alias `feedback-arc-set`) | Greedy heuristic. Suggests edges to break to make graph acyclic. |
| Strongly-connected components | `scc` | Tarjan iterative. Reports cyclic-dep clusters by size. |
| Topological sort | `topo-sort` (alias `topological-sort`) | Kahn's. Errors if cyclic with pointer to `scc`. |
| Dominator tree | `dominator-tree [entry]` | Cooper-Harvey-Kennedy. Auto-detects entry by max-fanout if not given. |
| Min-edge subgraph connecting N nodes | `steiner <a,b,c,...>` | MST 2-approximation heuristic. |
| Find pattern instances in graph | `subgraph-iso "<kind1>-><kind2>->..."` | VF2-style matching. Capped at 100 matches. |

### "I need to find missing imports / link prediction" (NEW 5.8)
| Trigger | Action | Example |
|---------|--------|---------|
| Files that share neighbors but don't import each other | `common-neighbors` | Top-30 unconnected pairs. |
| Same, normalized for degree | `jaccard` | |shared| / |union|. |
| Hub-discounted neighbor overlap | `adamic-adar` | Σ 1/log(degree(shared)). |

Useful for: "should A import B?" "what file is X probably missing an import to?"

### "I need to detect communities" (Leiden + 4 more, NEW 5.8)
| Trigger | Action | Example |
|---------|--------|---------|
| Default community detection (modularity) | `clusters` (= `leiden`) | Auto-named by path prefix or kind. |
| Legacy label-propagation variant | `clusters lpa` | Faster, slightly noisier. |
| Find dense skeleton (peeling) | `k-core <k>` | Iteratively remove nodes with degree < k. |
| Overlapping communities | `k-clique <k>` | Palla et al. 2005 k-clique percolation. |
| Greedy modularity maximization | `modularity-max` | Clauset-Newman-Moore. |
| Edge-betweenness divisive clustering | `divisive` | Girvan-Newman. Refuses on n > 500. |

### "What happens if I change X?"
| Trigger | Action | Example |
|---------|--------|---------|
| What breaks if I touch this file? | `blast-radius <file>` | BFS over imported_by. |
| Is this PR risky? | `risk <ref>` | 0-100 score combining churn × coupling. |
| Full diff impact analysis | `diff-impact <ref>` | Changed files + transitive impact. |
| What changed + blast radius | `diff <ref>` | git diff intersected with graph. |
| Functions changed since ref | `diff-functions <ref>` | Symbol-level diff. |
| Exports changed since ref | `api-diff <ref>` | What public surface changed. |
| Preview a rename | `rename <old> <new>` | Shows everywhere a symbol would change. |
| How connected is a file? | `import-cost <file>` | Recursive import weight. |
| Hidden git coupling | `git-coupling [N=200]` | Files that change together but don't import. |
| Per-file churn risk | `churn <ref>` | Recent changes × coupling = risk score. |

### "How does A connect to B?"
| Trigger | Action | Example |
|---------|--------|---------|
| Shortest path between files | `why <A> <B>` | Single path. |
| ALL paths between files | `paths <A> <B>` | Up to 100 paths. |
| Everything connected to X | `subgraph <pattern>` | Filtered by name pattern. |
| Files with similar imports | `similar <file>` | Ranked by import-set Jaccard. |
| Who calls this function? | `callers <name>` | Word-boundary cross-file regex. |
| Function call graph | `call-graph [file]` | AST-resolved cross-file call edges. |
| Function details | `fn-info <file>` | Functions, params, lines, call sites. |
| List a file's exported symbols | `exports <file>` (alias `functions`) | Public-API surface of one file. |
| Find duplicate code | `clones [file]` | Token-shingle clone detection. |
| Find complex functions | `complexity [file]` | Cyclomatic complexity per function. Skips minified JS. |

### "I need to clean up this codebase"
| Trigger | Action | Example |
|---------|--------|---------|
| Find unused files | `dead-files` | Zero importers + not main/index/cli basenames. |
| Find unused functions | `dead-functions` | Exported but never called. |
| Find unused exports | `orphan-exports` | Exports not imported anywhere. |
| Find unused dependencies | `dead-deps` | Manifest entries not referenced in imports. |
| Find circular imports | `circular` | DFS cycle detection with rotation dedup. |
| Most coupled files | `hotspots` | Top 30 by imports + imported_by. |
| Largest files | `size` | Top 30 by line count + % of codebase. |
| Files importing a package | `coupling <pattern>` | `coupling lodash` → all files using it. |
| Files phoning home (URLs) | `phone-home` | URL extraction grouped by host. |

### "I need to trace data flow / find security issues"
| Trigger | Action | Example |
|---------|--------|---------|
| Trace user input to database (interprocedural) | `taint <source> <sink>` | `taint req.body db.query`. CPG-backed, follows cross-file calls. |
| What feeds this line? (backward slice) | `slice <file>:<line>` | Backward def-use BFS. |
| Where does this value go? (forward) | `trace-value <f>:<l>:<n>` | Forward use-chain. |
| Find all sink points | `sinks [file]` | Built-in sink list (db.query, fs.write, exec, etc.) + custom via `.codemap/dataflow.json`. |
| Data flow for a function | `data-flow <file> [fn]` | Per-fn def/use/call summary. |
| Scan for hardcoded secrets | `secret-scan` | AWS keys, GitHub PATs, JWTs, passwords, conn strings, with masking + severity. |
| Map the public API surface | `api-surface` | All exported symbols, grouped. |

### "I need to reverse engineer a compiled binary"
| Trigger | Action | Example |
|---------|--------|---------|
| **Windows PE/DLL** | | |
| What DLLs and APIs does it call? | `pe-imports <file>` | Adds DllNode + SymbolNode to graph. |
| Extract SQL / strings from binary | `pe-strings <file>` | UTF-8 + UTF-16 + length filter. |
| Smart SQL mining + table map | `sql-extract <file\|dir>` | Categorizes by SELECT/INSERT/UPDATE/DDL. |
| Version info, manifests, UI strings | `pe-resources <file>` | RT_STRING, RT_VERSION, RT_DIALOG. |
| DLL export table | `pe-exports <file>` | Adds SymbolNode entries. |
| PDB paths, build date, compiler | `pe-debug <file>` | DEBUG_DIRECTORY parsing. |
| Section entropy (packed?) | `pe-sections <file>` | UPX / packed-binary detector. |
| .NET types, methods, assemblies | `dotnet-meta <file>` | CLR metadata stream parsing. |
| Compare two binary versions | `binary-diff <f1> <f2>` | Section + import/export delta. |
| **Linux ELF** | | |
| ELF sections, symbols, deps | `elf-info <file>` | DT_NEEDED entries become DllNode edges. |
| **macOS Mach-O** | | |
| Mach-O load commands, dylibs | `macho-info <file>` | LC_LOAD_DYLIB → DllNode edges. Fat/universal binaries supported. |
| **Java** | | |
| Class file / JAR analysis | `java-class <file>` | Magic + classfile structure + main-class. |
| **WebAssembly** | | |
| WASM imports, exports, sections | `wasm-info <file>` | Module structure. |

### "I need to parse a legacy database schema"
| Trigger | Action | Example |
|---------|--------|---------|
| Clarion .CLW DDL file | `clarion-schema <file>` | Files / Records / Fields → schema nodes. |
| dBASE/FoxPro .DBF file | `dbf-schema <file>` | Header + field descriptors. |

### "I need to map a web application" (scraper blueprint)
| Trigger | Action | Example |
|---------|--------|---------|
| Map API from HAR capture | `web-api <har>` | Endpoint / method / params / status / auth detection. |
| Analyze saved HTML page | `web-dom <html>` | Forms / tables / nav / click handlers / inline JS API calls. |
| Build sitemap from HTML files | `web-sitemap <dir>` | Page graph + hubs + dead ends. |
| Full scraper blueprint | `web-blueprint <har> [html]` | Auth recipe + endpoints + pagination + rate-limit hints. |
| Find APIs in JS bundles | `js-api-extract <file\|dir>` | fetch / axios / XHR / `apiUrl: '...'` constants. |

### "I need to understand infrastructure / API specs"
| Trigger | Action | Example |
|---------|--------|---------|
| Protobuf service definitions | `proto-schema <file>` | Messages + RPC services. |
| OpenAPI/Swagger spec | `openapi-schema <file>` | Paths + schemas. JSON or YAML. |
| GraphQL schema | `graphql-schema <file>` | Types + resolvers. |
| Docker Compose services | `docker-map <file>` | Service graph + topo startup order. |
| Terraform resources | `terraform-map <file>` | Resources + module references. |

### "I need to check dependencies"
| Trigger | Action | Example |
|---------|--------|---------|
| Show dependency tree | `dep-tree [manifest]` | 8 manifest formats (Cargo / npm / pip / go.mod / etc.). |
| Find unused dependencies | `dead-deps` | Manifest entries vs actual imports. |
| Files importing a package | `coupling <pattern>` | `coupling react` → all React-using files. |

### "I need cross-language bridge analysis"
| Trigger | Action | Example |
|---------|--------|---------|
| All cross-lang bridges | `lang-bridges` | PyO3 / pybind11 / TORCH_LIBRARY / Triton / CUDA / monkey-patches. |
| GPU kernel inventory | `gpu-functions` | Triton + CUDA __global__ + launches. |
| Python monkey-patches | `monkey-patches` | `module.Class = Replacement` patterns. |
| Backend dispatch tables | `dispatch-map` | YAML native_functions.yaml-style op→kernel maps. |

### "I need to use LSP for deeper analysis"
| Trigger | Action | Example |
|---------|--------|---------|
| Extract symbols from file | `lsp-symbols <server> <file>` | `lsp-symbols rust-analyzer src/main.rs` |
| Find all references | `lsp-references <server> <f:l:c>` | Cursor-position-based. |
| Call hierarchy | `lsp-calls <server> <f:l:c>` | Incoming + outgoing. |
| Get diagnostics | `lsp-diagnostics <server> <file>` | Errors + warnings from the LSP. |
| Get type info | `lsp-types <server> <file>` | Inferred types per symbol. |

Works with: rust-analyzer, pylsp, typescript-language-server, clangd, gopls — any LSP-compliant server.

### "I need a diagram"
| Trigger | Action | Example |
|---------|--------|---------|
| Graphviz DOT (kind-aware shapes) | `dot [target]` | `codemap --dir src dot parser > graph.dot` |
| Mermaid (GitHub-native) | `mermaid [target]` | Matching classDef per kind. |

### "I need to export the graph for an external tool" (NEW 5.9)
| Trigger | Action | Example |
|---------|--------|---------|
| Codemap-native JSON dump | `to-json` | Round-trip-safe full graph. |
| GraphML for yEd / Cytoscape / NetworkX | `to-graphml` | Standard XML graph format. |
| GEXF for Gephi | `to-gexf` | Per-EntityKind viz colors included. |

### "I need to compare repos / refs / binaries"
| Trigger | Action | Example |
|---------|--------|---------|
| Compare two repos | `compare <dir>` | Two-graph diff. |
| Functions changed since ref | `diff-functions <ref>` | Symbol-level. |
| Exports changed since ref | `api-diff <ref>` | Public surface delta. |
| Compare two binaries | `binary-diff <f1> <f2>` | Sections + imports + exports. |
| Detect entry points | `entry-points` | Multi-criteria entry detection. |
| Disconnected components | `islands` | CCs sorted by size. |

### "I need to analyze an ML model file"
| Trigger | Action | Example |
|---------|--------|---------|
| GGUF model (llama.cpp) | `gguf-info <file>` | Tensor shapes + metadata + quantization. |
| SafeTensors weights | `safetensors-info <file>` | Header + tensor list. |
| ONNX model | `onnx-info <file>` | Graph + ops + inputs/outputs. |
| Python bytecode | `pyc-info <file>` | Magic + module + co_consts. |
| CUDA kernels (cubin/fatbin) | `cuda-info <file>` | SM target + kernel names. |

### "I need a quick CI check or project briefing"
| Trigger | Action | Example |
|---------|--------|---------|
| Pass/fail health check for CI | `validate` | Exit code reflects health threshold. |
| Full PR/change analysis | `changeset <ref>` | Diff + risk + impact in one report. |
| Context-switching briefing | `handoff [budget]` | Resume-where-you-left-off summary. |
| One-page architectural risk overview | `audit` | Chokepoints + brokers + dual-risk + clusters + per-kind census. |
| Chain multiple actions in one process | `pipeline "act1:t1,act2:t2,..."` | `pipeline "web-blueprint:capture.har,meta-path:source->endpoint"` |

---

## Picking the right action when faced with ambiguity

| You want… | Best fit |
|-----------|----------|
| "What's the most important file" | `pagerank` (default) or `betweenness` (chokepoints) |
| "What's most likely to break" | `risk <ref>` or `audit` (dual-risk nodes) |
| "Where do I start refactoring" | `audit` first, then `fiedler` for natural bisection lines |
| "What's actually used in this PR" | `diff-impact <ref>` |
| "Is this codebase modular?" | `clusters` for module count; `spectral-gap` for the eigengap heuristic; `fiedler` for whether λ₂ is small (bottleneck) or large (well-connected) |
| "Which imports are vestigial" | `edge-churn` (zero co-change with both files in history) |
| "What changed last week" | `node-lifespan` (young hotspots) + `churn HEAD~50` |
| "Which files should know about each other but don't" | `common-neighbors` / `jaccard` / `adamic-adar` |
| "How do I cluster differently from Leiden?" | `spectral-cluster <k>` (captures bottleneck-shaped structure) |
| "Where are the cyclic deps?" | `scc` (typed components) or `circular` (file-level cycles) |
| "What's the entry point?" | `entry-points` or `dominator-tree` (auto-detects) or `reaching` (top-1 reach) |
| "Which file connects everything?" | `betweenness` (top-1) or `bridges` (articulation points) |
| "Cluster of code that grew together" | `community-evolution` then `audit` cluster summary |

---

## Supported Languages (15 + 4 regex)

**Tree-sitter AST:** TypeScript, TSX, JavaScript, Python, Rust, Go, Java, Ruby, PHP, C, C++, CUDA, Bash/Shell, C#, Lua
**Regex fallback:** Kotlin, SQL, YAML, CMake

## Key Behaviors

- `--dir` defaults to current directory. **Always pass `--dir <small_path>`** — without it, codemap scans CWD recursively (a `--dir ~` from home can balloon to 50 GB heap and OOM-kill its tmux scope).
- Repeat `--dir` for multi-repo scans. Imports crossing repos become real edges in the merged graph.
- Target arguments are joined with spaces: `codemap why a.rs b.rs` works.
- `->` separator is stripped: `codemap why a.rs -> b.rs` works.
- **Quote arrow patterns** for `meta-path` and `subgraph-iso`: `meta-path "source->endpoint"` (bash treats unquoted `>` as redirection).
- Reverse engineering actions (`pe-*`, `elf-*`, `macho-*`, `java-class`, `wasm-info`, `clarion-schema`, `dbf-schema`, schema actions, ML actions, web actions) take absolute file paths — they don't use the scan directory.
- `--json` wraps output in `{"action", "target", "files", "result", "ok", "error"}`.
- `--tree` gives ASCII tree rendering for `taint`, `slice`, `trace-value`.
- File size limit: 256MB for binaries, 10MB for source files.
- Cache at `.codemap/cache.bincode` — delete the directory or pass `--no-cache` to force a fresh scan. RE-action mutations (PE imports → DLL nodes, URL strings → endpoints) persist across CLI runs.
- Custom sinks/sources via `.codemap/dataflow.json`.
- Spectral analysis caps at 5000 nodes; larger graphs return a clear error suggesting `clusters leiden` instead.
- Temporal actions need a git repo. They run on a single `git log --name-status -M` pass — no checkouts, fast even on large histories.
