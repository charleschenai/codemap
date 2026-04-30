---
name: codemap
description: Heterogeneous-graph codebase analysis with 163 actions. ONE graph spans source files, PE/ELF/Mach-O binaries, DLL/symbol/function nodes, HTTP endpoints, schema tables, ML models, IaC resources, licenses, CVEs, certificates, Android packages, permissions — every graph algorithm (PageRank, Leiden, Fiedler, betweenness) runs uniformly across kinds. 17 NetworkX centrality measures, Leiden community detection, classical algorithms (Bellman-Ford / A* / Floyd-Warshall / SCC / dominator-tree / Steiner / VF2), spectral analysis (Fiedler bisection / Shi-Malik clustering / eigengap), temporal graph evolution from git history, link prediction, AST-powered call graphs across 15 languages, x86/x64 binary disassembly with intra-binary call graphs, supply-chain analysis (license-scan + offline CVE matching + SPDX/CycloneDX SBOM export + fuzzy hashing + Authenticode cert nodes), recon-artifact parsers (robots/sitemap/Wappalyzer-fingerprint/crt.sh). Pure static analyzer — consumes captured artifacts; never makes network requests. TRIGGER when asked to understand code structure, run an architectural audit, find load-bearing files, trace cross-domain dependencies (source→endpoint, binary→dll→cve), find graph bottlenecks (Fiedler), reverse engineer binaries, map APIs, scan for secrets, surface git-history hotspots, generate SBOMs, or parse recon artifacts (robots.txt, sitemap, crt.sh dumps).
user-invocable: true
allowed-tools:
  - Bash(codemap *)
  - Bash(~/bin/codemap *)
  - Bash(~/Desktop/codemap/target/release/codemap *)
  - Read
  - Grep
---

# /codemap — Heterogeneous-Graph Codebase Analysis (163 actions)

Single Rust binary. **One graph, many node types** (28 EntityKinds): source files coexist with PE/ELF/Mach-O binaries + their disassembled functions, DLLs, imported symbols, HTTP endpoints, web forms, schema tables, Protobuf/GraphQL/OpenAPI types, Docker/Terraform resources, ML model files, compilers, string literals, overlays, certificates, CVEs, licenses, Android packages, and permissions. Every graph algorithm runs uniformly across kinds — `pagerank --type bin_func` ranks functions inside binaries; `meta-path "source->dll->cve"` traces vulnerable transitive deps.

15 languages via tree-sitter AST. Pure static analyzer — codemap **never makes network requests**. Consumes captured artifacts (files you name explicitly).

---

## Quick Start

```bash
codemap [--dir <path>] <action> [target]
codemap --dir ~/project audit              # one-page architectural risk overview
codemap --dir ~/project fiedler            # bottleneck / natural bisection
codemap --dir . pe-imports /path/to.exe    # reverse-engineer a binary
codemap --dir ~/project license-scan       # compliance scan
```

Options: `--json` (JSON envelope), `--tree` (ASCII tree for data-flow), `--no-cache`, `--watch [secs]`, `-q` (quiet), `--dir` (repeatable for multi-repo), `--include-path` (C/C++ includes).

---

## Tier 1 — If you only know 10 actions, know these

These cover ~80% of typical codemap workflows. When in doubt, reach for one of these first:

| Action | When to use it | Output |
|---|---|---|
| `audit` | First look at any unfamiliar codebase. One-page architectural risk overview. | Chokepoints + brokers + 🚨 dual-risk nodes + clusters + per-kind census |
| `pagerank` | "Which files matter most?" | Top 30 by importance |
| `fiedler` | "Where's the bottleneck?" / "What's the natural fault line?" | λ₂ + sign-cut bisection |
| `blast-radius <file>` | "What breaks if I change X?" | BFS over importers |
| `meta-path "<a>-><b>"` | Cross-domain queries (source→endpoint, elf→dll→cve, apk→permission) | Typed paths through the graph |
| `taint <source> <sink>` | Security: trace user input to a sensitive call | CPG-backed interprocedural taint paths |
| `bin-disasm <binary>` | RE: x86/x64 binary → BinaryFunction graph | Function list + intra-binary call graph |
| `license-scan` | Compliance check on the current repo | License nodes + leaky-permission flags |
| `cve-match` | Supply chain: link DLLs to imported CVE feed | dll → cve edges |
| `web-fingerprint <html-or-bundle>` | "What stack is this site running?" | Wappalyzer-style framework / CMS / CDN identification |

If none of those fit — keep reading.

---

## Tier 2 — What am I trying to do?

Intent → action lookup. Most codebase questions resolve to one of these:

### Understanding code

| You want to know… | Reach for | Why |
|---|---|---|
| "What does this codebase do" | `stats` → `summary` → `audit` | Ladder from facts to architecture in 3 calls |
| "What are the layers" | `layers` | BFS depth → entry / orchestration / service / leaf, flags cross-layer violations |
| "What does this file do" | `trace <file>` | Imports + importers + URLs + exports |
| "What are the modules" | `clusters` (Leiden) or `spectral-cluster <k>` | Modularity-based vs cut-based clustering |
| "Make a context map for an LLM" | `context [budget]` | Fits in a prompt |
| "Score this codebase 0-100" | `health` | Letter grade with breakdown |

### Change risk / impact

| You want to know… | Reach for |
|---|---|
| "What breaks if I touch this file" | `blast-radius <file>` |
| "Is this PR risky" | `risk <ref>` (0-100) |
| "What changed + transitive impact" | `diff-impact <ref>` |
| "What public API changed" | `api-diff <ref>` |
| "Which functions changed" | `diff-functions <ref>` |
| "Preview a rename" | `rename <old> <new>` |
| "How recently was this churned" | `churn <ref>` (per-file) |
| "What files change together" | `git-coupling [N]` (hidden coupling) |

### Connecting things

| You want to know… | Reach for |
|---|---|
| "Shortest path A → B" | `why <A> <B>` |
| "Every path A → B" | `paths <A> <B>` |
| "Who calls this function" | `callers <name>` |
| "All files connected to X" | `subgraph <pattern>` |
| "Files with similar import sets" | `similar <file>` |
| "Functions inside a binary" | `bin-disasm <bin>` then `pagerank bin_func` |

### Finding bottlenecks / centrality

| You want to know… | Reach for |
|---|---|
| "What's load-bearing" | `audit` (dual-risk = chokepoint AND broker) |
| "What's a chokepoint" | `betweenness` (continuous) or `bridges` (binary) |
| "What brokers between groups" | `brokers` (alias `structural-holes`) |
| "What's the natural bisection" | `fiedler` |
| "How many communities" | `spectral-gap` (eigengap heuristic) |
| "Top spreaders" | `voterank` |
| "Asymmetric reach" | `reaching` |

### Heterogeneous / cross-domain

| You want to know… | Reach for |
|---|---|
| "Which source files hit APIs" | `meta-path "source->endpoint"` |
| "Which binary uses what DLL" | `meta-path "pe->dll"` or `"elf->dll"` |
| "Which code touches schema tables" | `meta-path "source->table"` |
| "Vulnerable transitive deps" | `meta-path "source->binary->dll->cve"` (after `cve-match`) |
| "What functions reference this string" | `meta-path "elf->bin_func->string"` (after `bin-disasm`) |
| "What permissions does this APK use" | `meta-path "apk->permission"` |
| "Filter centrality by kind" | any centrality action with `<kind>` arg: `pagerank bin_func`, `betweenness endpoint` |

### Cleanup / dead code

| You want to know… | Reach for |
|---|---|
| "Unused files" | `dead-files` |
| "Unused functions" | `dead-functions` |
| "Unused exports" | `orphan-exports` |
| "Unused dependencies" | `dead-deps` |
| "Vestigial imports" | `edge-churn` (zero co-change with both files in history) |
| "Circular imports" | `circular` |
| "Dead structural couplings" | `edge-churn` |
| "Should files A and B import each other" | `jaccard` / `adamic-adar` (link prediction) |

### Security / data flow

| You want to know… | Reach for |
|---|---|
| "Trace user input to DB" | `taint <source> <sink>` |
| "What feeds this line" | `slice <file>:<line>` (backward) |
| "Where does this value go" | `trace-value <file>:<line>:<name>` (forward) |
| "Hardcoded secrets" | `secret-scan` |
| "All sink points" | `sinks [file]` |
| "Public API surface" | `api-surface` |
| "Files phoning home" | `phone-home` |

### Reverse engineering

| You want to know… | Reach for |
|---|---|
| "Decode a Windows binary" | `pe-imports` + `pe-exports` + `pe-strings` + `pe-meta` (Rich + TLS + entry) |
| "Disassemble x86/x64" | `bin-disasm <file>` then `pagerank bin_func` |
| "What language is this binary" | `lang-fingerprint <file>` (Go / Rust / .NET / Delphi / PyInstaller / etc.) |
| "Is this binary signed" | `pe-cert <file>` (PE Authenticode → Cert nodes) |
| "Has this been packed" | `overlay-info <file>` (entropy + NSIS/Inno/PyInstaller/ZIP detection) |
| "C++/Rust mangled names" | already auto-applied — `pe-exports` / `elf-info` show demangled names + raw `attrs[mangled]` |
| "Linux binary" | `elf-info` |
| "Mac binary" | `macho-info` |
| ".NET assembly" | `dotnet-meta` |
| "JVM .class / JAR" | `java-class` |
| "WebAssembly" | `wasm-info` |
| "Python .pyc" | `pyc-info` |
| "Android APK" | `apk-info` |
| "ML model file" | `gguf-info` / `safetensors-info` / `onnx-info` / `cuda-info` |
| "Compare two binaries" | `binary-diff <a> <b>` or `fuzzy-hash` + `fuzzy-match` |

### Supply chain / SBOM

| You want to know… | Reach for |
|---|---|
| "What licenses are in this repo" | `license-scan` |
| "Are deps vulnerable" | `cve-import <nvd.json>` then `cve-match` then `meta-path "source->dll->cve"` |
| "Generate SBOM" | `to-spdx` (SPDX 2.3) or `to-cyclonedx` (CycloneDX 1.5) |
| "Who signed this binary" | `pe-cert <file>` |
| "Find binary variants in a fleet" | `fuzzy-hash` per binary then `fuzzy-match` |

### Git-history aware (temporal)

| You want to know… | Reach for |
|---|---|
| "Young hotspots" | `node-lifespan` (< 1y old, high commits/day) |
| "Active veterans" | `node-lifespan` (> 1y old AND touched < 30d ago) |
| "Vestigial imports" | `edge-churn` (zero co-change) |
| "How clusters formed over time" | `community-evolution [N=4]` (BIRTH / DEATH / SPLIT / MERGE events) |

### Recon-artifact parsing (5.16.0+ — pure static, file-only)

| You have… | Reach for |
|---|---|
| `robots.txt` you curled | `robots-parse` (classifies + flags leaky paths) |
| `sitemap.xml` (or .gz, gunzipped first) | `web-sitemap-parse` (auto-detects ID-enumeration patterns like `/lawyer/{ID}`) |
| Saved HTML / HAR / JS bundle | `web-fingerprint` (50+ Wappalyzer-style sigs) |
| crt.sh JSON dump | `crt-parse` (subdomain harvest → Cert nodes per issuer) |

### Diagrams / export

| You want… | Reach for |
|---|---|
| GraphViz DOT (kind-aware shapes) | `dot [target]` |
| Mermaid (GitHub-native) | `mermaid [target]` |
| yEd / Cytoscape / NetworkX import | `to-graphml` |
| Gephi import | `to-gexf` |
| Codemap-native JSON | `to-json` |

### CI / handoff

| You want… | Reach for |
|---|---|
| Pass/fail health check | `validate` |
| Full PR analysis | `changeset <ref>` |
| Resume context for another session | `handoff [budget]` |
| Chain multiple actions | `pipeline "act1:t1,act2:t2"` |

---

## Tier 3 — Full action catalog by category

163 actions total. Tier 1+2 above covers the questions you'll actually ask. The rest of this section is a reference index.

### Analysis (14)
`stats` `trace` `blast-radius` `phone-home` `coupling` `dead-files` `circular` `exports`/`functions` `callers` `hotspots` `size` `layers` `diff` `orphan-exports`

### Insights (5)
`health` `summary` `decorators` `rename` `context`

### Navigation (5)
`why` `paths` `subgraph` `similar` `structure`

### Graph theory (7)
`pagerank` `hubs` `bridges` `clusters [leiden\|lpa]` `islands` `dot` `mermaid`

### Function-level (13)
`call-graph` `dead-functions` `fn-info` `diff-functions` `complexity` `import-cost` `churn` `api-diff` `clones` `git-coupling` `risk` `diff-impact` `entry-points`

### Data flow (5) — interprocedural via CPG
`data-flow` `taint` `slice` `trace-value` `sinks`

### Centrality (17 NetworkX measures)
`pagerank` `hubs` (HITS) `betweenness` `eigenvector` `katz` `closeness` `harmonic` `load` `brokers`/`structural-holes` `voterank` `group <kind>` `percolation` `current-flow` `subgraph-centrality` `second-order` `dispersion` `reaching` `trophic` `current-flow-closeness`

### Classical algorithms (14)
`bellman-ford` `astar` `floyd-warshall` `diameter` `mst` `cliques` `kshortest` `max-flow` `feedback-arc` `scc` (Tarjan) `topo-sort` (Kahn) `dominator-tree` (CHK) `steiner` `subgraph-iso` (VF2)

### Link prediction (3)
`common-neighbors` `jaccard` `adamic-adar`

### Community detection (5)
`clusters [leiden\|lpa]` `k-core` `k-clique` `modularity-max` `divisive` (Girvan-Newman)

### Spectral (3)
`fiedler` `spectral-cluster <k>` `spectral-gap` (eigengap heuristic)

### Temporal (3) — git-history aware
`node-lifespan` `edge-churn` `community-evolution`

### Reverse engineering — Windows (11)
`pe-imports` `pe-exports` `pe-strings` `pe-resources` `pe-debug` `pe-sections` `pe-meta` (Rich + TLS + entry-point) `pe-cert` (Authenticode → Cert nodes) `dotnet-meta` `clarion-schema` `dbf-schema` `sql-extract` `binary-diff`

### Reverse engineering — disassembly (1) — x86/x64 only
`bin-disasm` (registers BinaryFunction nodes + intra-binary call graph + xrefs)

### Reverse engineering — non-PE (4)
`elf-info` (demangled symbols + DT_NEEDED → Dll edges + free-form string promotion) `macho-info` (LC_LOAD_DYLIB) `java-class` (constant pool + methods) `wasm-info` (function-level call graph)

### Binary triage / fingerprinting (4)
`lang-fingerprint` (compiler / runtime detection) `overlay-info` (NSIS/Inno/PyInstaller/ZIP/entropy classification) `fuzzy-hash` (TLSH + ssdeep) `fuzzy-match` (similarity edges)

### Schemas (5)
`proto-schema` `openapi-schema` `graphql-schema` `docker-map` `terraform-map`

### Web / scraper blueprinting (5)
`web-api` (HAR) `web-dom` (HTML) `web-sitemap` (HTML dir) `web-blueprint` (HAR + HTML) `js-api-extract`

### Recon-artifact parsers (4) — pure static, file-only
`robots-parse` `web-sitemap-parse` `web-fingerprint` `crt-parse`

### ML model files (5)
`gguf-info` `safetensors-info` `onnx-info` `pyc-info` `cuda-info`

### Schema / dependency / security (4)
`secret-scan` `dep-tree` `dead-deps` `api-surface`

### Cross-language bridges (4)
`lang-bridges` (PyO3 / pybind11 / TORCH_LIBRARY / Triton / CUDA) `gpu-functions` `monkey-patches` `dispatch-map`

### LSP integration (5)
`lsp-symbols` `lsp-references` `lsp-calls` `lsp-diagnostics` `lsp-types`

### Android (1)
`apk-info` (ZIP walk + permission scan + dangerous-perm flag)

### Compliance / SBOM (5)
`license-scan` `cve-import <nvd.json>` `cve-match` `to-spdx` `to-cyclonedx`

### Heterogeneous graph traversal (1)
`meta-path "<kind1>-><kind2>->..."` (e.g. `"source->endpoint"`, `"pe->dll->symbol"`, `"apk->permission"`, `"elf->dll->cve"`)

### Graph export (3)
`to-json` `to-graphml` (yEd/Cytoscape/NetworkX) `to-gexf` (Gephi)

### Composite (5)
`audit` (one-page architectural risk overview) `validate` `changeset <ref>` `handoff [budget]` `pipeline "a:t,b:t"`

### Comparison (1)
`compare <other-dir>`

---

## Tier 4 — Composing actions (recipes)

Common multi-step patterns. These compose Tier 1 actions for higher-leverage workflows.

### "I just inherited this codebase"

```bash
codemap --dir . stats        # facts
codemap --dir . audit        # architectural overview + dual-risk nodes
codemap --dir . layers       # BFS depth + cross-layer violations
codemap --dir . health       # 0-100 score
```

### "Is this PR shippable"

```bash
codemap --dir . diff-impact HEAD~1   # change + transitive impact
codemap --dir . risk HEAD~1          # 0-100 risk score
codemap --dir . api-diff HEAD~1      # public surface delta
codemap --dir . changeset HEAD~1     # all of the above + dead-function check
```

### "Reverse engineer this Windows binary"

```bash
codemap lang-fingerprint app.exe              # compiler / language / runtime
codemap pe-meta app.exe                       # Rich header + TLS + entry
codemap pe-imports app.exe                    # DLL deps
codemap pe-strings app.exe                    # SQL / URLs / paths / etc.
codemap pe-cert app.exe                       # who signed it
codemap overlay-info app.exe                  # packer / installer detection
codemap bin-disasm app.exe                    # x86/x64 functions + call graph
codemap pagerank bin_func                     # rank functions by intra-binary centrality
```

### "Audit a foreign repo for refactor"

```bash
codemap --dir . audit                         # dual-risk + brokers + clusters
codemap --dir . fiedler                       # natural bisection lines
codemap --dir . dead-files                    # cleanup candidates
codemap --dir . dead-functions                # more cleanup
codemap --dir . orphan-exports                # API surface cleanup
codemap --dir . circular                      # cycle detection
codemap --dir . hotspots                      # most-coupled files
codemap --dir . churn HEAD~50                 # recently-churned high-coupling files
```

### "Find vulnerable transitive deps"

```bash
# Given a captured NVD feed (offline JSON dump)
codemap --dir . elf-info /usr/local/bin/myapp        # registers DLL nodes
codemap cve-import /path/to/nvd.json                  # registers Cve nodes
codemap cve-match                                     # adds dll → cve edges
codemap meta-path "source->elf->dll->cve"            # the trace
codemap to-cyclonedx                                  # ship as CycloneDX 1.5
```

### "Recon analysis from captured artifacts"

```bash
# User does the curls themselves; codemap parses the results.
codemap robots-parse robots.txt                       # classify + flag leaky
codemap web-sitemap-parse sitemap.xml                 # detect ID-enumeration patterns
codemap web-fingerprint vendor.bundle.js              # framework / CMS / CDN
codemap crt-parse crt-sh.json                         # subdomain harvest
codemap meta-path "endpoint->endpoint"                # what's reachable from what
```

### "What changed last week and is it scary"

```bash
codemap --dir . node-lifespan                # young hotspots + active veterans
codemap --dir . edge-churn 200               # vestigial imports + true coupling
codemap --dir . community-evolution 4        # BIRTH/DEATH/SPLIT/MERGE events
codemap --dir . churn HEAD~30                # per-file recent churn
```

---

## Picking when actions overlap

When two actions could answer the same question, the disambiguation:

| Question | Best fit | Why |
|---|---|---|
| "Most important file" | `pagerank` | Random-walk importance, default for general "what matters" |
| "What's a chokepoint" | `betweenness` | Continuous score (vs `bridges` which is binary articulation-point) |
| "Is this codebase modular" | `clusters` (Leiden) for module count; `spectral-gap` for the eigengap heuristic; `fiedler` for whether it has a bottleneck | Three different angles on "modularity" |
| "Cluster differently than Leiden" | `spectral-cluster k` | Captures bottleneck-shaped structure modularity-based methods miss |
| "Cyclic deps" | `scc` (typed components) or `circular` (file-level) | `scc` works on the heterogeneous graph; `circular` is source-file-only |
| "Entry point" | `entry-points` (multi-criteria) or `dominator-tree` (auto-detects) or `reaching` (top-1 reach) | Three different entry-detection heuristics |
| "Connects everything" | `betweenness` (top-1) or `bridges` (articulation points) | Continuous vs binary |
| "Group of files that grew together" | `community-evolution` then `audit` cluster summary | Temporal modularity |

---

## Supported languages (15 + 4 regex)

**Tree-sitter AST:** TypeScript, TSX, JavaScript, Python, Rust, Go, Java, Ruby, PHP, C, C++, CUDA, Bash/Shell, C#, Lua
**Regex fallback:** Kotlin, SQL, YAML, CMake

## EntityKinds (28)

`source` (default) `pe` `elf` `macho` `jclass` `wasm` `dll` `symbol` `bin_func` (5.13+) `endpoint` `form` `table` `field` `proto` `gql` `oapi` `docker` `tf` `model` `asm` (.NET) `type` (.NET) `compiler` (5.12+) `string` (5.12+) `overlay` (5.12+) `license` (5.14+) `cve` (5.14+) `cert` (5.15+) `apk` (5.15+) `permission` (5.15+)

## Hard rules / behaviors

- `--dir` defaults to current dir. **Always pass `--dir <small_path>`** — without it, codemap scans CWD recursively (a `--dir ~` from home can balloon to 50 GB heap).
- Repeat `--dir` for multi-repo scans. Cross-repo imports become real edges.
- **Quote arrow patterns** for `meta-path` and `subgraph-iso`: `meta-path "source->endpoint"` (bash treats `>` as redirection).
- Reverse engineering + recon-parser actions take **absolute file paths** — they don't use the scan directory.
- `--json` wraps output in `{"action", "target", "files", "result", "ok", "error"}`.
- `--tree` gives ASCII tree rendering for `taint`, `slice`, `trace-value`.
- File size limit: 256 MB for binaries, 10 MB for source files.
- Cache at `.codemap/cache.bincode` — delete or pass `--no-cache` to force fresh. RE-action mutations (PE imports → DLL nodes, URL strings → endpoints) persist across CLI runs.
- Spectral analysis caps at 5000 nodes; larger graphs return a clear error suggesting `clusters leiden` instead.
- Temporal actions need a git repo. They run on a single `git log --name-status -M` pass — no checkouts.
- Recon parsers consume **named artifacts only** — codemap never makes network requests. User does the curl / playwright / nuclei / etc. and feeds the result here. Active recon belongs in separate tools (nuclei, subfinder, gobuster).
- Custom sinks/sources via `.codemap/dataflow.json`.
