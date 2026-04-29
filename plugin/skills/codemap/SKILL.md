---
name: codemap
description: Analyze codebase structure with 88 actions — AST-powered call graphs, binary reverse engineering, schema parsing, security scanning, web scraper blueprinting, LSP integration, and more. TRIGGER when asked to understand code structure, audit dependencies, reverse engineer binaries, map APIs, scan for secrets, or prepare for refactoring.
user-invocable: true
allowed-tools:
  - Bash(codemap *)
  - Bash(~/bin/codemap *)
  - Bash(~/Desktop/codemap/target/release/codemap *)
  - Read
  - Grep
---

# /codemap — Codebase Analysis & Reverse Engineering (88 actions)

Single Rust binary. 13 languages via tree-sitter AST. Rayon parallel. Bincode mtime cache. No external services.

## Quick Start

```bash
codemap [--dir <path>] <action> [target]
codemap --dir ~/project stats              # overview
codemap --dir ~/project health             # 0-100 score
codemap --dir . pe-imports /path/to.exe    # reverse engineer a binary
```

Options: `--json` (JSON envelope with ok/error), `--tree` (ASCII tree for data-flow), `--no-cache`, `--watch [secs]`, `-q` (quiet), `--dir` (repeatable for multi-repo), `--include-path` (C/C++ includes).

---

## When to Use Each Action

### "I need to understand this codebase"
| Trigger | Action | Example |
|---------|--------|---------|
| First look at a project | `stats` | `codemap --dir src stats` |
| Quick dashboard | `summary` | `codemap --dir src summary` |
| Health check / code quality | `health` | `codemap --dir src health` → 0-100 score |
| What does this file do? | `trace <file>` | `codemap --dir src trace src/main.rs` |
| What are the main files? | `pagerank` | `codemap --dir src pagerank` → top 30 by importance |
| What are the layers? | `layers` | `codemap --dir src layers` → entry/service/leaf |
| Find module boundaries | `clusters` | `codemap --dir src clusters` |
| Build an LLM context map | `context [budget]` | `codemap --dir src context 8k` → fits in a prompt |
| Directory overview with functions | `structure` | `codemap --dir src structure` |

### "What happens if I change X?"
| Trigger | Action | Example |
|---------|--------|---------|
| What breaks if I touch this file? | `blast-radius <file>` | `codemap --dir src blast-radius src/parser.rs` |
| Is this PR risky? | `risk <ref>` | `codemap --dir src risk HEAD~1` → 0-100 score |
| Full diff impact analysis | `diff-impact <ref>` | `codemap --dir src diff-impact main` |
| What changed + blast radius | `diff <ref>` | `codemap --dir src diff HEAD~3` |
| Preview a rename | `rename <old> <new>` | `codemap --dir src rename oldName newName` |
| How connected is a file? | `import-cost <file>` | `codemap --dir src import-cost src/big.rs` |

### "How does A connect to B?"
| Trigger | Action | Example |
|---------|--------|---------|
| Shortest path between files | `why <A> <B>` | `codemap --dir src why parser.rs lib.rs` |
| ALL paths between files | `paths <A> <B>` | `codemap --dir src paths a.rs b.rs` |
| Everything connected to X | `subgraph <pattern>` | `codemap --dir src subgraph auth` |
| Files with similar imports | `similar <file>` | `codemap --dir src similar src/utils.rs` |
| Who calls this function? | `callers <name>` | `codemap --dir src callers dispatch` |
| Function call graph | `call-graph [file]` | `codemap --dir src call-graph src/main.rs` |
| Function details | `fn-info <file>` | `codemap --dir src fn-info src/parser.rs` |

### "I need to clean up this codebase"
| Trigger | Action | Example |
|---------|--------|---------|
| Find unused files | `dead-files` | `codemap --dir src dead-files` |
| Find unused functions | `dead-functions` | `codemap --dir src dead-functions` |
| Find unused exports | `orphan-exports` | `codemap --dir src orphan-exports` |
| Find unused dependencies | `dead-deps` | `codemap --dir src dead-deps` |
| Find circular imports | `circular` | `codemap --dir src circular` |
| Find duplicate code | `clones` | `codemap --dir src clones` |
| Find complex functions | `complexity [file]` | `codemap --dir src complexity` |
| Find high-risk files | `churn <ref>` | `codemap --dir src churn HEAD~50` |
| Find hidden coupling | `git-coupling` | `codemap --dir src git-coupling 500` |
| Most coupled files | `hotspots` | `codemap --dir src hotspots` |
| Largest files | `size` | `codemap --dir src size` |
| Critical single-point-of-failure files | `bridges` | `codemap --dir src bridges` |
| Hub vs authority ranking | `hubs` | `codemap --dir src hubs` |

### "I need to trace data flow / find security issues"
| Trigger | Action | Example |
|---------|--------|---------|
| Trace user input to database | `taint <source> <sink>` | `codemap --dir src taint req.body db.query` |
| What feeds this line? | `slice <file>:<line>` | `codemap --dir src slice src/handler.rs:42` |
| Where does this value go? | `trace-value <f>:<l>:<n>` | `codemap --dir src trace-value src/a.rs:10:user` |
| Find all sink points | `sinks [file]` | `codemap --dir src sinks` |
| Data flow for a function | `data-flow <file> [fn]` | `codemap --dir src data-flow src/api.rs handle_upload` |
| Scan for hardcoded secrets | `secret-scan` | `codemap --dir src secret-scan` |
| Map the public API surface | `api-surface` | `codemap --dir src api-surface` |
| Files phoning home (URLs) | `phone-home` | `codemap --dir src phone-home` |

### "I need to reverse engineer a compiled binary"
| Trigger | Action | Example |
|---------|--------|---------|
| **Windows PE/DLL** | | |
| What DLLs and APIs does it call? | `pe-imports <file>` | `codemap --dir . pe-imports app.exe` |
| Extract SQL/strings from binary | `pe-strings <file>` | `codemap --dir . pe-strings app.exe` |
| Smart SQL mining + table map | `sql-extract <file\|dir>` | `codemap --dir . sql-extract ./binaries/` |
| Version info, manifests, UI strings | `pe-resources <file>` | `codemap --dir . pe-resources app.exe` |
| DLL export table | `pe-exports <file>` | `codemap --dir . pe-exports lib.dll` |
| PDB paths, build date, compiler | `pe-debug <file>` | `codemap --dir . pe-debug app.exe` |
| Section entropy (packed?) | `pe-sections <file>` | `codemap --dir . pe-sections app.exe` |
| .NET types, methods, assemblies | `dotnet-meta <file>` | `codemap --dir . dotnet-meta app.dll` |
| Compare two binary versions | `binary-diff <f1> <f2>` | `codemap --dir . binary-diff old.exe new.exe` |
| **Linux ELF** | | |
| ELF sections, symbols, deps | `elf-info <file>` | `codemap --dir . elf-info /usr/bin/app` |
| **macOS Mach-O** | | |
| Mach-O load commands, dylibs | `macho-info <file>` | `codemap --dir . macho-info app` |
| **Java** | | |
| Class file / JAR analysis | `java-class <file>` | `codemap --dir . java-class app.jar` |
| **WebAssembly** | | |
| WASM imports, exports, sections | `wasm-info <file>` | `codemap --dir . wasm-info module.wasm` |

### "I need to parse a legacy database schema"
| Trigger | Action | Example |
|---------|--------|---------|
| Clarion .CLW DDL file | `clarion-schema <file>` | `codemap --dir . clarion-schema sql_var.clw` |
| dBASE/FoxPro .DBF file | `dbf-schema <file>` | `codemap --dir . dbf-schema data.dbf` |

### "I need to map a web application"
| Trigger | Action | Example |
|---------|--------|---------|
| Map API from HAR capture | `web-api <har>` | `codemap --dir . web-api traffic.har` |
| Analyze saved HTML page | `web-dom <html>` | `codemap --dir . web-dom page.html` |
| Build sitemap from HTML files | `web-sitemap <dir>` | `codemap --dir . web-sitemap ./saved-pages/` |
| Full scraper blueprint | `web-blueprint <har> [html]` | `codemap --dir . web-blueprint traffic.har ./pages/` |
| Find APIs in JS bundles | `js-api-extract <file\|dir>` | `codemap --dir . js-api-extract dist/app.js` |

### "I need to understand infrastructure / API specs"
| Trigger | Action | Example |
|---------|--------|---------|
| Protobuf service definitions | `proto-schema <file>` | `codemap --dir . proto-schema api.proto` |
| OpenAPI/Swagger spec | `openapi-schema <file>` | `codemap --dir . openapi-schema openapi.json` |
| GraphQL schema | `graphql-schema <file>` | `codemap --dir . graphql-schema schema.graphql` |
| Docker Compose services | `docker-map <file>` | `codemap --dir . docker-map docker-compose.yml` |
| Terraform resources | `terraform-map <file>` | `codemap --dir . terraform-map main.tf` |

### "I need to check dependencies"
| Trigger | Action | Example |
|---------|--------|---------|
| Show dependency tree | `dep-tree [manifest]` | `codemap --dir src dep-tree` |
| Find unused dependencies | `dead-deps` | `codemap --dir src dead-deps` |
| Files importing a package | `coupling <pattern>` | `codemap --dir src coupling lodash` |

### "I need to use LSP for deeper analysis"
| Trigger | Action | Example |
|---------|--------|---------|
| Extract symbols from file | `lsp-symbols <server> <file>` | `codemap --dir . lsp-symbols rust-analyzer src/main.rs` |
| Find all references | `lsp-references <server> <f:l:c>` | `codemap --dir . lsp-references rust-analyzer src/main.rs:42:10` |
| Call hierarchy | `lsp-calls <server> <f:l:c>` | `codemap --dir . lsp-calls rust-analyzer src/main.rs:42:10` |
| Get diagnostics | `lsp-diagnostics <server> <file>` | `codemap --dir . lsp-diagnostics pylsp src/` |
| Get type info | `lsp-types <server> <file>` | `codemap --dir . lsp-types rust-analyzer src/main.rs` |

### "I need a diagram"
| Trigger | Action | Example |
|---------|--------|---------|
| Graphviz DOT | `dot [target]` | `codemap --dir src dot parser > graph.dot` |
| Mermaid (GitHub-native) | `mermaid [target]` | `codemap --dir src mermaid auth` |

### "I need to compare"
| Trigger | Action | Example |
|---------|--------|---------|
| Compare two repos | `compare <dir>` | `codemap --dir ./v1 compare ./v2` |
| Functions changed since ref | `diff-functions <ref>` | `codemap --dir src diff-functions main` |
| Exports changed since ref | `api-diff <ref>` | `codemap --dir src api-diff HEAD~5` |
| Compare two binaries | `binary-diff <f1> <f2>` | `codemap --dir . binary-diff old.exe new.exe` |
| Find decorators/attributes | `decorators <pattern>` | `codemap --dir src decorators test` |
| Detect entry points | `entry-points` | `codemap --dir src entry-points` |
| Disconnected components | `islands` | `codemap --dir src islands` |

---

## Supported Languages (13)

TypeScript, TSX, JavaScript, Python, Rust, Go, Java, Ruby, PHP, C, C++, CUDA, **Bash/Shell**

## Key Behaviors

- `--dir` defaults to current directory. Repeat for multi-repo scans.
- Target arguments are joined with spaces: `codemap why a.rs b.rs` works.
- `->` separator is stripped: `codemap why a.rs -> b.rs` works.
- Reverse engineering actions (`pe-*`, `elf-*`, `macho-*`, etc.) take absolute file paths — they don't use the scan directory.
- `--json` wraps output in `{"action", "target", "files", "result", "ok", "error"}`.
- `--tree` gives ASCII tree rendering for `taint`, `slice`, `trace-value`.
- File size limit: 256MB for binaries, 10MB for source files.
- Cache at `.codemap/cache.bincode` — delete or `--no-cache` to force fresh scan.
- Custom sinks/sources via `.codemap/dataflow.json`.
