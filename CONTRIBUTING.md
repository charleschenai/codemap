# Contributing to codemap

Thanks for considering a contribution. codemap is a single-Rust-binary heterogeneous-graph code analyzer; this doc covers everything you need to land a change.

For the per-release design narrative, see [`EVOLUTION.log`](./EVOLUTION.log). For the user-facing changelog, see [`CHANGELOG.md`](./CHANGELOG.md). For runtime behavior + the action catalog, see [`README.md`](./README.md).

---

## Build + test

```bash
git clone https://github.com/charleschenai/codemap.git
cd codemap
cargo build --release
cargo test --release
```

The release build is the only one that matters for benchmarks; debug builds are 10–50× slower for the disasm + spectral paths. CI runs the full suite (~210 tests across the workspace) on every PR.

To run codemap against a real repo without installing it:

```bash
./target/release/codemap --dir ~/some-project audit
./target/release/codemap think "find load-bearing files"
```

There is also a Node bindings crate (`codemap-napi`) that re-exports the core for `charlie-code`-style integrations. Most contributors won't need it.

---

## Repo layout

```
codemap/
├── codemap-core/          ← library: the action graph + every analysis pass
│   ├── src/
│   │   ├── lib.rs         ← `scan()` + `execute()` entry points
│   │   ├── scanner.rs     ← repo walk + tree-sitter parse + auto-classify
│   │   ├── parser.rs      ← per-language AST → graph
│   │   ├── disasm.rs      ← iced-x86 + ARM/AArch64 symbol-table walk
│   │   ├── demangle.rs    ← Itanium / MSVC / Rust v0
│   │   ├── strings.rs     ← URL / SQL / GUID / etc. classifier
│   │   ├── types.rs       ← `EntityKind` enum + `Graph` + `GraphNode`
│   │   └── actions/
│   │       ├── mod.rs     ← `dispatch()` — single match arm per action
│   │       ├── analysis.rs / centrality.rs / spectral.rs / leiden.rs / …
│   │       ├── reverse/   ← PE / Mach-O / web / clarion / dbf
│   │       ├── ml.rs      ← gguf / safetensors / onnx / pyc / cuda
│   │       ├── apk.rs     ← Android APK (ZIP + manifest + permission scan)
│   │       ├── dex.rs     ← Dalvik bytecode walker (5.23+)
│   │       ├── think.rs   ← natural-language goal router (5.25+)
│   │       └── …          ← 30+ more action modules
│   └── tests/integration.rs   ← end-to-end tests (~115 currently)
├── codemap-cli/           ← thin CLI wrapper over codemap-core
├── codemap-napi/          ← N-API bindings used by charlie-code
├── examples/              ← scenario walkthroughs (audit / APK / recon / diff)
├── EVOLUTION.log          ← per-release design narrative — append-only
├── CHANGELOG.md           ← user-facing release notes (Keep a Changelog)
└── README.md              ← runtime behavior + full action catalog
```

The dispatch in `codemap-core/src/actions/mod.rs` is one giant match arm — every action has exactly one entry there. New actions wire in by adding a single `"action-name" => Ok(module::fn(graph, target)),` line.

---

## How to add a new action

1. **Decide the surface.** Does it parse a structured artifact (binary, archive, schema)? Does it run a graph algorithm? Does it call into an external tool? The category determines which existing module it joins (or whether a new one is warranted).
2. **Write the function.** Signature: `pub fn my_action(graph: &mut Graph, target: &str) -> String`. Return the human-readable text. The `&mut Graph` is non-negotiable — every action that discovers structured findings should write them to the graph (see "How to wire findings to the graph" below).
3. **Wire dispatch.** Add one match arm in `codemap-core/src/actions/mod.rs`:
   ```rust
   "my-action" => Ok(my_module::my_action(graph, target)),
   ```
4. **Add tests.** Either a unit test in the action's module (`#[cfg(test)] mod tests { … }`) for pure logic, or an integration test in `codemap-core/tests/integration.rs` for the full `scan() + execute()` flow.
5. **Update docs.** README action catalog table + SKILL.md Tier 2 entry if appropriate.
6. **Append to EVOLUTION.log.** Per-release design narrative — what shipped, why, what's deferred. The format is informal; previous entries are the template.

---

## How to wire findings to the graph

This is the single most important pattern in codemap. Every action that parses structured data should register what it finds as typed graph nodes — not just print text.

The pattern (used by every action shipped 5.16.2 → 5.25.0):

```rust
use crate::types::EntityKind;

pub fn my_action(graph: &mut Graph, target: &str) -> String {
    // 1. Parse the artifact. Accept partial / corrupt input — never panic.
    let parsed = match parse_my_format(target) {
        Ok(p) => p,
        Err(e) => return format!("Parse error: {e}"),
    };

    // 2. Register a parent node for the artifact itself.
    let parent_id = format!("myformat:{target}");
    graph.ensure_typed_node(&parent_id, EntityKind::MyFormat, &[
        ("path", target),
    ]);

    // 3. For each discovered child item, register a typed node + edge.
    //    Cap at a sane upper bound (5000 is the convention) so pathological
    //    inputs don't blow up the graph.
    for (i, item) in parsed.items.iter().enumerate().take(5000) {
        let item_id = format!("myitem:{target}::{i}");
        graph.ensure_typed_node(&item_id, EntityKind::MyItem, &[
            ("name", item.name.as_str()),
            ("attr", item.attr.as_str()),
        ]);
        graph.add_edge(&parent_id, &item_id);
    }

    // 4. Return human-readable text alongside.
    format_report(&parsed)
}
```

Why this matters: every graph algorithm — `pagerank`, `audit`, `meta-path`, `fiedler` — works uniformly across every node kind. Once your data is in the graph, it participates in cross-domain queries (`meta-path "source->endpoint"`, `pagerank --type my_item`, etc.) without you writing any extra code.

---

## How to add a new EntityKind

Five places need to be touched together (CI will catch any you miss via the `match` exhaustiveness check):

1. **`codemap-core/src/types.rs`** — add the variant to the `EntityKind` enum with a doc comment that names the action that creates it, the edges it participates in, and the killer queries it unlocks.
2. **`as_str()` impl** — map enum → short string (used in node IDs + filtering).
3. **`from_str()` impl** — accept aliases (`"sec" | "secret" | "credential"`).
4. **`codemap-core/src/actions/graph_theory.rs`** — add a DOT shape and a Mermaid kind alias so the new EntityKind renders distinctly.
5. **`codemap-core/src/actions/exports_format.rs`** — add an RGB color tuple for GEXF export.

Reference: see commit `feat: 5.17.0` (added `Secret`), `feat: 5.19.0` (added `Dependency`), `feat: 5.20.0` (added `MlTensor` + `MlOperator`), `feat: 5.21.0` (added `BinarySection`).

---

## Testing conventions

- **Unit tests** live in the module they test: `#[cfg(test)] mod tests { use super::*; … }` at the bottom of the file. Use these for pure logic — parser fragments, classifier predicates, algorithm internals.
- **Integration tests** live in `codemap-core/tests/integration.rs`. Use these for the full `scan() + execute()` flow — when you need a populated `Graph` to assert against. These tests have access to `codemap_core::{scan, execute, ScanOptions}` and `codemap_core::types::{Graph, GraphNode, EntityKind}`.
- **Parser-rejects-bad-input tests are mandatory** for any action that parses a binary format. Pass garbage bytes, assert `Err`. Pattern: every parser this session has at least one rejection test alongside its happy-path test.
- **Cap-enforcement tests are mandatory** for any action that registers nodes in a loop. Cf. `lsp_symbol_walker_respects_cap` — feed payload of `cap+100`, assert exactly `cap` nodes register.
- **No mocks for the graph.** Tests build a real `Graph` (often via `scan()` on a synthetic tmpdir) and inspect it directly. The `Graph` is cheap to construct and avoids the mock/prod divergence problem.

---

## Hard rules

These are inviolable. If a PR breaks one of them, it won't merge.

1. **Codemap never makes network requests.** It is a pure-static analyzer. Active recon belongs in dedicated tools (nuclei, subfinder, gobuster, Burp). The `think` action enforces this for users by rejecting live URLs in goal strings; the codebase enforces it for contributors by code review. If you need to support a new data source, write a parser that consumes a captured artifact (file path the user names explicitly).
2. **Pure-Rust dependencies only.** No system libraries (no libcapstone, no libzip, no openssl). When a new format requires a parser, prefer rolling it from spec (DEX, GGUF, ONNX, Mach-O were all hand-rolled this way) or pulling a pure-Rust crate (`iced-x86` for x86 disasm, `miniz_oxide` for deflate). The dep list at the top of `Cargo.toml` is small and audited; new deps need justification in the EVOLUTION.log entry.
3. **Always pass `--dir <small_path>`.** This is a user-facing rule (also documented in the README), but contributors hit it during local development. Without `--dir`, codemap walks CWD recursively — from `~` that's hundreds of thousands of files and ~50 GB heap before OOM-kill. Use `--dir /tmp/test-repo` or similar during dev.
4. **Default scan invariant.** Adding a new action MUST NOT change what the default `codemap scan` walks or what nodes it auto-classifies. New formats can join `actions/scanner.rs::auto_classify_typed_files` only if they carry well-known file extensions and the registration is cheap (no parsing during scan, just `ensure_typed_node` with `auto_classified=true`).
5. **Caps everywhere.** Any loop that registers graph nodes from external input has a cap. The convention is 5000 (matches StringLiteral / LSP-symbol / DEX-method caps). Document the cap in the action's text output when it kicks in (`[graph] X nodes registered (cap 5000).`).

---

## Commit + version conventions

- **Commit messages.** Format: `feat: X.Y.Z — <short headline>` for shipping releases, `fix: <topic>` for bug fixes, `docs: <topic>` for doc-only changes, `chore: <topic>` for housekeeping. Body explains the *why* + the design tradeoffs, not just the *what* — the diff already shows the what.
- **Versioning.** PATCH (`5.25.x`) = bug fixes, doc-only changes, polish. MINOR (`5.x.0`) = new actions, new EntityKinds, new capability. MAJOR (`6.0.0`) = breaking change to the graph schema or the dispatch surface (we're not there yet).
- **Workspace version.** Bump both `codemap-core/Cargo.toml` and `codemap-cli/Cargo.toml` together. The README version line + descriptions should also reflect the bump.
- **Tag every release.** `git tag vX.Y.Z && git push origin vX.Y.Z`. GitHub auto-creates a release from the tag (we're not currently auto-uploading binaries — TODO).
- **EVOLUTION.log every release.** Append a per-release entry with the design narrative. Format is loose but should cover: source (what motivated the release), implementation (key files / new types), tests, action count + EntityKind delta, what's deferred. The entry is the future contributor's primary reference for "why does this work this way?"
- **CHANGELOG.md every release.** Standard Keep-a-Changelog format. Shorter than EVOLUTION.log; user-facing.

---

## Filing issues

Keep the title imperative ("disasm fails on stripped ELF" not "disasm broken?"). Body should answer:

1. What command did you run? (Include the full `codemap …` invocation.)
2. What did you expect?
3. What happened? (Paste the actual output, even if long. Use a `<details>` block.)
4. What's the input file? (If you can share it, attach it. If not, describe its shape — file size, format, source.)

Bug reports without a reproducer get triaged into "needs repro" and may sit. Reports with a one-line `codemap …` + minimal target file get fixed within the week.

---

## License

MIT. By contributing, you agree your contributions will be licensed under the same.
