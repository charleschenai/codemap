# Rust Language Support — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make codemap fully analyze Rust codebases — resolve `mod`/`use` imports to file paths, extract method calls correctly, and harden error handling.

**Architecture:** Six targeted fixes in four files. The Rust tree-sitter grammar already loads and extracts AST nodes correctly (tree-sitter 0.25 + tree-sitter-rust 0.24). The gap is: (1) resolver doesn't map Rust import paths to files, (2) `mod` declarations aren't captured as imports, (3) method call extraction uses JS field names instead of Rust ones, (4) minor hardening issues.

**Tech Stack:** Rust, tree-sitter, tree-sitter-rust 0.24

**Build & Test:** `cd ~/Desktop/codemap && export PATH="$HOME/.cargo/bin:$PATH" && cargo build --release` then test with `~/bin/codemap` (symlink to `target/release/codemap`).

**Testing codebase:** Use codemap's own source: `--dir ~/Desktop/codemap/codemap-core/src --dir ~/Desktop/codemap/codemap-cli/src`

---

### Task 1: Add `target/` to SKIP_DIRS and bump cache version

**Files:**
- Modify: `codemap-core/src/scanner.rs:20` (SKIP_DIRS)
- Modify: `codemap-core/src/scanner.rs:16` (CACHE_VERSION)

- [ ] **Step 1: Add "target" to SKIP_DIRS**

In `scanner.rs`, change:

```rust
const SKIP_DIRS: &[&str] = &["node_modules", ".git", "dist", "build", ".codemap"];
```

To:

```rust
const SKIP_DIRS: &[&str] = &["node_modules", ".git", "dist", "build", ".codemap", "target"];
```

- [ ] **Step 2: Bump CACHE_VERSION to invalidate stale caches**

In `scanner.rs`, change:

```rust
const CACHE_VERSION: u32 = 4;
```

To:

```rust
const CACHE_VERSION: u32 = 5;
```

This ensures old caches (created when Rust parsing was broken due to tree-sitter 0.24 ABI mismatch) get discarded automatically.

- [ ] **Step 3: Build and verify**

```bash
cd ~/Desktop/codemap && export PATH="$HOME/.cargo/bin:$PATH" && cargo build --release
```

Expected: compiles with no errors.

- [ ] **Step 4: Test cache invalidation**

```bash
# Old caches should be ignored now
~/bin/codemap --dir ~/Desktop/codemap/codemap-core/src stats
```

Expected: Should NOT say "Cache: X/Y files unchanged" on first run (old v4 caches are rejected). Second run should show cache hits.

- [ ] **Step 5: Commit**

```bash
cd ~/Desktop/codemap
git add codemap-core/src/scanner.rs
git commit -m "fix: add target/ to SKIP_DIRS and bump cache version to invalidate stale Rust caches"
```

---

### Task 2: Fix silent `set_language` error in parser

**Files:**
- Modify: `codemap-core/src/parser.rs:91`

- [ ] **Step 1: Add warning on grammar load failure**

In `parser.rs`, the `parse_with_treesitter` function at line 88-96, change:

```rust
        let parser = cache.entry(grammar).or_insert_with(|| {
            let mut p = Parser::new();
            if let Some(lang) = grammar_to_language(grammar) {
                let _ = p.set_language(&lang);
            }
            p
        });
```

To:

```rust
        let parser = cache.entry(grammar).or_insert_with(|| {
            let mut p = Parser::new();
            if let Some(lang) = grammar_to_language(grammar) {
                if let Err(e) = p.set_language(&lang) {
                    eprintln!("Warning: failed to load {grammar} grammar: {e}");
                }
            }
            p
        });
```

- [ ] **Step 2: Build and verify**

```bash
cd ~/Desktop/codemap && export PATH="$HOME/.cargo/bin:$PATH" && cargo build --release
```

Expected: compiles with no errors.

- [ ] **Step 3: Commit**

```bash
cd ~/Desktop/codemap
git add codemap-core/src/parser.rs
git commit -m "fix: warn on tree-sitter grammar load failure instead of silently ignoring"
```

---

### Task 3: Extract `mod` declarations as imports

**Files:**
- Modify: `codemap-core/src/parser.rs:135` (import_types)
- Modify: `codemap-core/src/parser.rs:252-264` (Rust import extraction block)

`mod foo;` in Rust creates a file dependency on `foo.rs` or `foo/mod.rs`. Currently, only `use_declaration` is captured. We need to also capture `mod_item` nodes and extract the module name as a relative file import.

- [ ] **Step 1: Add `mod_item` to import_types for Rust**

In `parser.rs`, change line 135:

```rust
        "rust" => &["use_declaration"],
```

To:

```rust
        "rust" => &["use_declaration", "mod_item"],
```

- [ ] **Step 2: Handle `mod_item` in import extraction**

In `parser.rs`, in the `} else if grammar == "rust" {` block of `extract_imports_from_ast` (starting around line 252), change:

```rust
    } else if grammar == "rust" {
        for node in collect(root, itypes) {
            let path_node = node.child_by_field_name("argument").or_else(|| node.child(1));
            if let Some(pn) = path_node {
                let t = text(pn, src);
                if t != "use" && !t.is_empty() {
                    // Take first 2 :: segments
                    let trimmed = t.trim_end_matches(';');
                    let segments: Vec<&str> = trimmed.split("::").take(2).collect();
                    imports.push(segments.join("::"));
                }
            }
        }
```

To:

```rust
    } else if grammar == "rust" {
        for node in collect(root, itypes) {
            if node.kind() == "mod_item" {
                // mod foo; → import "foo" (resolved to foo.rs or foo/mod.rs)
                if let Some(name) = node.child_by_field_name("name") {
                    let mod_name = text(name, src);
                    if !mod_name.is_empty() {
                        // Check if this is a `mod foo;` (external) vs `mod foo { ... }` (inline)
                        // Inline mods have a body child; external ones don't
                        let has_body = node.child_by_field_name("body").is_some();
                        if !has_body {
                            imports.push(format!("./{mod_name}"));
                        }
                    }
                }
            } else {
                // use_declaration
                let path_node = node.child_by_field_name("argument").or_else(|| node.child(1));
                if let Some(pn) = path_node {
                    let t = text(pn, src);
                    if t != "use" && !t.is_empty() {
                        // Take first 2 :: segments
                        let trimmed = t.trim_end_matches(';');
                        let segments: Vec<&str> = trimmed.split("::").take(2).collect();
                        imports.push(segments.join("::"));
                    }
                }
            }
        }
```

The `./` prefix on mod imports will let the resolver distinguish them from `use` imports and resolve them as relative file references. A `mod foo;` in `lib.rs` means either `foo.rs` or `foo/mod.rs` exists as a sibling.

- [ ] **Step 3: Build and verify**

```bash
cd ~/Desktop/codemap && export PATH="$HOME/.cargo/bin:$PATH" && cargo build --release
```

Expected: compiles with no errors.

- [ ] **Step 4: Test mod extraction**

```bash
~/bin/codemap --dir ~/Desktop/codemap/codemap-core/src --no-cache trace lib.rs
```

Expected: lib.rs should now show imports for `./types`, `./parser`, `./resolve`, `./scanner`, `./cpg`, `./actions` in addition to existing `use` imports.

- [ ] **Step 5: Commit**

```bash
cd ~/Desktop/codemap
git add codemap-core/src/parser.rs
git commit -m "feat: extract Rust mod declarations as file-level imports"
```

---

### Task 4: Add Rust module resolution to resolver

**Files:**
- Modify: `codemap-core/src/resolve.rs` (add Rust section before bare specifier fallback)

The resolver currently handles: JS relative imports, tsconfig aliases, C/C++ `#include`. Rust `crate::X` imports and `./X` mod imports need file path resolution.

- [ ] **Step 1: Add Rust extension list constant**

In `resolve.rs`, after the `C_CPP_EXTS` constant (line 73), add:

```rust
const RUST_EXTS: &[&str] = &[".rs", "/mod.rs"];
```

- [ ] **Step 2: Add Rust resolution section**

In `resolve.rs`, in the `resolve_and_add` function, add a new section **before** the "4. Bare specifier" section (before line 196 `// ── 4. Bare specifier`). The section handles both `crate::*` use paths and `./module` mod declarations:

```rust
    // ── Rust module resolution ─────────────────────────────────────
    if from_ext == ".rs" {
        // ./module imports from mod declarations
        if specifier.starts_with("./") {
            let mod_name = &specifier[2..];
            let from_dir = Path::new(from_file).parent().unwrap_or(Path::new(""));

            for ext in RUST_EXTS {
                let candidate = from_dir.join(format!("{mod_name}{ext}"));
                if candidate.exists() {
                    if let Ok(rel) = candidate.strip_prefix(scan_dir) {
                        node_imports.push(normalize_path(&rel.to_string_lossy()));
                        return;
                    }
                }
            }
            return;
        }

        // crate:: imports → resolve relative to crate root (scan_dir)
        if specifier.starts_with("crate::") {
            let rest = &specifier[7..]; // strip "crate::"
            // Clean up tree-sitter artifacts like "{Foo, Bar}"
            let module = rest.split("::{").next().unwrap_or(rest);
            let module = module.split("::").next().unwrap_or(module);

            for ext in RUST_EXTS {
                let candidate = scan_dir.join(format!("{module}{ext}"));
                if candidate.exists() {
                    if let Ok(rel) = candidate.strip_prefix(scan_dir) {
                        node_imports.push(normalize_path(&rel.to_string_lossy()));
                        return;
                    }
                }
            }
            return;
        }

        // self:: and super:: — resolve relative to current file
        if specifier.starts_with("self::") || specifier.starts_with("super::") {
            // These reference the current module or parent, not separate files
            return;
        }

        // External crates (std::, serde::, rayon::, etc.) — skip, don't store as imports
        if !specifier.contains('/') {
            return;
        }
    }
```

**Important:** This section must come BEFORE the bare specifier fallback. The final `return` for external crates prevents them from being stored as false import edges.

- [ ] **Step 3: Build and verify**

```bash
cd ~/Desktop/codemap && export PATH="$HOME/.cargo/bin:$PATH" && cargo build --release
```

Expected: compiles with no errors.

- [ ] **Step 4: Test module resolution**

```bash
~/bin/codemap --dir ~/Desktop/codemap/codemap-core/src --no-cache trace lib.rs
~/bin/codemap --dir ~/Desktop/codemap/codemap-core/src --no-cache trace scanner.rs
```

Expected for lib.rs: `./types` → `types.rs`, `./parser` → `parser.rs`, `./actions` → `actions/mod.rs`, etc.
Expected for scanner.rs: `crate::parser` → `parser.rs`, `crate::types` → `types.rs`, `crate::resolve` → `resolve.rs`.

- [ ] **Step 5: Test graph connectivity**

```bash
~/bin/codemap --dir ~/Desktop/codemap/codemap-core/src --no-cache islands
~/bin/codemap --dir ~/Desktop/codemap/codemap-core/src --no-cache pagerank
~/bin/codemap --dir ~/Desktop/codemap/codemap-core/src --no-cache layers
```

Expected: Files should be connected (not 13 isolated islands). PageRank should show differentiated scores. Layers should show >1 level.

- [ ] **Step 6: Commit**

```bash
cd ~/Desktop/codemap
git add codemap-core/src/resolve.rs
git commit -m "feat: add Rust module resolution for crate:: use paths and mod declarations"
```

---

### Task 5: Fix Rust method call extraction in call graph

**Files:**
- Modify: `codemap-core/src/parser.rs:555-559`

Rust's tree-sitter uses `field_expression` with a child named `field` for method calls (e.g., `obj.method()`). The current code checks for `property` (JS convention), which always returns None, causing the full expression `obj.method` to be stored as the callee instead of just `method`.

- [ ] **Step 1: Fix field name lookup for field_expression**

In `parser.rs`, in `extract_functions_from_ast`, change lines 555-559:

```rust
                let callee = if f.kind() == "member_expression" || f.kind() == "field_expression" {
                    f.child_by_field_name("property")
                        .map(|p| text(p, src).to_string())
                        .unwrap_or_else(|| text(f, src).to_string())
```

To:

```rust
                let callee = if f.kind() == "member_expression" || f.kind() == "field_expression" {
                    f.child_by_field_name("property")
                        .or_else(|| f.child_by_field_name("field"))
                        .map(|p| text(p, src).to_string())
                        .unwrap_or_else(|| text(f, src).to_string())
```

This tries `property` first (JS/TS), then falls back to `field` (Rust). Works for all languages.

- [ ] **Step 2: Build and verify**

```bash
cd ~/Desktop/codemap && export PATH="$HOME/.cargo/bin:$PATH" && cargo build --release
```

Expected: compiles with no errors.

- [ ] **Step 3: Test call graph**

```bash
~/bin/codemap --dir ~/Desktop/codemap/codemap-core/src --no-cache call-graph parse_file
~/bin/codemap --dir ~/Desktop/codemap/codemap-core/src --no-cache call-graph scan_directories
```

Expected: Should show cross-function calls. `parse_file` calls `ext_to_grammar`, `parse_with_treesitter`, `extract_imports_from_ast`, etc. `scan_directories` calls `scan_single_dir`, etc.

- [ ] **Step 4: Commit**

```bash
cd ~/Desktop/codemap
git add codemap-core/src/parser.rs
git commit -m "fix: use correct field name for Rust method call extraction in call graphs"
```

---

### Task 6: End-to-end validation — codemap on codemap

Run all major actions on codemap's own source to verify everything works together.

- [ ] **Step 1: Delete all caches and rebuild**

```bash
rm -rf ~/Desktop/codemap/codemap-core/src/.codemap ~/Desktop/codemap/codemap-cli/src/.codemap
cd ~/Desktop/codemap && export PATH="$HOME/.cargo/bin:$PATH" && cargo build --release
```

- [ ] **Step 2: Run comprehensive test suite**

```bash
CM="~/bin/codemap --dir ~/Desktop/codemap/codemap-core/src --dir ~/Desktop/codemap/codemap-cli/src"

# Graph basics
eval "$CM stats"          # Should show >0 import edges, >0 exports
eval "$CM pagerank"       # Should show differentiated scores
eval "$CM islands"        # Should have fewer than 14 islands
eval "$CM layers"         # Should show >1 layer
eval "$CM clusters"       # Should find clusters
eval "$CM hotspots"       # Should show non-zero imported_by counts
eval "$CM circular"       # Should run without error

# File analysis
eval "$CM trace lib.rs"         # Should show mod imports resolving to files
eval "$CM trace scanner.rs"     # Should show crate:: imports resolving to files
eval "$CM exports parser.rs"    # Should show ParseResult, parse_file

# Function-level
eval "$CM call-graph parse_file"       # Should show calls to helper functions
eval "$CM call-graph scan_directories" # Should show calls
eval "$CM dead-functions"              # Should find dead functions
eval "$CM complexity parser.rs"        # Should rank functions by complexity

# Data flow
eval "$CM data-flow parser.rs"   # Should show parameter flow
```

Expected: All commands produce meaningful output. No "0 imports" or "all files independent."

- [ ] **Step 3: Copy updated binary to bin**

The symlink already points to `target/release/codemap`, so this should be automatic. Verify:

```bash
~/bin/codemap --dir ~/Desktop/codemap/codemap-core/src stats | head -5
```

- [ ] **Step 4: Commit all remaining changes (if any)**

```bash
cd ~/Desktop/codemap && git status
# If there are uncommitted changes:
git add -A && git commit -m "feat: complete Rust language support in codemap"
```

- [ ] **Step 5: Push to GitHub**

```bash
cd ~/Desktop/codemap && git push origin main
```
