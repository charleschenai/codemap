use std::fs;
use std::path::PathBuf;
use codemap_core::{scan, execute, ScanOptions};

fn scan_self() -> codemap_core::types::Graph {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    scan(ScanOptions {
        dirs: vec![dir],
        include_paths: vec![],
        no_cache: true,
        quiet: true,
    }).expect("scan should succeed")
}

#[test]
fn test_stats() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "stats", "", false).unwrap();
    assert!(result.contains("Codemap Stats"));
    assert!(result.contains("Files:"));
    assert!(result.contains("Lines:"));
    assert!(result.contains(".rs"));
}

#[test]
fn test_hotspots() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "hotspots", "", false).unwrap();
    assert!(result.contains("Hotspots"));
    assert!(result.contains("coupling"));
}

#[test]
fn test_dead_files() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "dead-files", "", false).unwrap();
    // Should return something (may have dead files or not)
    assert!(!result.is_empty());
}

#[test]
fn test_circular() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "circular", "", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_size() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "size", "", false).unwrap();
    assert!(result.contains("lines"));
}

#[test]
fn test_layers() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "layers", "", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_pagerank() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "pagerank", "", false).unwrap();
    assert!(result.contains("PageRank"));
}

#[test]
fn test_hubs() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "hubs", "", false).unwrap();
    assert!(result.contains("Hubs"));
}

#[test]
fn test_bridges() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "bridges", "", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_clusters() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "clusters", "", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_islands() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "islands", "", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_dead_functions() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "dead-functions", "", false).unwrap();
    assert!(result.contains("exported functions"));
}

#[test]
fn test_complexity() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "complexity", ".", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_dot() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "dot", "", false).unwrap();
    assert!(result.contains("digraph"));
}

#[test]
fn test_exports() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "exports", ".", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_unknown_action() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "nonexistent", "", false);
    assert!(result.is_err());
}

#[test]
fn test_trace() {
    let mut graph = scan_self();
    // Trace a file that exists
    let result = execute(&mut graph, "trace", "lib.rs", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_phone_home() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "phone-home", "", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_coupling() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "coupling", ".", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_data_flow() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "data-flow", ".", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_sinks() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "sinks", ".", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_health() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "health", "", false).unwrap();
    assert!(result.contains("Project Health:"));
    assert!(result.contains("/100"));
}

#[test]
fn test_summary() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "summary", "", false).unwrap();
    assert!(result.contains("files,"));
    assert!(result.contains("functions"));
}

#[test]
fn test_mermaid() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "mermaid", "", false).unwrap();
    assert!(result.contains("graph LR"));
    assert!(result.contains("-->"));
}

#[test]
fn test_clones() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "clones", "", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_context() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "context", "4k", false).unwrap();
    assert!(result.contains("codemap context:"));
    assert!(result.contains("tokens"));
}

#[test]
fn test_entry_points() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "entry-points", "", false).unwrap();
    // src/ has no main or test files, so "No entry points" is valid
    assert!(!result.is_empty());
}

#[test]
fn test_structure() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "structure", ".", false).unwrap();
    assert!(result.contains("Structure"));
    assert!(result.contains("lines"));
}

#[test]
fn test_decorators() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "decorators", "test", false).unwrap();
    // src/ may not have decorators, but result should not error
    assert!(!result.is_empty());
}

#[test]
fn test_rename() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "rename", "dispatch run_action", false).unwrap();
    assert!(result.contains("Rename Preview"));
}

#[test]
fn test_risk() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "risk", "HEAD~1", false).unwrap();
    // May return "No files changed" if HEAD~1 doesn't exist, which is OK
    assert!(!result.is_empty());
}

// ── Smoke tests for previously untested actions ──────────────────────

fn src_dir() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .to_string_lossy()
        .to_string()
}

#[test]
fn test_compare_self() {
    let mut graph = scan_self();
    let dir = src_dir();
    let result = execute(&mut graph, "compare", &dir, false).unwrap();
    assert!(!result.is_empty());
    // Comparing against itself should show no differences or a structural match
    assert!(result.contains("Compare") || result.contains("compare") || result.contains("identical") || result.contains("diff"));
}

#[test]
fn test_why() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "why", "lib.rs mod.rs", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_paths() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "paths", "lib.rs mod.rs", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_subgraph() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "subgraph", "lib.rs", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_similar() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "similar", "lib.rs", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_call_graph() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "call-graph", "lib.rs", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_fn_info() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "fn-info", "lib.rs", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_import_cost() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "import-cost", "lib.rs", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_blast_radius() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "blast-radius", "lib.rs", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_callers_dispatch() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "callers", "dispatch", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_taint() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "taint", "lib.rs mod.rs", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_slice() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "slice", "lib.rs:1", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_lang_bridges() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "lang-bridges", "", false).unwrap();
    // Pure Rust codebase likely has no bridges, but should not panic
    assert!(!result.is_empty());
}

#[test]
fn test_gpu_functions() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "gpu-functions", "", false).unwrap();
    // Pure Rust codebase has no GPU functions, but should not panic
    assert!(!result.is_empty());
}

#[test]
fn test_monkey_patches() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "monkey-patches", "", false).unwrap();
    // Pure Rust codebase has no monkey patches, but should not panic
    assert!(!result.is_empty());
}

#[test]
fn test_dispatch_map() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "dispatch-map", "", false).unwrap();
    // Pure Rust codebase may not have dispatch mappings, but should not panic
    assert!(!result.is_empty());
}

#[test]
fn test_diff_functions() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "diff-functions", "HEAD", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_api_diff() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "api-diff", "HEAD", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_churn() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "churn", "HEAD", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_diff_impact() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "diff-impact", "HEAD", false).unwrap();
    assert!(!result.is_empty());
}

#[test]
fn test_git_coupling() {
    let mut graph = scan_self();
    let result = execute(&mut graph, "git-coupling", "", false).unwrap();
    assert!(!result.is_empty());
}

// ── Skip-dir guards ────────────────────────────────────────────────
//
// Regression test for the OOM-cascade incident 2026-04-29 23:18 UTC.
// SKIP_DIRS must exclude vendored / cached / build trees so a scan
// rooted near user code doesn't descend into 10K-file `.venv` trees
// and AST-parse the world.

fn write(path: &std::path::Path, body: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
}

#[test]
fn test_skip_dirs_exclude_dep_trees() {
    let tmp = std::env::temp_dir().join(format!("codemap-skip-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);

    write(&tmp.join("src/user_code.py"), "def real_function():\n    pass\n");
    write(&tmp.join(".venv/lib/python3.13/site-packages/mypy/vendored.py"), "def junk(): pass\n");
    write(&tmp.join("venv/lib/site.py"), "def junk(): pass\n");
    write(&tmp.join("__pycache__/cached.py"), "def junk(): pass\n");
    write(&tmp.join(".pytest_cache/v/cache.py"), "def junk(): pass\n");
    write(&tmp.join(".mypy_cache/3.13/types.py"), "def junk(): pass\n");
    write(&tmp.join("vendor/dep.go"), "package vendored\n");
    write(&tmp.join("node_modules/lib/index.js"), "function junk(){}\n");
    write(&tmp.join(".next/server/page.js"), "function junk(){}\n");
    write(&tmp.join("Pods/lib.swift"), "func junk(){}\n");
    write(&tmp.join("target/release/build.rs"), "fn junk() {}\n");
    write(&tmp.join("dist/bundle.js"), "function junk(){}\n");

    let graph = scan(ScanOptions {
        dirs: vec![tmp.clone()],
        include_paths: vec![],
        no_cache: true,
        quiet: true,
    }).expect("scan should succeed");

    let scanned: Vec<&String> = graph.nodes.keys().collect();
    let user_hits = scanned.iter().filter(|p| p.contains("user_code.py")).count();
    let vendored_hits = scanned.iter().filter(|p| {
        p.contains(".venv/") || p.contains("/venv/") || p.contains("__pycache__/")
            || p.contains(".pytest_cache/") || p.contains(".mypy_cache/")
            || p.contains("/vendor/") || p.contains("/node_modules/")
            || p.contains("/.next/") || p.contains("/Pods/")
            || p.contains("/target/") || p.contains("/dist/")
    }).count();

    let _ = fs::remove_dir_all(&tmp);

    assert_eq!(user_hits, 1, "expected user_code.py to be scanned (found paths: {:?})", scanned);
    assert_eq!(vendored_hits, 0, "expected zero vendored/cache files in graph (found: {:?})",
        scanned.iter().filter(|p| !p.contains("user_code.py")).collect::<Vec<_>>());
}
