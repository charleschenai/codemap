use std::fs;
use std::path::PathBuf;
use codemap_core::{scan, execute, ScanOptions};
use codemap_core::types::{Graph, GraphNode, EntityKind};
use std::collections::HashMap;

/// Helper: build a small synthetic heterogeneous graph for centrality /
/// meta-path tests. Topology:
///   src1.py ─→ ep_get_users    (HttpEndpoint)
///   src1.py ─→ ep_post_orders  (HttpEndpoint)
///   src2.py ─→ ep_get_users
///   ep_get_users ─→ users      (SchemaTable)
///   ep_post_orders ─→ orders   (SchemaTable)
///   orders ─→ users           (FK relationship — common)
fn synthetic_hetero_graph() -> Graph {
    let mut g = Graph {
        nodes: HashMap::new(),
        scan_dir: ".".to_string(),
        cpg: None,
    };
    g.ensure_typed_node("file:src1.py",   EntityKind::SourceFile,   &[]);
    g.ensure_typed_node("file:src2.py",   EntityKind::SourceFile,   &[]);
    g.ensure_typed_node("ep:GET:users",   EntityKind::HttpEndpoint, &[]);
    g.ensure_typed_node("ep:POST:orders", EntityKind::HttpEndpoint, &[]);
    g.ensure_typed_node("table:users",    EntityKind::SchemaTable,  &[]);
    g.ensure_typed_node("table:orders",   EntityKind::SchemaTable,  &[]);

    g.add_edge("file:src1.py",   "ep:GET:users");
    g.add_edge("file:src1.py",   "ep:POST:orders");
    g.add_edge("file:src2.py",   "ep:GET:users");
    g.add_edge("ep:GET:users",   "table:users");
    g.add_edge("ep:POST:orders", "table:orders");
    g.add_edge("table:orders",   "table:users");
    g
}

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

// ── Heterogeneous graph + new centrality measures (5.2.0) ──────────

#[test]
fn test_meta_path_traverses_typed_edges() {
    let g = synthetic_hetero_graph();
    let paths = g.meta_path(&[
        EntityKind::SourceFile, EntityKind::HttpEndpoint, EntityKind::SchemaTable,
    ], 100);
    assert_eq!(paths.len(), 3, "expected 3 source→endpoint→table paths, got {paths:?}");
    for p in &paths {
        assert_eq!(p.len(), 3);
        assert!(p[0].starts_with("file:"));
        assert!(p[1].starts_with("ep:"));
        assert!(p[2].starts_with("table:"));
    }

    let paths2 = g.meta_path(&[
        EntityKind::SourceFile, EntityKind::HttpEndpoint,
    ], 100);
    assert_eq!(paths2.len(), 3);
}

#[test]
fn test_meta_path_action_via_dispatch() {
    let mut g = synthetic_hetero_graph();
    let result = execute(&mut g, "meta-path", "source->endpoint->table", false).unwrap();
    assert!(result.contains("Meta-Path:"), "missing header: {result}");
    assert!(result.contains("Paths: 3"), "expected 3 paths in output: {result}");
}

#[test]
fn test_betweenness_finds_chokepoints() {
    let mut g = synthetic_hetero_graph();
    let result = execute(&mut g, "betweenness", "", false).unwrap();
    assert!(result.contains("Betweenness Centrality"));
    assert!(result.contains("ep:GET:users"), "ep:GET:users should be high-betweenness, got: {result}");
}

#[test]
fn test_eigenvector_centrality_runs() {
    let mut g = synthetic_hetero_graph();
    let result = execute(&mut g, "eigenvector", "", false).unwrap();
    assert!(result.contains("Eigenvector Centrality"), "missing header: {result}");
}

#[test]
fn test_katz_centrality_runs() {
    let mut g = synthetic_hetero_graph();
    let result = execute(&mut g, "katz", "", false).unwrap();
    assert!(result.contains("Katz Centrality"), "missing header: {result}");
}

#[test]
fn test_closeness_centrality_runs() {
    let mut g = synthetic_hetero_graph();
    let result = execute(&mut g, "closeness", "", false).unwrap();
    assert!(result.contains("Closeness Centrality"), "missing header: {result}");
}

#[test]
fn test_kind_filter_restricts_centrality() {
    let mut g = synthetic_hetero_graph();
    let result = execute(&mut g, "betweenness", "table", false).unwrap();
    assert!(result.contains("Filter: table"), "filter not echoed: {result}");
    assert!(!result.contains("ep:GET:users"), "endpoint leaked into table-only filter: {result}");
}

#[test]
fn test_ensure_typed_node_is_idempotent() {
    let mut g = synthetic_hetero_graph();
    let n_before = g.nodes.len();
    g.ensure_typed_node("file:src1.py", EntityKind::SourceFile, &[("x", "y")]);
    let n_after = g.nodes.len();
    assert_eq!(n_before, n_after, "ensure_typed_node should be idempotent on existing id");
    assert_eq!(g.nodes.get("file:src1.py").unwrap().attrs.get("x"), Some(&"y".to_string()));
}

#[test]
fn test_add_edge_idempotent_and_bidirectional() {
    let mut g = synthetic_hetero_graph();
    let users_imported_by_initial = g.nodes.get("table:users").unwrap().imported_by.len();
    g.add_edge("ep:GET:users", "table:users");
    g.add_edge("ep:GET:users", "table:users");
    let after = g.nodes.get("table:users").unwrap().imported_by.len();
    assert_eq!(users_imported_by_initial, after, "duplicate edges leaked");
    let users = g.nodes.get("table:users").unwrap();
    assert!(users.imported_by.iter().any(|s| s == "ep:GET:users"));
}

#[test]
fn test_entity_kind_from_str_round_trip() {
    for k in [
        EntityKind::SourceFile, EntityKind::PeBinary, EntityKind::ElfBinary,
        EntityKind::SchemaTable, EntityKind::HttpEndpoint, EntityKind::MlModel,
    ] {
        let s = k.as_str();
        assert_eq!(EntityKind::from_str(s), Some(k), "round-trip failed for {s}");
    }
}

// ── Leiden community detection ───────────────────────────────────

/// Build a graph with two clearly-separated cliques of 4 nodes each plus
/// a single bridge edge. Leiden should recover the two cliques as
/// communities; LPA also typically finds them but is not guaranteed.
fn two_clique_graph() -> Graph {
    let mut g = Graph {
        nodes: HashMap::new(),
        scan_dir: ".".to_string(),
        cpg: None,
    };
    let make = |g: &mut Graph, id: &str| {
        g.ensure_typed_node(id, EntityKind::SourceFile, &[]);
    };
    for i in 0..4 { make(&mut g, &format!("a{i}")); }
    for i in 0..4 { make(&mut g, &format!("b{i}")); }

    // Clique A: a0-a1-a2-a3 fully connected
    for i in 0..4 {
        for j in 0..4 {
            if i != j { g.add_edge(&format!("a{i}"), &format!("a{j}")); }
        }
    }
    // Clique B: b0-b1-b2-b3 fully connected
    for i in 0..4 {
        for j in 0..4 {
            if i != j { g.add_edge(&format!("b{i}"), &format!("b{j}")); }
        }
    }
    // Single bridge edge between cliques
    g.add_edge("a0", "b0");
    g
}

#[test]
fn test_leiden_recovers_two_cliques() {
    let mut g = two_clique_graph();
    let result = execute(&mut g, "clusters", "leiden", false).unwrap();
    assert!(result.contains("Leiden"), "missing Leiden header: {result}");
    // Two communities of 4 nodes each.
    assert!(result.contains("Cluster 1 (4 files"), "expected Cluster 1 of 4 files: {result}");
    assert!(result.contains("Cluster 2 (4 files"), "expected Cluster 2 of 4 files: {result}");
}

#[test]
fn test_clusters_default_is_leiden() {
    let mut g = two_clique_graph();
    let result = execute(&mut g, "clusters", "", false).unwrap();
    assert!(result.contains("Leiden"), "default should be Leiden: {result}");
}

#[test]
fn test_clusters_lpa_still_available() {
    let mut g = two_clique_graph();
    let result = execute(&mut g, "clusters", "lpa", false).unwrap();
    // LPA's header is just "Clusters" without "Leiden"
    assert!(result.contains("Clusters"));
    assert!(!result.contains("Leiden"), "LPA shouldn't claim Leiden: {result}");
}

#[test]
fn test_clusters_unknown_algo_errors_helpfully() {
    let mut g = two_clique_graph();
    let result = execute(&mut g, "clusters", "spectral", false).unwrap();
    assert!(result.contains("Unknown clusters algo"), "should reject unknown: {result}");
    assert!(result.contains("leiden"), "should suggest leiden: {result}");
}

#[test]
fn test_harmonic_centrality_runs() {
    let mut g = synthetic_hetero_graph();
    let result = execute(&mut g, "harmonic", "", false).unwrap();
    assert!(result.contains("Harmonic Centrality"), "missing header: {result}");
}

#[test]
fn test_load_centrality_runs() {
    let mut g = synthetic_hetero_graph();
    let result = execute(&mut g, "load", "", false).unwrap();
    assert!(result.contains("Load Centrality"), "missing header: {result}");
}

#[test]
fn test_structural_holes_finds_brokers() {
    let mut g = two_clique_graph();
    let result = execute(&mut g, "structural-holes", "", false).unwrap();
    assert!(result.contains("Structural Holes"), "missing header: {result}");
    // a0 + b0 form the bridge between cliques, so they should rank
    // among the highest brokers (they have non-redundant connections).
    assert!(result.contains("a0") || result.contains("b0"), "expected a0/b0 as broker: {result}");
}

#[test]
fn test_brokers_alias() {
    let mut g = two_clique_graph();
    let result = execute(&mut g, "brokers", "", false).unwrap();
    assert!(result.contains("Structural Holes"), "brokers should alias to structural-holes: {result}");
}

#[test]
fn test_voterank_runs() {
    let mut g = two_clique_graph();
    let result = execute(&mut g, "voterank", "", false).unwrap();
    assert!(result.contains("VoteRank"), "missing header: {result}");
    // Top spreaders should include nodes from both cliques
    assert!(result.contains("a") || result.contains("b"));
}

#[test]
fn test_group_centrality_runs() {
    let mut g = synthetic_hetero_graph();
    // Group all SchemaTable nodes
    let result = execute(&mut g, "group", "table", false).unwrap();
    assert!(result.contains("Group Centrality"), "missing header: {result}");
}

#[test]
fn test_group_centrality_requires_filter() {
    let mut g = synthetic_hetero_graph();
    let result = execute(&mut g, "group", "", false).unwrap();
    assert!(result.contains("requires a kind filter"), "should warn: {result}");
}

#[test]
fn test_percolation_runs() {
    let mut g = synthetic_hetero_graph();
    let result = execute(&mut g, "percolation", "", false).unwrap();
    assert!(result.contains("Percolation"), "missing header: {result}");
}

#[test]
fn test_current_flow_runs() {
    let mut g = synthetic_hetero_graph();
    let result = execute(&mut g, "current-flow", "", false).unwrap();
    assert!(result.contains("Current-Flow"), "missing header: {result}");
}

#[test]
fn test_pipeline_chains_actions() {
    // 5.5.1: pipeline composite chains multiple actions in one call,
    // accumulating graph mutations. Cache-persistence makes this also
    // work across processes; pipeline is the one-shot variant that
    // doesn't depend on .codemap/ state.
    let tmp = std::env::temp_dir().join(format!("codemap-pipeline-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(tmp.join("src")).unwrap();
    fs::write(tmp.join("src/c.js"),
        "fetch('https://api.real.io/users');".to_string()
    ).unwrap();

    let mut g = scan(ScanOptions {
        dirs: vec![tmp.clone()],
        include_paths: vec![],
        no_cache: true,
        quiet: true,
    }).expect("scan should succeed");

    // Pipeline: js-api-extract THEN meta-path. The JS-extracted endpoint
    // should be visible to the meta-path step in the same process.
    let pipeline_arg = format!("js-api-extract:{},meta-path:source->endpoint",
        tmp.join("src/").to_string_lossy());
    let result = execute(&mut g, "pipeline", &pipeline_arg, false).unwrap();

    let _ = fs::remove_dir_all(&tmp);

    assert!(result.contains("Pipeline (2 steps)"));
    assert!(result.contains("Step 1/2: js-api-extract"));
    assert!(result.contains("Step 2/2: meta-path"));
    assert!(result.contains("Final output"));
    assert!(result.contains("Paths:"), "meta-path output missing: {result}");
    // The JS source already auto-promotes URL → endpoint via scanner pass,
    // so we expect at least 1 path.
    assert!(!result.contains("Paths: 0"), "expected paths from chained js-api-extract: {result}");
}

#[test]
fn test_pipeline_help() {
    let mut g = synthetic_hetero_graph();
    let result = execute(&mut g, "pipeline", "", false).unwrap();
    assert!(result.contains("Usage:"), "should show usage: {result}");
    assert!(result.contains("action1:target1"), "should explain syntax: {result}");
}

#[test]
fn test_scanner_auto_classifies_typed_files() {
    // 5.6.0: scanner walks for binary / ML / schema file extensions and
    // registers typed nodes during scan, so a plain `codemap structure`
    // produces a heterogeneous graph without needing manual RE actions.
    let tmp = std::env::temp_dir().join(format!("codemap-auto-classify-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(tmp.join("bin")).unwrap();
    fs::create_dir_all(tmp.join("models")).unwrap();
    fs::create_dir_all(tmp.join("schemas")).unwrap();

    fs::write(tmp.join("bin/server.exe"), b"MZ\x00\x00").unwrap();
    fs::write(tmp.join("bin/lib.so"), b"\x7FELF").unwrap();
    fs::write(tmp.join("bin/util.dylib"), b"\xFE\xED\xFA\xCE").unwrap();
    fs::write(tmp.join("models/m.gguf"), b"GGUF").unwrap();
    fs::write(tmp.join("models/m.onnx"), b"\x08\x00").unwrap();
    fs::write(tmp.join("schemas/api.proto"), "syntax = \"proto3\";").unwrap();
    fs::write(tmp.join("schemas/main.tf"), "resource \"x\" \"y\" {}").unwrap();

    let g = scan(ScanOptions {
        dirs: vec![tmp.clone()],
        include_paths: vec![],
        no_cache: true,
        quiet: true,
    }).expect("scan should succeed");

    let _ = fs::remove_dir_all(&tmp);

    let kinds: std::collections::HashSet<EntityKind> = g.nodes.values()
        .map(|n| n.kind).collect();

    assert!(kinds.contains(&EntityKind::PeBinary), "no .exe → PeBinary node: {:?}", kinds);
    assert!(kinds.contains(&EntityKind::ElfBinary), "no .so → ElfBinary node: {:?}", kinds);
    assert!(kinds.contains(&EntityKind::MachoBinary), "no .dylib → MachoBinary node: {:?}", kinds);
    assert!(kinds.contains(&EntityKind::MlModel), "no .gguf/.onnx → MlModel node: {:?}", kinds);
    assert!(kinds.contains(&EntityKind::ProtoMessage), "no .proto → ProtoMessage node: {:?}", kinds);
    assert!(kinds.contains(&EntityKind::TerraformResource), "no .tf → TerraformResource node: {:?}", kinds);

    // Verify auto-classified nodes are tagged so future RE-action runs
    // know they were lightly classified (not deeply parsed)
    let auto_count = g.nodes.values()
        .filter(|n| n.attrs.get("auto_classified").map(|s| s == "true").unwrap_or(false))
        .count();
    assert!(auto_count >= 7, "expected ≥7 auto-classified nodes, got {auto_count}");
}

#[test]
fn test_audit_runs_and_reports_kinds() {
    let mut g = synthetic_hetero_graph();
    let result = execute(&mut g, "audit", "", false).unwrap();
    assert!(result.contains("Architectural Audit"), "missing header: {result}");
    assert!(result.contains("chokepoints"));
    assert!(result.contains("brokers"));
    assert!(result.contains("clusters"));
    assert!(result.contains("Node census"));
    // synthetic_hetero_graph has source + endpoint + table kinds
    assert!(result.contains("source"));
    assert!(result.contains("endpoint"));
    assert!(result.contains("table"));
}

#[test]
fn test_dot_output_uses_subgraph_clusters() {
    let mut g = synthetic_hetero_graph();
    let result = execute(&mut g, "dot", "", false).unwrap();
    // Heterogeneous graph should produce subgraph cluster blocks
    assert!(result.contains("subgraph cluster_endpoint"), "missing endpoint cluster: {result}");
    assert!(result.contains("subgraph cluster_table"), "missing table cluster: {result}");
    // SourceFile nodes should NOT be wrapped in a cluster (per the
    // implementation comment — too noisy)
    assert!(!result.contains("subgraph cluster_source"));
    // compound=true must be set so cross-cluster edges render
    assert!(result.contains("compound=true"));
}

#[test]
fn test_pipeline_halts_on_error() {
    let mut g = synthetic_hetero_graph();
    let result = execute(&mut g, "pipeline",
        "pagerank:,nonexistent-action:foo,closeness:", false).unwrap();
    assert!(result.contains("halted"), "should report halt: {result}");
    // First step succeeded
    assert!(result.contains("Step 1"));
    // Closeness (step 3) should NOT have run
    assert!(!result.contains("Closeness Centrality"));
}

#[test]
fn test_scanner_promotes_urls_to_endpoint_nodes() {
    // 5.4.0: source-code URLs become HttpEndpoint nodes during scan, so
    // `meta-path source->endpoint` works on any codebase without first
    // running a web-RE action (web-api, js-api-extract, etc.).
    let tmp = std::env::temp_dir().join(format!("codemap-url-promote-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(tmp.join("src")).unwrap();
    fs::write(tmp.join("src/api.py"), concat!(
        "import requests\n",
        "def get_users():\n",
        "    return requests.get('https://api.production.io/users')\n",
        "def post_order():\n",
        "    return requests.post('https://api.production.io/orders')\n",
    )).unwrap();

    let mut g = scan(ScanOptions {
        dirs: vec![tmp.clone()],
        include_paths: vec![],
        no_cache: true,
        quiet: true,
    }).expect("scan should succeed");

    let result = execute(&mut g, "meta-path", "source->endpoint", false).unwrap();
    let _ = fs::remove_dir_all(&tmp);

    assert!(result.contains("Paths: 2"), "expected 2 source→endpoint paths, got: {result}");
    assert!(result.contains("api.production.io"), "endpoint url missing: {result}");
}

#[test]
fn test_url_promotion_skips_localhost_and_examples() {
    // localhost / 127.0.0.1 / example.com URLs should NOT become endpoint
    // nodes — they're typically test fixtures or doc placeholders, and
    // including them would pollute production-graph queries.
    let tmp = std::env::temp_dir().join(format!("codemap-url-skip-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(tmp.join("src")).unwrap();
    fs::write(tmp.join("src/test.py"), concat!(
        "fetch('http://localhost:8080/dev')\n",
        "fetch('http://127.0.0.1/local')\n",
        "fetch('https://example.com/placeholder')\n",
        "fetch('https://real.api/endpoint')\n",
    )).unwrap();

    let mut g = scan(ScanOptions {
        dirs: vec![tmp.clone()],
        include_paths: vec![],
        no_cache: true,
        quiet: true,
    }).expect("scan should succeed");
    let result = execute(&mut g, "meta-path", "source->endpoint", false).unwrap();
    let _ = fs::remove_dir_all(&tmp);

    // Only the real endpoint should land in the graph
    assert!(result.contains("real.api"), "real endpoint missing: {result}");
    assert!(!result.contains("localhost"), "localhost leaked into graph: {result}");
    assert!(!result.contains("127.0.0.1"), "127.0.0.1 leaked into graph: {result}");
    assert!(!result.contains("example.com"), "example.com leaked: {result}");
}

#[test]
fn test_typed_node_cache_persists_across_invocations() {
    // 5.3.1: RE-action mutations must persist through a save→load round
    // trip so multi-step CLI workflows can compose passes. Simulates two
    // separate `codemap` processes scanning the same directory.
    let tmp = std::env::temp_dir().join(format!("codemap-persist-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(tmp.join("src")).unwrap();
    fs::write(tmp.join("src/client.js"),
        r#"async function getUsers() { return await fetch('https://api.example.com/users'); }"#
    ).unwrap();

    // Process 1: scan + js-api-extract (registers HttpEndpoint, saves cache)
    let mut g1 = scan(ScanOptions {
        dirs: vec![tmp.clone()],
        include_paths: vec![],
        no_cache: true,
        quiet: true,
    }).expect("scan 1 should succeed");
    let _ = execute(&mut g1, "js-api-extract", &tmp.join("src/").to_string_lossy(), false).unwrap();
    drop(g1); // simulate process exit (cache flush already happened)

    // Process 2: scan + meta-path (should read cached endpoints)
    let mut g2 = scan(ScanOptions {
        dirs: vec![tmp.clone()],
        include_paths: vec![],
        no_cache: false,
        quiet: true,
    }).expect("scan 2 should succeed");
    let result = execute(&mut g2, "meta-path", "source->endpoint", false).unwrap();

    let _ = fs::remove_dir_all(&tmp);

    assert!(result.contains("Paths:"), "missing paths header: {result}");
    // Should NOT be 0 — js-api-extract from process 1 left endpoints in cache
    assert!(!result.contains("Paths: 0"), "endpoints did not persist across processes: {result}");
}

// ── web-dom truncated-tag regression ──────────────────────────────
//
// 5.1.4: extract_buttons/forms/tables/navs in actions/reverse/web.rs used
// `unwrap_or(content.len())` as a fallback when the closing tag was missing.
// On the next loop iteration `pos = close + 1` would equal `content.len() + 1`
// and the slice `lower[pos..]` would panic with "byte index N is out of bounds".
// Reproduced on legislature.maine.gov 2026-04-30. Fix: treat a missing close
// tag as end-of-document and break out of the scan loop.

#[test]
fn test_web_dom_handles_truncated_tags_without_panic() {
    let tmp = std::env::temp_dir().join(format!("codemap-trunc-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    // Each fragment opens a tag and never closes it. Pre-fix any of these
    // would panic in extract_{buttons,forms,tables,navs} because the loop
    // would index past content.len().
    let cases = [
        ("trunc_button.html", "<html><body><button>click me"),
        ("trunc_form.html",   "<html><body><form action=\"/x\"><input name=\"a\">"),
        ("trunc_table.html",  "<html><body><table><tr><th>col"),
        ("trunc_nav.html",    "<html><body><nav><a href=\"/x\">link"),
    ];
    for (name, body) in cases.iter() {
        fs::write(tmp.join(name), body).unwrap();
    }

    let graph = scan(ScanOptions {
        dirs: vec![tmp.clone()],
        include_paths: vec![],
        no_cache: true,
        quiet: true,
    }).expect("scan should succeed");
    let mut graph = graph;

    for (name, _) in cases.iter() {
        let path = tmp.join(name).to_string_lossy().to_string();
        let result = execute(&mut graph, "web-dom", &path, false);
        assert!(
            result.is_ok(),
            "web-dom on {} should not panic; got error: {:?}",
            name, result
        );
    }

    let _ = fs::remove_dir_all(&tmp);
}
