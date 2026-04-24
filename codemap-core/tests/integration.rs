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
