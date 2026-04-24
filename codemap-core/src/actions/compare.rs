use crate::scanner;
use crate::types::Graph;
use crate::ScanOptions;
use std::cmp::Reverse;
use std::collections::HashSet;
use std::path::PathBuf;

pub fn compare(graph: &mut Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap compare <other-dir>  (e.g. codemap compare ~/Desktop/old-version)".to_string();
    }

    let resolved_dir = std::path::Path::new(target).canonicalize()
        .unwrap_or_else(|_| PathBuf::from(target));
    let resolved_str = resolved_dir.to_string_lossy().to_string();

    let other_graph = match scanner::scan_directories(ScanOptions {
        dirs: vec![resolved_dir.clone()],
        include_paths: vec![],
        no_cache: false,
        quiet: true,
    }) {
        Ok(g) => g,
        Err(_) => return format!("Failed to scan directory: {resolved_str}"),
    };

    let a_files: HashSet<&str> = graph.nodes.keys().map(|k| k.as_str()).collect();
    let b_files: HashSet<&str> = other_graph.nodes.keys().map(|k| k.as_str()).collect();

    let mut added: Vec<&str> = a_files.difference(&b_files).copied().collect();
    let mut removed: Vec<&str> = b_files.difference(&a_files).copied().collect();
    let common: Vec<&str> = a_files.intersection(&b_files).copied().collect();
    added.sort();
    removed.sort();

    let mut a_lines = 0usize;
    let mut b_lines = 0usize;
    let mut a_imports = 0usize;
    let mut b_imports = 0usize;
    let mut a_urls = 0usize;
    let mut b_urls = 0usize;
    for n in graph.nodes.values() { a_lines += n.lines; a_imports += n.imports.len(); a_urls += n.urls.len(); }
    for n in other_graph.nodes.values() { b_lines += n.lines; b_imports += n.imports.len(); b_urls += n.urls.len(); }

    // Coupling changes
    let mut coupling_changes: Vec<(String, i64, i64)> = Vec::new();
    for id in &common {
        let a = graph.nodes.get(*id).unwrap();
        let b = other_graph.nodes.get(*id).unwrap();
        let a_coupling = (a.imports.len() + a.imported_by.len()) as i64;
        let b_coupling = (b.imports.len() + b.imported_by.len()) as i64;
        if a_coupling != b_coupling {
            coupling_changes.push((id.to_string(), b_coupling, a_coupling));
        }
    }
    coupling_changes.sort_by_key(|a| Reverse((a.2 - a.1).abs()));

    // URLs
    let mut a_url_set: HashSet<String> = HashSet::new();
    let mut b_url_set: HashSet<String> = HashSet::new();
    for n in graph.nodes.values() { for u in &n.urls { a_url_set.insert(u.clone()); } }
    for n in other_graph.nodes.values() { for u in &n.urls { b_url_set.insert(u.clone()); } }
    let mut new_urls: Vec<&str> = a_url_set.iter().filter(|u| !b_url_set.contains(u.as_str())).map(|u| u.as_str()).collect();
    let mut removed_urls: Vec<&str> = b_url_set.iter().filter(|u| !a_url_set.contains(u.as_str())).map(|u| u.as_str()).collect();
    new_urls.sort();
    removed_urls.sort();

    let delta = |a: usize, b: usize| -> String {
        let d = a as i64 - b as i64;
        if d > 0 { format!("+{d}") } else { d.to_string() }
    };

    let mut lines = vec![
        format!("=== Compare: current vs {resolved_str} ==="),
        String::new(),
        "           Current    Other    Delta".to_string(),
        format!("Files:     {:>7}  {:>7}  {:>7}", a_files.len(), b_files.len(), delta(a_files.len(), b_files.len())),
        format!("Lines:     {:>7}  {:>7}  {:>7}", a_lines, b_lines, delta(a_lines, b_lines)),
        format!("Imports:   {:>7}  {:>7}  {:>7}", a_imports, b_imports, delta(a_imports, b_imports)),
        format!("URLs:      {:>7}  {:>7}  {:>7}", a_urls, b_urls, delta(a_urls, b_urls)),
        String::new(),
    ];

    if !added.is_empty() {
        lines.push(format!("Added files ({}):", added.len()));
        for f in added.iter().take(20) { lines.push(format!("  + {f}")); }
        if added.len() > 20 { lines.push(format!("  ... and {} more", added.len() - 20)); }
        lines.push(String::new());
    }

    if !removed.is_empty() {
        lines.push(format!("Removed files ({}):", removed.len()));
        for f in removed.iter().take(20) { lines.push(format!("  - {f}")); }
        if removed.len() > 20 { lines.push(format!("  ... and {} more", removed.len() - 20)); }
        lines.push(String::new());
    }

    if !coupling_changes.is_empty() {
        lines.push(format!("Coupling changes ({} files):", coupling_changes.len()));
        for c in coupling_changes.iter().take(20) {
            let d = c.2 - c.1;
            let sign = if d > 0 { "+" } else { "" };
            lines.push(format!("  {sign}{d} coupling  {}  ({} \u{2192} {})", c.0, c.1, c.2));
        }
        if coupling_changes.len() > 20 { lines.push(format!("  ... and {} more", coupling_changes.len() - 20)); }
        lines.push(String::new());
    }

    if !new_urls.is_empty() {
        lines.push(format!("New URLs ({}):", new_urls.len()));
        for u in new_urls.iter().take(15) { lines.push(format!("  + {u}")); }
        if new_urls.len() > 15 { lines.push(format!("  ... and {} more", new_urls.len() - 15)); }
        lines.push(String::new());
    }

    if !removed_urls.is_empty() {
        lines.push(format!("Removed URLs ({}):", removed_urls.len()));
        for u in removed_urls.iter().take(15) { lines.push(format!("  - {u}")); }
        if removed_urls.len() > 15 { lines.push(format!("  ... and {} more", removed_urls.len() - 15)); }
    }

    lines.join("\n")
}
