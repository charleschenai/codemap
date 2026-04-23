use std::collections::{HashSet, VecDeque};
use crate::types::Graph;

/// BFS shortest path A→B via imports. If not found, try reverse via importedBy.
pub fn why(graph: &Graph, target: &str) -> String {
    let parts: Vec<&str> = target.split_whitespace()
        .filter(|p| *p != "->" && *p != "→")
        .collect();
    if parts.len() < 2 {
        return "Usage: codemap why <fileA> <fileB>  (or: codemap why <fileA> -> <fileB>)".to_string();
    }
    let (a, b) = (parts[0], parts[1]);
    let node_a = match graph.find_node(a) {
        Some(n) => n,
        None => return format!("File not found: {a}"),
    };
    let node_b = match graph.find_node(b) {
        Some(n) => n,
        None => return format!("File not found: {b}"),
    };
    let id_a = node_a.id.clone();
    let id_b = node_b.id.clone();

    // BFS from A to B following imports
    let mut queue: VecDeque<Vec<String>> = VecDeque::new();
    let mut visited: HashSet<String> = HashSet::new();
    queue.push_back(vec![id_a.clone()]);
    visited.insert(id_a.clone());

    while let Some(path) = queue.pop_front() {
        let current = path.last().unwrap();
        if current == &id_b {
            let mut lines = vec![
                format!("Shortest path ({} hops):", path.len() - 1),
                String::new(),
            ];
            lines.push(format!("  {}", path.join("\n  \u{2192} ")));
            return lines.join("\n");
        }
        if let Some(node) = graph.nodes.get(current) {
            for imp in &node.imports {
                if !visited.contains(imp) && graph.nodes.contains_key(imp) {
                    visited.insert(imp.clone());
                    let mut new_path = path.clone();
                    new_path.push(imp.clone());
                    queue.push_back(new_path);
                }
            }
        }
    }

    // Try reverse direction — follow importedBy edges
    let mut queue2: VecDeque<Vec<String>> = VecDeque::new();
    let mut visited2: HashSet<String> = HashSet::new();
    queue2.push_back(vec![id_a.clone()]);
    visited2.insert(id_a.clone());

    while let Some(path) = queue2.pop_front() {
        let current = path.last().unwrap();
        if current == &id_b {
            let mut lines = vec![
                format!("Reverse path ({} hops, via importedBy edges):", path.len() - 1),
                String::new(),
            ];
            lines.push(format!("  {}", path.join("\n  \u{2190} ")));
            return lines.join("\n");
        }
        if let Some(node) = graph.nodes.get(current) {
            for imp in &node.imported_by {
                if !visited2.contains(imp) && graph.nodes.contains_key(imp) {
                    visited2.insert(imp.clone());
                    let mut new_path = path.clone();
                    new_path.push(imp.clone());
                    queue2.push_back(new_path);
                }
            }
        }
    }

    format!("No import path found between {} and {}.", id_a, id_b)
}

/// DFS all paths with depth limit 10, path limit 20. Try both directions.
pub fn paths(graph: &Graph, target: &str) -> String {
    let parts: Vec<&str> = target.split_whitespace()
        .filter(|p| *p != "->" && *p != "→")
        .collect();
    if parts.len() < 2 {
        return "Usage: codemap paths <fileA> <fileB>  (or: codemap paths <fileA> -> <fileB>)".to_string();
    }
    let (a, b) = (parts[0], parts[1]);
    let node_a = match graph.find_node(a) {
        Some(n) => n,
        None => return format!("File not found: {a}"),
    };
    let node_b = match graph.find_node(b) {
        Some(n) => n,
        None => return format!("File not found: {b}"),
    };
    let id_a = node_a.id.clone();
    let id_b = node_b.id.clone();

    let max_paths = 20usize;
    let max_depth = 10usize;
    let mut all_paths: Vec<Vec<String>> = Vec::new();

    #[allow(clippy::too_many_arguments)]
    fn dfs(
        graph: &Graph,
        current: &str,
        target_id: &str,
        path: &mut Vec<String>,
        visited: &mut HashSet<String>,
        all_paths: &mut Vec<Vec<String>>,
        max_paths: usize,
        max_depth: usize,
    ) {
        if all_paths.len() >= max_paths { return; }
        if path.len() > max_depth { return; }
        if current == target_id {
            all_paths.push(path.clone());
            return;
        }

        if let Some(node) = graph.nodes.get(current) {
            for imp in &node.imports {
                if graph.nodes.contains_key(imp) && !visited.contains(imp) {
                    visited.insert(imp.clone());
                    path.push(imp.clone());
                    dfs(graph, imp, target_id, path, visited, all_paths, max_paths, max_depth);
                    path.pop();
                    visited.remove(imp);
                }
            }
        }
    }

    // Try A→B
    let mut path = vec![id_a.clone()];
    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(id_a.clone());
    dfs(graph, &id_a, &id_b, &mut path, &mut visited, &mut all_paths, max_paths, max_depth);

    // Try B→A if no paths found, label direction correctly
    let mut reversed = false;
    if all_paths.is_empty() {
        let mut path = vec![id_b.clone()];
        let mut visited: HashSet<String> = HashSet::new();
        visited.insert(id_b.clone());
        dfs(graph, &id_b, &id_a, &mut path, &mut visited, &mut all_paths, max_paths, max_depth);
        if !all_paths.is_empty() {
            for p in &mut all_paths {
                p.reverse();
            }
            reversed = true;
        }
    }

    if all_paths.is_empty() {
        return format!(
            "No import paths found between {} and {} (searched up to {} hops).",
            id_a, id_b, max_depth
        );
    }

    all_paths.sort_by_key(|p| p.len());
    let dir_note = if reversed { " (via reverse edges \u{2014} B imports toward A)" } else { "" };
    let mut lines = vec![
        format!("=== All paths: {} \u{2192} {} ({} found{}) ===", id_a, id_b, all_paths.len(), dir_note),
        String::new(),
    ];
    for (i, p) in all_paths.iter().enumerate() {
        lines.push(format!("Path {} ({} hops):", i + 1, p.len() - 1));
        let sep = if reversed { " \u{2190} " } else { " \u{2192} " };
        lines.push(format!("  {}", p.join(sep)));
        lines.push(String::new());
    }
    lines.join("\n")
}

/// Pattern match on file IDs, BFS both directions for connected component.
pub fn subgraph(graph: &Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap subgraph <file-or-pattern>".to_string();
    }

    let mut seeds: Vec<String> = Vec::new();
    for id in graph.nodes.keys() {
        if id.contains(target) {
            seeds.push(id.clone());
        }
    }
    if seeds.is_empty() {
        if let Some(node) = graph.find_node(target) {
            seeds.push(node.id.clone());
        }
    }
    if seeds.is_empty() {
        return format!("No files matching \"{target}\".");
    }

    // BFS in both directions to get full connected component
    let mut component: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    for s in &seeds {
        component.insert(s.clone());
        queue.push_back(s.clone());
    }

    while let Some(current) = queue.pop_front() {
        if let Some(node) = graph.nodes.get(&current) {
            for imp in &node.imports {
                if graph.nodes.contains_key(imp) && !component.contains(imp) {
                    component.insert(imp.clone());
                    queue.push_back(imp.clone());
                }
            }
            for imp in &node.imported_by {
                if !component.contains(imp) {
                    component.insert(imp.clone());
                    queue.push_back(imp.clone());
                }
            }
        }
    }

    let mut sorted: Vec<&String> = component.iter().collect();
    sorted.sort();
    let mut lines = vec![
        format!("=== Subgraph around \"{}\" ({} files) ===", target, sorted.len()),
        String::new(),
    ];
    for id in sorted {
        if let Some(node) = graph.nodes.get(id) {
            let in_count = node.imports.iter().filter(|i| component.contains(*i)).count();
            let out_count = node.imported_by.iter().filter(|i| component.contains(*i)).count();
            lines.push(format!("  {}  ({}\u{2192} {}\u{2190})", id, in_count, out_count));
        }
    }
    lines.join("\n")
}

/// Jaccard similarity on imports + importers, top 20.
pub fn similar(graph: &Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap similar <file>".to_string();
    }
    let node = match graph.find_node(target) {
        Some(n) => n,
        None => return format!("File not found: {target}"),
    };
    let node_id = node.id.clone();

    // Filter to local files only — exclude external packages
    let my_imports: HashSet<&String> = node.imports.iter()
        .filter(|i| graph.nodes.contains_key(*i))
        .collect();
    let my_importers: HashSet<&String> = node.imported_by.iter().collect();

    struct Score {
        id: String,
        score: f64,
        shared: usize,
    }

    let mut scores: Vec<Score> = Vec::new();
    for (id, other) in &graph.nodes {
        if id == &node_id { continue; }

        let other_imports: HashSet<&String> = other.imports.iter()
            .filter(|i| graph.nodes.contains_key(*i))
            .collect();
        let other_importers: HashSet<&String> = other.imported_by.iter().collect();

        // Jaccard similarity on imports
        let import_union: HashSet<&String> = my_imports.union(&other_imports).cloned().collect();
        let import_intersect = my_imports.intersection(&other_imports).count();

        // Jaccard similarity on importers
        let importer_union: HashSet<&String> = my_importers.union(&other_importers).cloned().collect();
        let importer_intersect = my_importers.intersection(&other_importers).count();

        let import_jaccard = if import_union.is_empty() { 0.0 } else { import_intersect as f64 / import_union.len() as f64 };
        let importer_jaccard = if importer_union.is_empty() { 0.0 } else { importer_intersect as f64 / importer_union.len() as f64 };

        let score_val = (import_jaccard + importer_jaccard) / 2.0;
        let shared = import_intersect + importer_intersect;
        if score_val > 0.0 {
            scores.push(Score { id: id.clone(), score: score_val, shared });
        }
    }

    scores.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    let top: Vec<&Score> = scores.iter().take(20).collect();
    if top.is_empty() {
        return format!("No files similar to {}.", node_id);
    }

    let mut lines = vec![
        format!("=== Files similar to {} ===", node_id),
        String::new(),
    ];
    for s in &top {
        // padStart(5) in TS = right-align in 5 chars
        let pct = format!("{:.1}", s.score * 100.0);
        lines.push(format!("  {:>5}% similar  {}  ({} shared deps)", pct, s.id, s.shared));
    }
    lines.join("\n")
}
