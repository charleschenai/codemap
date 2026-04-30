use std::collections::HashSet;
use crate::types::Graph;

// ── Link Prediction ──────────────────────────────────────────────────
//
// Find pairs of nodes that "should be connected" based on shared
// neighborhood structure. Surfaces missing-import bugs, cohesion
// gaps, and nodes that look architecturally similar but never
// directly reference each other.
//
// Three classical similarity measures:
//   - Common Neighbors:    |N(u) ∩ N(v)|
//   - Jaccard:             |N(u) ∩ N(v)| / |N(u) ∪ N(v)|
//   - Adamic-Adar:         Σ_{w ∈ N(u) ∩ N(v)} 1 / log(|N(w)|)
//
// All operate on the undirected graph (union of imports + imported_by).
// Output is the top-30 unconnected pairs by similarity score —
// "files that look like they should know about each other but don't."

fn build_undirected(graph: &Graph) -> (Vec<String>, Vec<HashSet<usize>>) {
    let mut ids: Vec<String> = graph.nodes.keys().cloned().collect();
    ids.sort();
    let n = ids.len();
    let id_to_idx: std::collections::HashMap<&str, usize> = ids.iter().enumerate()
        .map(|(i, s)| (s.as_str(), i)).collect();
    let mut adj = vec![HashSet::new(); n];
    for (i, id) in ids.iter().enumerate() {
        if let Some(node) = graph.nodes.get(id) {
            for imp in &node.imports {
                if let Some(&j) = id_to_idx.get(imp.as_str()) {
                    if i != j { adj[i].insert(j); adj[j].insert(i); }
                }
            }
            for imp in &node.imported_by {
                if let Some(&j) = id_to_idx.get(imp.as_str()) {
                    if i != j { adj[i].insert(j); adj[j].insert(i); }
                }
            }
        }
    }
    (ids, adj)
}

/// Common Neighbors: simplest link-prediction signal. Count of shared
/// undirected neighbors between two non-connected nodes.
pub fn common_neighbors(graph: &Graph) -> String {
    let (ids, adj) = build_undirected(graph);
    let n = ids.len();
    if n < 2 { return "Need at least 2 nodes.".to_string(); }

    let mut pairs: Vec<(usize, usize, usize)> = Vec::new();
    for u in 0..n {
        for v in (u + 1)..n {
            // Skip already-connected pairs
            if adj[u].contains(&v) { continue; }
            let common = adj[u].intersection(&adj[v]).count();
            if common > 0 {
                pairs.push((u, v, common));
            }
        }
    }
    pairs.sort_by(|a, b| b.2.cmp(&a.2));

    let mut lines = vec![
        format!("=== Common Neighbors (top {} unconnected pairs) ===",
            pairs.len().min(30)),
        "Pairs of files that share neighbors but don't directly connect —".to_string(),
        "candidates for missing imports / refactor opportunities.".to_string(),
        String::new(),
    ];
    for (u, v, score) in pairs.iter().take(30) {
        lines.push(format!("  {:>4} shared  {} ↔ {}", score, ids[*u], ids[*v]));
    }
    lines.join("\n")
}

/// Jaccard similarity: |N(u) ∩ N(v)| / |N(u) ∪ N(v)|. Penalizes
/// node pairs where one has many more neighbors than the other —
/// a "bigger" node looks similar to many things via raw common-
/// neighbor count, but Jaccard normalizes for that.
pub fn jaccard(graph: &Graph) -> String {
    let (ids, adj) = build_undirected(graph);
    let n = ids.len();
    if n < 2 { return "Need at least 2 nodes.".to_string(); }

    let mut pairs: Vec<(usize, usize, f64)> = Vec::new();
    for u in 0..n {
        for v in (u + 1)..n {
            if adj[u].contains(&v) { continue; }
            let inter = adj[u].intersection(&adj[v]).count();
            if inter == 0 { continue; }
            let union = adj[u].union(&adj[v]).count();
            let score = inter as f64 / union as f64;
            pairs.push((u, v, score));
        }
    }
    pairs.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));

    let mut lines = vec![
        format!("=== Jaccard Similarity (top {} unconnected pairs) ===",
            pairs.len().min(30)),
        "|shared| / |either| — normalized for node degree.".to_string(),
        String::new(),
    ];
    for (u, v, s) in pairs.iter().take(30) {
        lines.push(format!("  {:>6.3}  {} ↔ {}", s, ids[*u], ids[*v]));
    }
    lines.join("\n")
}

/// Adamic-Adar: Σ 1/log(|N(w)|) over shared neighbors w. Common
/// neighbors with FEWER total connections weight more — "this rare
/// shared connection is meaningful." Empirically the strongest of
/// the classical link-prediction signals on social and citation
/// graphs.
pub fn adamic_adar(graph: &Graph) -> String {
    let (ids, adj) = build_undirected(graph);
    let n = ids.len();
    if n < 2 { return "Need at least 2 nodes.".to_string(); }

    // Pre-compute weights: 1 / log(|N(w)|) for each w
    let weights: Vec<f64> = adj.iter().map(|nb| {
        let k = nb.len();
        if k > 1 { 1.0 / (k as f64).ln() } else { 0.0 }
    }).collect();

    let mut pairs: Vec<(usize, usize, f64)> = Vec::new();
    for u in 0..n {
        for v in (u + 1)..n {
            if adj[u].contains(&v) { continue; }
            let mut score = 0.0f64;
            for w in adj[u].intersection(&adj[v]) {
                score += weights[*w];
            }
            if score > 0.0 {
                pairs.push((u, v, score));
            }
        }
    }
    pairs.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));

    let mut lines = vec![
        format!("=== Adamic-Adar (top {} unconnected pairs) ===",
            pairs.len().min(30)),
        "Σ 1/log(degree(shared-neighbor)) — rare neighbors weighted higher.".to_string(),
        String::new(),
    ];
    for (u, v, s) in pairs.iter().take(30) {
        lines.push(format!("  {:>6.3}  {} ↔ {}", s, ids[*u], ids[*v]));
    }
    lines.join("\n")
}
