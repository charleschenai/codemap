use std::collections::{HashMap, VecDeque};
use crate::types::{Graph, EntityKind};

// ── Centrality Measures ──────────────────────────────────────────────
//
// Modern centrality measures complementing PageRank/HITS. Imported from
// the NetworkX catalog (which ships 17 — we add 4 of the most useful here):
//
//   betweenness — continuous chokepoint score (Brandes 2001 algorithm).
//                 Complements `bridges` (which only reports articulation
//                 points as binary). High betweenness = "every shortest
//                 path between groups runs through me."
//   eigenvector — power-iteration eigenvector centrality. PageRank without
//                 damping; honors the importance of the importers.
//   katz        — generalized eigenvector with attenuation factor α and
//                 baseline β. Handles disconnected components better
//                 than eigenvector alone.
//   closeness   — 1 / sum of shortest-path distances. "How quickly can I
//                 reach everyone." Useful for finding library files that
//                 are central in dependency depth, not just count.
//
// All four take a `kinds` filter (Vec<EntityKind>) so callers can compute
// centrality over a slice of the heterogeneous graph — e.g. just over
// HttpEndpoint+SourceFile to find chokepoint API calls without binary
// nodes diluting the rankings.

/// Build the index-based adjacency representation used by every measure
/// in this module. Filtering by `kinds` reduces the working set to a
/// kind-typed subgraph (used by `--type` flag on every centrality action).
fn build_adj(graph: &Graph, kinds: &[EntityKind]) -> (Vec<String>, Vec<Vec<usize>>, Vec<Vec<usize>>) {
    let allowed: Vec<&str> = if kinds.is_empty() {
        graph.nodes.keys().map(|s| s.as_str()).collect()
    } else {
        graph.nodes.values()
            .filter(|n| kinds.contains(&n.kind))
            .map(|n| n.id.as_str())
            .collect()
    };
    let mut allowed_sorted: Vec<&str> = allowed;
    allowed_sorted.sort();

    let ids: Vec<String> = allowed_sorted.iter().map(|s| s.to_string()).collect();
    let id_to_idx: HashMap<&str, usize> = ids.iter().enumerate()
        .map(|(i, id)| (id.as_str(), i))
        .collect();

    let n = ids.len();
    let mut out_adj: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut in_adj: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, id) in ids.iter().enumerate() {
        if let Some(node) = graph.nodes.get(id) {
            for imp in &node.imports {
                if let Some(&j) = id_to_idx.get(imp.as_str()) {
                    out_adj[i].push(j);
                    in_adj[j].push(i);
                }
            }
        }
    }
    (ids, out_adj, in_adj)
}

/// Normalize a Vec<f64> to L2 unit norm (in-place).
fn l2_normalize(v: &mut [f64]) {
    let norm = v.iter().map(|x| x * x).sum::<f64>().sqrt();
    if norm > 0.0 {
        for x in v.iter_mut() { *x /= norm; }
    }
}

/// Betweenness centrality via Brandes' algorithm (O(VE) for unweighted
/// graphs). For each source vertex, BFS computes shortest-path counts and
/// dependency accumulations. The dependencies sum into the centrality
/// score. Reports the top 30 with normalized scores [0, 1].
pub fn betweenness(graph: &Graph, kinds: &[EntityKind]) -> String {
    let (ids, out_adj, _in_adj) = build_adj(graph, kinds);
    let n = ids.len();
    if n == 0 {
        return "No nodes to rank.".to_string();
    }

    let mut cb = vec![0.0f64; n];

    for s in 0..n {
        // Single-source shortest-path BFS
        let mut stack: Vec<usize> = Vec::with_capacity(n);
        let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); n];
        let mut sigma = vec![0i64; n];
        sigma[s] = 1;
        let mut dist = vec![-1i64; n];
        dist[s] = 0;

        let mut queue: VecDeque<usize> = VecDeque::new();
        queue.push_back(s);

        while let Some(v) = queue.pop_front() {
            stack.push(v);
            for &w in &out_adj[v] {
                if dist[w] < 0 {
                    dist[w] = dist[v] + 1;
                    queue.push_back(w);
                }
                if dist[w] == dist[v] + 1 {
                    sigma[w] += sigma[v];
                    predecessors[w].push(v);
                }
            }
        }

        // Dependency accumulation (in reverse BFS order)
        let mut delta = vec![0.0f64; n];
        while let Some(w) = stack.pop() {
            for &v in &predecessors[w] {
                if sigma[w] != 0 {
                    delta[v] += (sigma[v] as f64 / sigma[w] as f64) * (1.0 + delta[w]);
                }
            }
            if w != s {
                cb[w] += delta[w];
            }
        }
    }

    // Normalize. For directed graphs the divisor is (n-1)(n-2).
    let scale = if n > 2 { 1.0 / ((n - 1) * (n - 2)) as f64 } else { 1.0 };
    for x in cb.iter_mut() { *x *= scale; }

    let mut ranked: Vec<(usize, f64)> = cb.iter().copied().enumerate().collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let top: Vec<&(usize, f64)> = ranked.iter().filter(|(_, s)| *s > 0.0).take(30).collect();
    let mut lines = vec![
        format!("=== Betweenness Centrality (top {} chokepoints) ===", top.len()),
        format!("Filter: {} | Nodes scored: {}", kinds_to_str(kinds), n),
        String::new(),
    ];
    if top.is_empty() {
        lines.push("  (no chokepoints — graph may be a tree or fully disconnected)".to_string());
    }
    for r in &top {
        let score_str = format!("{:.4}", r.1);
        lines.push(format!("  {:>8}  {}", score_str, ids[r.0]));
    }
    lines.join("\n")
}

/// Eigenvector centrality via power iteration. x_{k+1} = A^T x_k / ||·||₂
/// Stops at 100 iterations or when L1 delta < 1e-6. For directed graphs
/// uses incoming edges (importance flows from importers to imported).
pub fn eigenvector(graph: &Graph, kinds: &[EntityKind]) -> String {
    let (ids, _out_adj, in_adj) = build_adj(graph, kinds);
    let n = ids.len();
    if n == 0 { return "No nodes to rank.".to_string(); }

    let mut x = vec![1.0 / (n as f64).sqrt(); n];
    let mut x_new = vec![0.0f64; n];
    let max_iter = 100;
    let tol = 1e-6;

    for _ in 0..max_iter {
        x_new.fill(0.0);
        for v in 0..n {
            for &u in &in_adj[v] {
                x_new[v] += x[u];
            }
        }
        l2_normalize(&mut x_new);
        let delta: f64 = x.iter().zip(x_new.iter())
            .map(|(a, b)| (a - b).abs()).sum();
        std::mem::swap(&mut x, &mut x_new);
        if delta < tol { break; }
    }

    rank_and_format("Eigenvector Centrality", &ids, &x, kinds, "score")
}

/// Katz centrality: x = α A^T x + β. Converges for α < 1/λ_max where
/// λ_max is the largest eigenvalue of A. Default α=0.1 is conservative
/// (works on most real-world graphs); β=1.0 gives every node equal
/// baseline weight. Returns top 30.
pub fn katz(graph: &Graph, kinds: &[EntityKind]) -> String {
    let (ids, _out_adj, in_adj) = build_adj(graph, kinds);
    let n = ids.len();
    if n == 0 { return "No nodes to rank.".to_string(); }

    let alpha = 0.1f64;
    let beta = 1.0f64;
    let mut x = vec![beta; n];
    let mut x_new = vec![0.0f64; n];
    let max_iter = 1000;
    let tol = 1e-6;

    for _ in 0..max_iter {
        x_new.fill(beta);
        for v in 0..n {
            for &u in &in_adj[v] {
                x_new[v] += alpha * x[u];
            }
        }
        let delta: f64 = x.iter().zip(x_new.iter())
            .map(|(a, b)| (a - b).abs()).sum();
        std::mem::swap(&mut x, &mut x_new);
        if delta < tol { break; }
    }
    l2_normalize(&mut x);

    rank_and_format(&format!("Katz Centrality (α={}, β={})", alpha, beta), &ids, &x, kinds, "score")
}

/// Closeness centrality: for each node v, 1 / Σ d(v, u) over reachable u.
/// Reports top 30. Disconnected components report 0 for unreachable
/// pairs (Wasserman-Faust normalization is approximated here for speed).
pub fn closeness(graph: &Graph, kinds: &[EntityKind]) -> String {
    let (ids, out_adj, _in_adj) = build_adj(graph, kinds);
    let n = ids.len();
    if n == 0 { return "No nodes to rank.".to_string(); }

    let mut scores = vec![0.0f64; n];
    for s in 0..n {
        // BFS from s, record distances
        let mut dist = vec![-1i64; n];
        dist[s] = 0;
        let mut q: VecDeque<usize> = VecDeque::new();
        q.push_back(s);
        let mut total: i64 = 0;
        let mut reached: usize = 0;
        while let Some(v) = q.pop_front() {
            for &w in &out_adj[v] {
                if dist[w] < 0 {
                    dist[w] = dist[v] + 1;
                    total += dist[w];
                    reached += 1;
                    q.push_back(w);
                }
            }
        }
        if total > 0 {
            // Wasserman-Faust normalization: scale by reached/(n-1)
            let raw = reached as f64 / total as f64;
            scores[s] = raw * (reached as f64 / (n - 1) as f64);
        }
    }

    rank_and_format("Closeness Centrality", &ids, &scores, kinds, "score")
}

fn rank_and_format(title: &str, ids: &[String], scores: &[f64], kinds: &[EntityKind], score_label: &str) -> String {
    let mut ranked: Vec<(usize, f64)> = scores.iter().copied().enumerate().collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let top: Vec<&(usize, f64)> = ranked.iter().filter(|(_, s)| *s > 0.0).take(30).collect();
    let mut lines = vec![
        format!("=== {title} (top {}) ===", top.len()),
        format!("Filter: {} | {}: 4-decimal", kinds_to_str(kinds), score_label),
        String::new(),
    ];
    for r in &top {
        let score_str = format!("{:.4}", r.1);
        lines.push(format!("  {:>8}  {}", score_str, ids[r.0]));
    }
    lines.join("\n")
}

fn kinds_to_str(kinds: &[EntityKind]) -> String {
    if kinds.is_empty() {
        "all".to_string()
    } else {
        kinds.iter().map(|k| k.as_str()).collect::<Vec<_>>().join(",")
    }
}

/// Parse a comma-separated kind filter from a target string.
/// e.g. "table,field" → [SchemaTable, SchemaField]. Empty/whitespace → [].
/// Unknown kinds are silently dropped (after warning to stderr) so a typo
/// gives a helpful "no nodes scored" message rather than an error.
pub fn parse_kinds(target: &str) -> Vec<EntityKind> {
    let mut out = Vec::new();
    for tok in target.split(|c: char| c == ',' || c.is_whitespace()) {
        let tok = tok.trim();
        if tok.is_empty() { continue; }
        match EntityKind::from_str(tok) {
            Some(k) => out.push(k),
            None => eprintln!("Warning: unknown entity kind '{tok}' (try: source pe elf macho dll symbol endpoint form table field model …)"),
        }
    }
    out
}
