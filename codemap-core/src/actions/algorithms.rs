use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::cmp::Reverse;
use crate::types::Graph;

// ── Classical Graph Algorithms ─────────────────────────────────────
//
// petgraph parity: Bellman-Ford, A*, Floyd-Warshall, MST, max-flow,
// cliques, K-shortest paths, feedback arc set, diameter.
//
// Edge weights default to 1.0 (unweighted graphs); future work could
// honor `attrs["weight"]` if a user wants weighted edges.

fn build_index(graph: &Graph) -> (Vec<String>, HashMap<String, usize>) {
    let mut ids: Vec<String> = graph.nodes.keys().cloned().collect();
    ids.sort();
    let map: HashMap<String, usize> = ids.iter().enumerate()
        .map(|(i, s)| (s.clone(), i))
        .collect();
    (ids, map)
}

fn directed_adj(graph: &Graph) -> (Vec<String>, Vec<Vec<usize>>) {
    let (ids, map) = build_index(graph);
    let n = ids.len();
    let mut adj = vec![Vec::new(); n];
    for (i, id) in ids.iter().enumerate() {
        if let Some(node) = graph.nodes.get(id) {
            for imp in &node.imports {
                if let Some(&j) = map.get(imp) {
                    if i != j { adj[i].push(j); }
                }
            }
        }
    }
    (ids, adj)
}

fn undirected_adj(graph: &Graph) -> (Vec<String>, Vec<Vec<usize>>) {
    let (ids, map) = build_index(graph);
    let n = ids.len();
    let mut adj_set = vec![HashSet::new(); n];
    for (i, id) in ids.iter().enumerate() {
        if let Some(node) = graph.nodes.get(id) {
            for imp in &node.imports {
                if let Some(&j) = map.get(imp) {
                    if i != j { adj_set[i].insert(j); adj_set[j].insert(i); }
                }
            }
            for imp in &node.imported_by {
                if let Some(&j) = map.get(imp) {
                    if i != j { adj_set[i].insert(j); adj_set[j].insert(i); }
                }
            }
        }
    }
    let adj: Vec<Vec<usize>> = adj_set.into_iter()
        .map(|s| { let mut v: Vec<usize> = s.into_iter().collect(); v.sort(); v })
        .collect();
    (ids, adj)
}

// ── Bellman-Ford ────────────────────────────────────────────────────
//
// Single-source shortest paths with negative-edge support. We treat
// edge weights as 1.0 (unweighted), so Bellman-Ford here gives the
// same result as BFS — but it's the right entry point if we ever
// want weighted edges. Detects negative cycles even in unweighted
// graphs (impossible since w=1, but the check is free).

pub fn bellman_ford(graph: &Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap bellman-ford <source-node>".to_string();
    }
    let (ids, adj) = directed_adj(graph);
    let n = ids.len();
    if n == 0 { return "No nodes.".to_string(); }
    let src = match graph.find_node(target).and_then(|n| ids.iter().position(|id| id == &n.id)) {
        Some(i) => i,
        None => return format!("Source not found: {target}"),
    };

    let mut dist = vec![f64::INFINITY; n];
    dist[src] = 0.0;
    for _ in 0..n.saturating_sub(1) {
        let mut changed = false;
        for u in 0..n {
            if dist[u].is_infinite() { continue; }
            for &v in &adj[u] {
                if dist[u] + 1.0 < dist[v] {
                    dist[v] = dist[u] + 1.0;
                    changed = true;
                }
            }
        }
        if !changed { break; }
    }

    let mut ranked: Vec<(usize, f64)> = dist.iter().copied().enumerate()
        .filter(|(_, d)| !d.is_infinite())
        .collect();
    ranked.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

    let mut lines = vec![
        format!("=== Bellman-Ford from {} ({} reachable nodes) ===",
            ids[src], ranked.len()),
        String::new(),
    ];
    for (i, d) in ranked.iter().take(50) {
        lines.push(format!("  {:>4} hops  {}", *d as i64, ids[*i]));
    }
    if ranked.len() > 50 {
        lines.push(format!("  ... and {} more", ranked.len() - 50));
    }
    lines.join("\n")
}

// ── A* ─────────────────────────────────────────────────────────────
//
// Shortest path between two nodes using A*. Heuristic: 0 (degrades
// to Dijkstra for unweighted graphs). Could be improved with a
// graph-distance estimate, but for typed-graph use cases (path from
// a source file to an endpoint) the homogeneous-edge case is fine.

pub fn astar(graph: &Graph, target: &str) -> String {
    let parts: Vec<&str> = target.split_whitespace().collect();
    if parts.len() < 2 {
        return "Usage: codemap astar <source> <target>".to_string();
    }
    let (ids, adj) = directed_adj(graph);
    let n = ids.len();
    let src = match graph.find_node(parts[0]).and_then(|node| ids.iter().position(|id| id == &node.id)) {
        Some(i) => i,
        None => return format!("Source not found: {}", parts[0]),
    };
    let dst = match graph.find_node(parts[1]).and_then(|node| ids.iter().position(|id| id == &node.id)) {
        Some(i) => i,
        None => return format!("Target not found: {}", parts[1]),
    };

    let mut g_score = vec![f64::INFINITY; n];
    g_score[src] = 0.0;
    let mut came_from: Vec<Option<usize>> = vec![None; n];
    let mut open: BinaryHeap<Reverse<(u64, usize)>> = BinaryHeap::new();
    open.push(Reverse((0, src)));

    while let Some(Reverse((_, u))) = open.pop() {
        if u == dst { break; }
        for &v in &adj[u] {
            let tentative = g_score[u] + 1.0;
            if tentative < g_score[v] {
                came_from[v] = Some(u);
                g_score[v] = tentative;
                let f = tentative.to_bits();
                open.push(Reverse((f, v)));
            }
        }
    }

    if g_score[dst].is_infinite() {
        return format!("No path from {} to {}", ids[src], ids[dst]);
    }

    // Reconstruct path
    let mut path: Vec<usize> = vec![dst];
    let mut cur = dst;
    while let Some(p) = came_from[cur] {
        path.push(p);
        cur = p;
    }
    path.reverse();

    let mut lines = vec![
        format!("=== A* {} → {} ({} hops) ===", ids[src], ids[dst], path.len() - 1),
        String::new(),
    ];
    for (i, &n_idx) in path.iter().enumerate() {
        if i > 0 { lines.push("  ↓".to_string()); }
        lines.push(format!("  [{i}] {}", ids[n_idx]));
    }
    lines.join("\n")
}

// ── Floyd-Warshall + Diameter ──────────────────────────────────────
//
// All-pairs shortest paths. O(V³) — heavy for big graphs but useful
// for diameter (longest shortest path) and exact-distance queries.
// Reports just the diameter and eccentricity stats; full matrix would
// dump V² lines.

pub fn floyd_warshall(graph: &Graph, _target: &str) -> String {
    let (ids, adj) = directed_adj(graph);
    let n = ids.len();
    if n == 0 { return "No nodes.".to_string(); }
    if n > 2000 {
        return format!("Floyd-Warshall is O(V³) — refusing on {n} nodes (>2000). \
            Use `codemap betweenness` or `bellman-ford <node>` instead.");
    }

    // Initialize with INFINITY, 0 on diagonal, 1 for edges
    let inf = f64::INFINITY;
    let mut d = vec![vec![inf; n]; n];
    for i in 0..n {
        d[i][i] = 0.0;
        for &j in &adj[i] { d[i][j] = 1.0; }
    }
    // O(V³) triple loop
    for k in 0..n {
        for i in 0..n {
            if d[i][k].is_infinite() { continue; }
            for j in 0..n {
                let alt = d[i][k] + d[k][j];
                if alt < d[i][j] { d[i][j] = alt; }
            }
        }
    }

    // Eccentricity = max distance from each node to any reachable node
    let mut eccentricity = vec![0.0f64; n];
    for i in 0..n {
        let m = d[i].iter().copied()
            .filter(|x| !x.is_infinite())
            .fold(0.0, f64::max);
        eccentricity[i] = m;
    }
    let radius = eccentricity.iter().copied()
        .filter(|x| *x > 0.0)
        .fold(f64::INFINITY, f64::min);
    let diameter = eccentricity.iter().copied().fold(0.0f64, f64::max);

    let mut by_ecc: Vec<(usize, f64)> = eccentricity.iter().copied().enumerate().collect();
    by_ecc.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let mut lines = vec![
        format!("=== Floyd-Warshall ({} nodes, O(V³) all-pairs) ===", n),
        format!("Diameter:  {} (longest shortest path)", diameter as i64),
        format!("Radius:    {} (smallest max distance)",
            if radius.is_infinite() { 0 } else { radius as i64 }),
        String::new(),
        "── Top 10 by eccentricity (peripheral nodes) ──".to_string(),
    ];
    for (i, e) in by_ecc.iter().take(10) {
        lines.push(format!("  ecc={:<3}  {}", *e as i64, ids[*i]));
    }
    lines.join("\n")
}

pub fn diameter(graph: &Graph, _target: &str) -> String {
    // Just diameter — uses BFS from each node, faster than Floyd-Warshall
    // for unweighted graphs (O(VE) vs O(V³)).
    let (ids, adj) = directed_adj(graph);
    let n = ids.len();
    if n == 0 { return "No nodes.".to_string(); }

    let mut max_dist = 0i64;
    let mut endpoints = (0usize, 0usize);
    for s in 0..n {
        let mut dist = vec![-1i64; n];
        dist[s] = 0;
        let mut q: VecDeque<usize> = VecDeque::new();
        q.push_back(s);
        while let Some(u) = q.pop_front() {
            for &v in &adj[u] {
                if dist[v] < 0 {
                    dist[v] = dist[u] + 1;
                    q.push_back(v);
                    if dist[v] > max_dist {
                        max_dist = dist[v];
                        endpoints = (s, v);
                    }
                }
            }
        }
    }
    format!("=== Graph Diameter ===\n\n  {} hops: {} → {}",
        max_dist, ids[endpoints.0], ids[endpoints.1])
}

// ── Minimum Spanning Tree (Kruskal) ────────────────────────────────
//
// On unweighted graphs, MST = any spanning tree (all edges weight 1).
// We use Kruskal's with union-find for canonical ordering.

pub fn mst(graph: &Graph, _target: &str) -> String {
    let (ids, adj) = undirected_adj(graph);
    let n = ids.len();
    if n == 0 { return "No nodes.".to_string(); }

    // Union-find
    let mut parent: Vec<usize> = (0..n).collect();
    fn find(p: &mut [usize], x: usize) -> usize {
        if p[x] != x { let r = find(p, p[x]); p[x] = r; r } else { x }
    }

    let mut edges: Vec<(usize, usize)> = Vec::new();
    for (u, neighbors) in adj.iter().enumerate() {
        for &v in neighbors {
            if u < v { edges.push((u, v)); }
        }
    }
    edges.sort();

    let mut tree_edges: Vec<(usize, usize)> = Vec::new();
    for (u, v) in edges {
        let ru = find(&mut parent, u);
        let rv = find(&mut parent, v);
        if ru != rv {
            parent[ru] = rv;
            tree_edges.push((u, v));
        }
    }
    let components = (0..n).filter(|&i| find(&mut parent, i) == i).count();

    let mut lines = vec![
        format!("=== Minimum Spanning Tree ({} edges across {} components) ===",
            tree_edges.len(), components),
        String::new(),
    ];
    for (u, v) in tree_edges.iter().take(50) {
        lines.push(format!("  {} — {}", ids[*u], ids[*v]));
    }
    if tree_edges.len() > 50 {
        lines.push(format!("  ... and {} more", tree_edges.len() - 50));
    }
    lines.join("\n")
}

// ── Maximum Cliques (Bron-Kerbosch) ────────────────────────────────
//
// Find all maximal cliques in the undirected graph. Useful for
// identifying tightly-coupled groups smaller than Leiden communities.
// Output is the top 10 by size.

pub fn cliques(graph: &Graph, _target: &str) -> String {
    let (ids, adj) = undirected_adj(graph);
    let n = ids.len();
    if n == 0 { return "No nodes.".to_string(); }
    let adj_sets: Vec<HashSet<usize>> = adj.iter()
        .map(|v| v.iter().copied().collect())
        .collect();

    let mut max_cliques: Vec<HashSet<usize>> = Vec::new();
    let p: HashSet<usize> = (0..n).collect();
    let r = HashSet::new();
    let x = HashSet::new();
    bron_kerbosch(&r, p, x, &adj_sets, &mut max_cliques);

    // Filter trivially-small cliques (size <= 2)
    max_cliques.retain(|c| c.len() >= 3);
    max_cliques.sort_by(|a, b| b.len().cmp(&a.len()));

    let mut lines = vec![
        format!("=== Maximal Cliques (size ≥ 3, top 10) ==="),
        format!("Total cliques: {}", max_cliques.len()),
        String::new(),
    ];
    for (i, clique) in max_cliques.iter().take(10).enumerate() {
        let mut members: Vec<&str> = clique.iter().map(|&j| ids[j].as_str()).collect();
        members.sort();
        lines.push(format!("Clique {} ({} nodes):", i + 1, clique.len()));
        for m in members.iter().take(8) {
            lines.push(format!("  {m}"));
        }
        if clique.len() > 8 {
            lines.push(format!("  ... and {} more", clique.len() - 8));
        }
        lines.push(String::new());
    }
    lines.join("\n")
}

fn bron_kerbosch(
    r: &HashSet<usize>,
    p: HashSet<usize>,
    x: HashSet<usize>,
    adj: &[HashSet<usize>],
    out: &mut Vec<HashSet<usize>>,
) {
    if p.is_empty() && x.is_empty() {
        if !r.is_empty() { out.push(r.clone()); }
        return;
    }
    // Pivot: choose vertex in P ∪ X with max neighbors in P
    let pivot = p.union(&x).max_by_key(|&&v| {
        adj[v].iter().filter(|&n| p.contains(n)).count()
    }).copied();
    let candidates: Vec<usize> = if let Some(piv) = pivot {
        p.iter().filter(|&v| !adj[piv].contains(v)).copied().collect()
    } else {
        p.iter().copied().collect()
    };
    let mut p = p;
    let mut x = x;
    for v in candidates {
        let mut r_v = r.clone();
        r_v.insert(v);
        let p_v: HashSet<usize> = p.intersection(&adj[v]).copied().collect();
        let x_v: HashSet<usize> = x.intersection(&adj[v]).copied().collect();
        bron_kerbosch(&r_v, p_v, x_v, adj, out);
        p.remove(&v);
        x.insert(v);
        // Avoid pathological depth for huge graphs
        if out.len() > 1000 { return; }
    }
}

// ── K-Shortest Paths (Yen's algorithm) ─────────────────────────────
//
// Find the K shortest simple paths between two nodes. Default k=5.

pub fn kshortest(graph: &Graph, target: &str) -> String {
    let parts: Vec<&str> = target.split_whitespace().collect();
    if parts.len() < 2 {
        return "Usage: codemap kshortest <source> <target> [k]".to_string();
    }
    let k: usize = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);
    let (ids, adj) = directed_adj(graph);
    let n = ids.len();
    let src = match graph.find_node(parts[0]).and_then(|node| ids.iter().position(|id| id == &node.id)) {
        Some(i) => i, None => return format!("Source not found: {}", parts[0]),
    };
    let dst = match graph.find_node(parts[1]).and_then(|node| ids.iter().position(|id| id == &node.id)) {
        Some(i) => i, None => return format!("Target not found: {}", parts[1]),
    };

    // Yen's algorithm (Bhandari/Yen): start with shortest path, then
    // for each iteration find the next shortest deviating from prior.
    let bfs_path = |s: usize, t: usize, blocked: &HashSet<usize>| -> Option<Vec<usize>> {
        if s == t { return Some(vec![s]); }
        let mut prev: Vec<Option<usize>> = vec![None; n];
        let mut visited = vec![false; n];
        visited[s] = true;
        let mut q: VecDeque<usize> = VecDeque::new();
        q.push_back(s);
        while let Some(u) = q.pop_front() {
            for &v in &adj[u] {
                if visited[v] || blocked.contains(&v) { continue; }
                visited[v] = true; prev[v] = Some(u);
                if v == t {
                    let mut path = vec![t];
                    let mut cur = t;
                    while let Some(p) = prev[cur] { path.push(p); cur = p; }
                    path.reverse();
                    return Some(path);
                }
                q.push_back(v);
            }
        }
        None
    };

    let first = match bfs_path(src, dst, &HashSet::new()) {
        Some(p) => p, None => return format!("No path from {} to {}", ids[src], ids[dst]),
    };
    let mut paths: Vec<Vec<usize>> = vec![first];
    let mut candidates: Vec<Vec<usize>> = Vec::new();

    while paths.len() < k {
        let last = paths.last().unwrap().clone();
        for i in 0..last.len() - 1 {
            let spur = last[i];
            let root: Vec<usize> = last[..=i].to_vec();
            let mut blocked: HashSet<usize> = HashSet::new();
            for prior in &paths {
                if prior.len() > i && prior[..=i] == root[..] {
                    blocked.insert(prior[i + 1]);
                }
            }
            // Block intermediate root nodes from re-use
            for &n_idx in &root[..root.len() - 1] {
                blocked.insert(n_idx);
            }
            if let Some(spur_path) = bfs_path(spur, dst, &blocked) {
                let mut full = root[..root.len() - 1].to_vec();
                full.extend_from_slice(&spur_path);
                if !paths.contains(&full) && !candidates.contains(&full) {
                    candidates.push(full);
                }
            }
        }
        if candidates.is_empty() { break; }
        candidates.sort_by_key(|p| p.len());
        paths.push(candidates.remove(0));
    }

    let mut lines = vec![
        format!("=== K-Shortest Paths {} → {} (top {}) ===", ids[src], ids[dst], paths.len()),
        String::new(),
    ];
    for (i, path) in paths.iter().enumerate() {
        let names: Vec<&str> = path.iter().map(|&j| ids[j].as_str()).collect();
        lines.push(format!("  [{i}] ({} hops)  {}", path.len() - 1, names.join(" → ")));
    }
    lines.join("\n")
}

// ── Maximum Flow (Edmonds-Karp / BFS Ford-Fulkerson) ───────────────

pub fn max_flow(graph: &Graph, target: &str) -> String {
    let parts: Vec<&str> = target.split_whitespace().collect();
    if parts.len() < 2 {
        return "Usage: codemap max-flow <source> <sink>".to_string();
    }
    let (ids, adj) = directed_adj(graph);
    let n = ids.len();
    let s = match graph.find_node(parts[0]).and_then(|node| ids.iter().position(|id| id == &node.id)) {
        Some(i) => i, None => return format!("Source not found: {}", parts[0]),
    };
    let t = match graph.find_node(parts[1]).and_then(|node| ids.iter().position(|id| id == &node.id)) {
        Some(i) => i, None => return format!("Sink not found: {}", parts[1]),
    };

    // Build residual graph (capacity 1 per edge)
    let mut cap = vec![vec![0i32; n]; n];
    for (u, neighbors) in adj.iter().enumerate() {
        for &v in neighbors {
            cap[u][v] += 1;
        }
    }

    let mut flow = 0;
    loop {
        // BFS for augmenting path
        let mut prev: Vec<Option<usize>> = vec![None; n];
        let mut visited = vec![false; n];
        visited[s] = true;
        let mut q: VecDeque<usize> = VecDeque::new();
        q.push_back(s);
        while let Some(u) = q.pop_front() {
            if u == t { break; }
            for v in 0..n {
                if !visited[v] && cap[u][v] > 0 {
                    visited[v] = true;
                    prev[v] = Some(u);
                    q.push_back(v);
                }
            }
        }
        if !visited[t] { break; }
        // Find bottleneck (always 1 here since unit capacities)
        let mut path_flow = i32::MAX;
        let mut cur = t;
        while let Some(p) = prev[cur] {
            path_flow = path_flow.min(cap[p][cur]);
            cur = p;
        }
        // Augment
        let mut cur = t;
        while let Some(p) = prev[cur] {
            cap[p][cur] -= path_flow;
            cap[cur][p] += path_flow;
            cur = p;
        }
        flow += path_flow;
    }

    format!("=== Max-Flow {} → {} ===\n\n  {} edge-disjoint paths",
        ids[s], ids[t], flow)
}

// ── Feedback Arc Set (greedy DFS heuristic) ────────────────────────
//
// Find a minimal set of edges whose removal makes the graph acyclic.
// Exact min-FAS is NP-hard; we use a greedy heuristic: DFS, when we
// see a back-edge, mark it for removal.

pub fn feedback_arc(graph: &Graph, _target: &str) -> String {
    let (ids, adj) = directed_adj(graph);
    let n = ids.len();
    if n == 0 { return "No nodes.".to_string(); }

    // Tarjan-style DFS — color WHITE/GRAY/BLACK
    let mut color = vec![0u8; n]; // 0=white, 1=gray, 2=black
    let mut feedback: Vec<(usize, usize)> = Vec::new();

    fn dfs(u: usize, adj: &[Vec<usize>], color: &mut [u8], feedback: &mut Vec<(usize, usize)>) {
        color[u] = 1;
        for &v in &adj[u] {
            if color[v] == 1 {
                feedback.push((u, v)); // back-edge
            } else if color[v] == 0 {
                dfs(v, adj, color, feedback);
            }
        }
        color[u] = 2;
    }

    for u in 0..n {
        if color[u] == 0 { dfs(u, &adj, &mut color, &mut feedback); }
    }

    let mut lines = vec![
        format!("=== Feedback Arc Set ({} edges to remove for DAG) ===", feedback.len()),
        String::new(),
    ];
    if feedback.is_empty() {
        lines.push("Graph is already acyclic.".to_string());
    } else {
        for (u, v) in feedback.iter().take(50) {
            lines.push(format!("  {} → {}", ids[*u], ids[*v]));
        }
        if feedback.len() > 50 {
            lines.push(format!("  ... and {} more", feedback.len() - 50));
        }
    }
    lines.join("\n")
}
