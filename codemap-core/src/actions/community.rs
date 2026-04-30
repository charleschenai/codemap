use std::collections::{HashMap, HashSet};
use crate::types::Graph;

// ── More Community Detection ─────────────────────────────────────────
//
// We already have Leiden (default) + LPA. NetworkX-equivalent
// additions:
//
//   k-core            — find dense skeleton (k = peeling threshold)
//   k-clique          — k-clique percolation (Palla et al. 2005)
//   modularity-max    — greedy modularity (Clauset-Newman-Moore 2004)
//   divisive          — Girvan-Newman edge-betweenness deletion
//
// Each returns clusters in human-readable form mirroring leiden.rs's
// output style.

fn build_undirected(graph: &Graph) -> (Vec<String>, Vec<HashSet<usize>>) {
    let mut ids: Vec<String> = graph.nodes.keys().cloned().collect();
    ids.sort();
    let n = ids.len();
    let id_to_idx: HashMap<&str, usize> = ids.iter().enumerate()
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

// ── k-core decomposition ───────────────────────────────────────────
//
// Iteratively peel nodes of degree < k. The resulting subgraph is
// the k-core. Higher k = denser skeleton. Reports the maximum k for
// which the graph has a non-empty core, and lists the core members.

pub fn k_core(graph: &Graph, target: &str) -> String {
    let (ids, adj) = build_undirected(graph);
    let n = ids.len();
    if n == 0 { return "No nodes.".to_string(); }

    // Compute coreness number per node via standard k-core algorithm
    let mut degree: Vec<usize> = adj.iter().map(|nb| nb.len()).collect();
    let mut coreness = vec![0usize; n];
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by_key(|&v| degree[v]);
    let mut removed = vec![false; n];

    for &v in &order {
        if removed[v] { continue; }
        coreness[v] = degree[v];
        removed[v] = true;
        for &u in &adj[v] {
            if !removed[u] && degree[u] > degree[v] {
                degree[u] -= 1;
            }
        }
    }

    // If user passed a specific k, show that core; otherwise show max
    let target_k: Option<usize> = target.trim().parse().ok();
    let max_k = *coreness.iter().max().unwrap_or(&0);
    let k = target_k.unwrap_or(max_k);

    let core: Vec<usize> = (0..n).filter(|&v| coreness[v] >= k).collect();
    let mut lines = vec![
        format!("=== K-Core Decomposition ==="),
        format!("Max core: {max_k}-core ({} nodes)",
            (0..n).filter(|&v| coreness[v] >= max_k).count()),
        format!("Selected core (k={k}): {} nodes", core.len()),
        String::new(),
    ];
    if core.is_empty() {
        lines.push(format!("(no nodes with coreness ≥ {k})"));
    } else {
        let mut names: Vec<&str> = core.iter().map(|&v| ids[v].as_str()).collect();
        names.sort();
        for name in names.iter().take(50) {
            lines.push(format!("  {name}"));
        }
        if core.len() > 50 {
            lines.push(format!("  ... and {} more", core.len() - 50));
        }
    }
    lines.push(String::new());
    lines.push("Tip: pass k as target (e.g. `codemap k-core 3`) to slice".to_string());
    lines.push("a specific layer.".to_string());
    lines.join("\n")
}

// ── k-clique percolation (Palla et al. 2005) ──────────────────────
//
// Find all maximal cliques of size ≥ k, then merge cliques that
// share k-1 nodes. The connected components of merged cliques form
// communities. k=3 is the most common (triangle percolation).

pub fn k_clique(graph: &Graph, target: &str) -> String {
    let k: usize = target.trim().parse().unwrap_or(3);
    if k < 2 {
        return "k must be ≥ 2 (k=3 is the default triangle-percolation case)".to_string();
    }
    let (ids, adj) = build_undirected(graph);
    let n = ids.len();
    if n == 0 { return "No nodes.".to_string(); }

    // Find all maximal cliques via Bron-Kerbosch (limit to ones ≥ k)
    let mut max_cliques: Vec<HashSet<usize>> = Vec::new();
    let p: HashSet<usize> = (0..n).collect();
    bron_kerbosch(&HashSet::new(), p, HashSet::new(), &adj, &mut max_cliques, k, 5000);
    max_cliques.retain(|c| c.len() >= k);

    if max_cliques.is_empty() {
        return format!("No {k}-cliques found in the graph.");
    }

    // Union-find over cliques: merge if they share ≥ k-1 nodes
    let nc = max_cliques.len();
    let mut parent: Vec<usize> = (0..nc).collect();
    fn find(p: &mut [usize], x: usize) -> usize {
        if p[x] != x { let r = find(p, p[x]); p[x] = r; r } else { x }
    }
    let need_overlap = k.saturating_sub(1);
    for i in 0..nc {
        for j in (i + 1)..nc {
            let overlap = max_cliques[i].intersection(&max_cliques[j]).count();
            if overlap >= need_overlap {
                let ri = find(&mut parent, i);
                let rj = find(&mut parent, j);
                if ri != rj { parent[ri] = rj; }
            }
        }
    }

    // Group cliques by root, union their members → community node sets
    let mut communities: HashMap<usize, HashSet<usize>> = HashMap::new();
    for i in 0..nc {
        let r = find(&mut parent, i);
        communities.entry(r).or_default().extend(&max_cliques[i]);
    }
    let mut comms: Vec<HashSet<usize>> = communities.into_values().collect();
    comms.sort_by(|a, b| b.len().cmp(&a.len()));

    let mut lines = vec![
        format!("=== {k}-Clique Communities ({} found) ===", comms.len()),
        String::new(),
    ];
    for (i, c) in comms.iter().take(15).enumerate() {
        let mut names: Vec<&str> = c.iter().map(|&v| ids[v].as_str()).collect();
        names.sort();
        lines.push(format!("Community {} ({} nodes):", i + 1, c.len()));
        for n_id in names.iter().take(8) {
            lines.push(format!("  {n_id}"));
        }
        if c.len() > 8 {
            lines.push(format!("  ... and {} more", c.len() - 8));
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
    min_size: usize,
    cap: usize,
) {
    if out.len() >= cap { return; }
    if p.is_empty() && x.is_empty() {
        if r.len() >= min_size { out.push(r.clone()); }
        return;
    }
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
        bron_kerbosch(&r_v, p_v, x_v, adj, out, min_size, cap);
        p.remove(&v);
        x.insert(v);
        if out.len() >= cap { return; }
    }
}

// ── Greedy modularity (Clauset-Newman-Moore 2004) ─────────────────
//
// Each node starts in its own community. Repeatedly merge the pair
// of communities that yields the largest modularity gain. Faster
// than Leiden but less accurate. Useful as a sanity-check / cross-
// validation for Leiden output.

pub fn modularity_max(graph: &Graph, _target: &str) -> String {
    let (ids, adj) = build_undirected(graph);
    let n = ids.len();
    if n == 0 { return "No nodes.".to_string(); }

    // Total edge weight (each undirected edge counted once)
    let total_w: f64 = adj.iter().enumerate()
        .map(|(i, nb)| nb.iter().filter(|&&j| j > i).count() as f64)
        .sum();
    let m2 = (2.0 * total_w).max(1.0);

    let mut comm: Vec<usize> = (0..n).collect();
    let degree: Vec<f64> = adj.iter().map(|nb| nb.len() as f64).collect();

    // Iterate: try merging adjacent communities, pick best ΔQ
    let mut iter = 0;
    loop {
        iter += 1;
        if iter > 100 { break; }

        // Build community-level adjacency: e_ab = edges between communities
        let mut comm_edges: HashMap<(usize, usize), f64> = HashMap::new();
        let mut comm_degree: HashMap<usize, f64> = HashMap::new();
        for u in 0..n {
            *comm_degree.entry(comm[u]).or_insert(0.0) += degree[u];
            for &v in &adj[u] {
                if u < v {
                    let cu = comm[u]; let cv = comm[v];
                    let key = if cu < cv { (cu, cv) } else { (cv, cu) };
                    *comm_edges.entry(key).or_insert(0.0) += 1.0;
                }
            }
        }

        // Find best ΔQ merge
        let mut best_dq = 0.0f64;
        let mut best_pair: Option<(usize, usize)> = None;
        for ((a, b), &e_ab) in &comm_edges {
            if a == b { continue; }
            let d_a = *comm_degree.get(a).unwrap_or(&0.0);
            let d_b = *comm_degree.get(b).unwrap_or(&0.0);
            // Modularity gain from merging a and b
            let dq = 2.0 * (e_ab / m2 - (d_a * d_b) / (m2 * m2));
            if dq > best_dq + 1e-9 {
                best_dq = dq;
                best_pair = Some((*a, *b));
            }
        }

        match best_pair {
            None => break, // no positive merge available
            Some((a, b)) => {
                let merge_into = a.min(b);
                let merge_from = a.max(b);
                for c in comm.iter_mut() {
                    if *c == merge_from { *c = merge_into; }
                }
            }
        }
    }

    // Group + report
    let mut groups: HashMap<usize, Vec<usize>> = HashMap::new();
    for (v, &c) in comm.iter().enumerate() {
        groups.entry(c).or_default().push(v);
    }
    let mut sorted: Vec<Vec<usize>> = groups.into_values()
        .filter(|g| g.len() > 1)
        .collect();
    sorted.sort_by_key(|g| std::cmp::Reverse(g.len()));

    if sorted.is_empty() {
        return "Greedy modularity found no communities (>1 node).".to_string();
    }
    let mut lines = vec![
        format!("=== Modularity Max (Clauset-Newman-Moore, {} communities) ===",
            sorted.len()),
        String::new(),
    ];
    for (i, c) in sorted.iter().take(15).enumerate() {
        let mut names: Vec<&str> = c.iter().map(|&v| ids[v].as_str()).collect();
        names.sort();
        lines.push(format!("Cluster {} ({} nodes):", i + 1, c.len()));
        for n_id in names.iter().take(8) {
            lines.push(format!("  {n_id}"));
        }
        if c.len() > 8 {
            lines.push(format!("  ... and {} more", c.len() - 8));
        }
        lines.push(String::new());
    }
    lines.join("\n")
}

// ── Girvan-Newman divisive (edge-betweenness deletion) ────────────
//
// Repeatedly delete the edge with highest betweenness; each time the
// graph fragments, record the partition. We report partitions at the
// first 5 fragmentation events. O(VE²) per iteration — heavy but
// classical, useful on small graphs.

pub fn divisive(graph: &Graph, _target: &str) -> String {
    let (ids, adj_init) = build_undirected(graph);
    let n = ids.len();
    if n == 0 { return "No nodes.".to_string(); }
    if n > 500 {
        return format!("Girvan-Newman is O(VE²) — refusing on {n} nodes (>500). \
            Use `codemap clusters` (Leiden) for large graphs.").to_string();
    }
    let mut adj: Vec<HashSet<usize>> = adj_init;

    let count_components = |adj: &[HashSet<usize>]| -> Vec<HashSet<usize>> {
        let mut visited = vec![false; n];
        let mut comps: Vec<HashSet<usize>> = Vec::new();
        for s in 0..n {
            if visited[s] { continue; }
            let mut q: std::collections::VecDeque<usize> = std::collections::VecDeque::new();
            q.push_back(s);
            visited[s] = true;
            let mut c = HashSet::new();
            while let Some(u) = q.pop_front() {
                c.insert(u);
                for &v in &adj[u] {
                    if !visited[v] { visited[v] = true; q.push_back(v); }
                }
            }
            if !c.is_empty() { comps.push(c); }
        }
        comps
    };

    let initial_components = count_components(&adj).len();
    let mut snapshots: Vec<(usize, Vec<HashSet<usize>>)> = Vec::new();
    let mut iterations = 0;
    let max_iterations = 200; // bound for safety

    while snapshots.len() < 5 && iterations < max_iterations {
        iterations += 1;
        // Compute edge betweenness via BFS from every node
        let mut edge_bt: HashMap<(usize, usize), f64> = HashMap::new();
        for s in 0..n {
            // Brandes for edges
            let mut stack: Vec<usize> = Vec::with_capacity(n);
            let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); n];
            let mut sigma = vec![0i64; n];
            sigma[s] = 1;
            let mut dist = vec![-1i64; n];
            dist[s] = 0;
            let mut q: std::collections::VecDeque<usize> = std::collections::VecDeque::new();
            q.push_back(s);
            while let Some(v) = q.pop_front() {
                stack.push(v);
                for &w in &adj[v] {
                    if dist[w] < 0 {
                        dist[w] = dist[v] + 1;
                        q.push_back(w);
                    }
                    if dist[w] == dist[v] + 1 {
                        sigma[w] += sigma[v];
                        predecessors[w].push(v);
                    }
                }
            }
            let mut delta = vec![0.0f64; n];
            while let Some(w) = stack.pop() {
                for &v in &predecessors[w] {
                    if sigma[w] != 0 {
                        let c = (sigma[v] as f64 / sigma[w] as f64) * (1.0 + delta[w]);
                        delta[v] += c;
                        let key = if v < w { (v, w) } else { (w, v) };
                        *edge_bt.entry(key).or_insert(0.0) += c;
                    }
                }
            }
        }

        if edge_bt.is_empty() { break; }
        let (max_edge, _) = edge_bt.iter().max_by(|a, b|
            a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal)).unwrap();
        let (a, b) = *max_edge;
        adj[a].remove(&b);
        adj[b].remove(&a);

        let comps = count_components(&adj);
        if comps.len() > initial_components + snapshots.len() {
            snapshots.push((iterations, comps));
        }
    }

    if snapshots.is_empty() {
        return "Girvan-Newman: no fragmentation occurred within iteration cap.".to_string();
    }
    let mut lines = vec![
        format!("=== Girvan-Newman Divisive ({} fragmentations recorded) ===",
            snapshots.len()),
        String::new(),
    ];
    for (round, comps) in &snapshots {
        let bigs: Vec<&HashSet<usize>> = comps.iter().filter(|c| c.len() > 1).collect();
        lines.push(format!("After edge {round}: {} components (largest {} have >1 node)",
            comps.len(), bigs.len()));
        for (i, c) in bigs.iter().take(3).enumerate() {
            let mut names: Vec<&str> = c.iter().map(|&v| ids[v].as_str()).collect();
            names.sort();
            let preview = names.iter().take(3).copied().collect::<Vec<_>>().join(", ");
            lines.push(format!("  Comp {} ({} nodes): {preview}{}",
                i + 1, c.len(),
                if c.len() > 3 { format!(", +{} more", c.len() - 3) } else { String::new() }));
        }
        lines.push(String::new());
    }
    lines.join("\n")
}
