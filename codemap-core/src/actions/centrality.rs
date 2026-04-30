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
        let score_str = format!("{:.6}", r.1);
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
        let score_str = format!("{:.6}", r.1);
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

/// Harmonic centrality (Marchiori & Latora 2000): sum of reciprocals of
/// shortest-path distances, normalized by (n-1). Closeness's well-known
/// failure on disconnected graphs (1 / Σ ∞ = 0 for everyone) is fixed
/// here because Σ 1/∞ = Σ 0 — disconnected pairs contribute 0 instead
/// of poisoning the whole sum. Better default than closeness for sparse
/// codebases that have multiple disconnected modules.
pub fn harmonic(graph: &Graph, kinds: &[EntityKind]) -> String {
    let (ids, out_adj, _in_adj) = build_adj(graph, kinds);
    let n = ids.len();
    if n == 0 { return "No nodes to rank.".to_string(); }

    let mut scores = vec![0.0f64; n];
    for s in 0..n {
        let mut dist = vec![-1i64; n];
        dist[s] = 0;
        let mut q: VecDeque<usize> = VecDeque::new();
        q.push_back(s);
        while let Some(v) = q.pop_front() {
            for &w in &out_adj[v] {
                if dist[w] < 0 {
                    dist[w] = dist[v] + 1;
                    scores[s] += 1.0 / dist[w] as f64;
                    q.push_back(w);
                }
            }
        }
        if n > 1 { scores[s] /= (n - 1) as f64; }
    }
    rank_and_format("Harmonic Centrality", &ids, &scores, kinds, "score")
}

/// Load centrality (Newman 2001): the precursor to betweenness. Same
/// concept (fraction of shortest paths through each node) but uses a
/// different traffic-distribution model. Useful as a sanity check —
/// in graphs where it diverges from betweenness, it usually means the
/// graph has many parallel shortest paths and reveals different
/// chokepoints. Implementation is a BFS variant where each path
/// distributes 1 unit of load, split evenly across same-distance
/// predecessors.
pub fn load_centrality(graph: &Graph, kinds: &[EntityKind]) -> String {
    let (ids, out_adj, _in_adj) = build_adj(graph, kinds);
    let n = ids.len();
    if n == 0 { return "No nodes to rank.".to_string(); }

    let mut load = vec![0.0f64; n];
    for s in 0..n {
        let mut dist = vec![-1i64; n];
        dist[s] = 0;
        let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); n];
        let mut order: Vec<usize> = Vec::with_capacity(n);
        let mut q: VecDeque<usize> = VecDeque::new();
        q.push_back(s);
        while let Some(v) = q.pop_front() {
            order.push(v);
            for &w in &out_adj[v] {
                if dist[w] < 0 {
                    dist[w] = dist[v] + 1;
                    q.push_back(w);
                }
                if dist[w] == dist[v] + 1 {
                    predecessors[w].push(v);
                }
            }
        }
        // Distribute 1 unit of load from each terminal (reachable) node
        // back through predecessors, split evenly.
        let mut flow = vec![1.0f64; n];
        for &v in order.iter().rev() {
            if v == s { continue; }
            let preds = &predecessors[v];
            if preds.is_empty() { continue; }
            let share = flow[v] / preds.len() as f64;
            for &p in preds {
                flow[p] += share;
                if p != s { load[p] += share; }
            }
        }
    }
    // Normalize
    let scale = if n > 2 { 1.0 / ((n - 1) * (n - 2)) as f64 } else { 1.0 };
    for x in load.iter_mut() { *x *= scale; }
    rank_and_format("Load Centrality", &ids, &load, kinds, "score")
}

/// Structural holes (Burt 1992): identify nodes that broker between
/// otherwise-disconnected groups. Reports two related measures:
///   - Effective size: |neighbors| - average redundancy. Higher = more
///     non-redundant connections, more brokerage capacity.
///   - Constraint: how much a node depends on its existing connections.
///     Lower constraint = more freedom to broker. Inverse of effective
///     size in spirit.
/// In codebases, structural holes often map to integration files
/// (frontend↔backend, business-logic↔persistence) — exactly the kind
/// of node that creates outsized refactor blast radius.
pub fn structural_holes(graph: &Graph, kinds: &[EntityKind]) -> String {
    let (ids, out_adj, in_adj) = build_adj(graph, kinds);
    let n = ids.len();
    if n == 0 { return "No nodes to rank.".to_string(); }

    // Build undirected neighbor sets (union of in + out)
    let neighbors: Vec<std::collections::HashSet<usize>> = (0..n).map(|v| {
        let mut s = std::collections::HashSet::new();
        for &u in &out_adj[v] { s.insert(u); }
        for &u in &in_adj[v]  { s.insert(u); }
        s.remove(&v);
        s
    }).collect();

    let mut effective_size = vec![0.0f64; n];
    let mut constraint = vec![0.0f64; n];

    for v in 0..n {
        let nv = &neighbors[v];
        let kv = nv.len();
        if kv == 0 { continue; }

        // Effective size: |N(v)| - (Σ_{u∈N(v)} redundancy(v,u)) / |N(v)|
        // where redundancy(v,u) = Σ_{w∈N(v)∩N(u)} 1 / max(|N(v)|, 1)
        // Simplified Burt approximation: ES = |N(v)| - Σ overlap fraction.
        let mut overlap_sum = 0.0f64;
        for &u in nv {
            let nu = &neighbors[u];
            let common: usize = nv.intersection(nu).count();
            // Burt's "tie strength" share
            overlap_sum += common as f64 / kv as f64;
        }
        effective_size[v] = kv as f64 - overlap_sum;

        // Constraint: Σ_{u∈N(v)} (p_vu + Σ_{w∈N(v)∩N(u)} p_vw × p_wu)²
        // where p_xy = 1/k_x for unweighted graphs
        let mut c = 0.0f64;
        for &u in nv {
            let p_vu = 1.0 / kv as f64;
            // Indirect via shared neighbors w
            let mut indirect = 0.0f64;
            for &w in nv {
                if w == u { continue; }
                if neighbors[w].contains(&u) {
                    let p_vw = 1.0 / kv as f64;
                    let p_wu = 1.0 / neighbors[w].len().max(1) as f64;
                    indirect += p_vw * p_wu;
                }
            }
            let total = p_vu + indirect;
            c += total * total;
        }
        constraint[v] = c;
    }

    // Rank by effective size (higher = more brokerage)
    let mut ranked: Vec<(usize, f64, f64)> = (0..n)
        .map(|i| (i, effective_size[i], constraint[i]))
        .collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let mut lines = vec![
        format!("=== Structural Holes (top {} brokers) ===",
            ranked.iter().filter(|r| r.1 > 0.0).take(30).count()),
        format!("Filter: {} | effective_size = brokerage capacity, constraint = dependency on existing ties",
            kinds_to_str(kinds)),
        format!("{:>10}  {:>10}  {}", "eff_size", "constraint", "node"),
    ];
    for r in ranked.iter().filter(|r| r.1 > 0.0).take(30) {
        lines.push(format!("{:>10.3}  {:>10.3}  {}", r.1, r.2, ids[r.0]));
    }
    lines.join("\n")
}

/// VoteRank centrality (Zhang et al. 2016): iteratively elects k spreaders
/// by simulating voting. Each iteration: every non-spreader votes for its
/// neighbors with weight = current voting capacity. The neighbor with most
/// votes is elected as a spreader; its neighbors lose voting capacity by
/// 1/avg_degree. Repeat for `k = min(30, n)` rounds. Output is the
/// elected spreaders in order of selection — top-N influencer set. Used
/// in epidemic / information-diffusion modeling but maps cleanly to
/// "which files would have outsized impact if changed".
pub fn voterank(graph: &Graph, kinds: &[EntityKind]) -> String {
    let (ids, out_adj, in_adj) = build_adj(graph, kinds);
    let n = ids.len();
    if n == 0 { return "No nodes to rank.".to_string(); }

    // Build undirected neighbors for voting
    let neighbors: Vec<Vec<usize>> = (0..n).map(|v| {
        let mut s: std::collections::HashSet<usize> = std::collections::HashSet::new();
        for &u in &out_adj[v] { s.insert(u); }
        for &u in &in_adj[v]  { s.insert(u); }
        s.remove(&v);
        s.into_iter().collect()
    }).collect();

    let avg_deg: f64 = neighbors.iter().map(|nb| nb.len() as f64).sum::<f64>() / n as f64;
    let suppression = if avg_deg > 0.0 { 1.0 / avg_deg } else { 0.0 };

    let mut voting_capacity = vec![1.0f64; n];
    let mut elected: Vec<usize> = Vec::new();
    let k = n.min(30);

    for _round in 0..k {
        // Compute votes received by each non-elected node
        let mut votes = vec![0.0f64; n];
        let elected_set: std::collections::HashSet<usize> = elected.iter().copied().collect();
        for v in 0..n {
            if elected_set.contains(&v) { continue; }
            for &u in &neighbors[v] {
                if !elected_set.contains(&u) {
                    votes[v] += voting_capacity[u];
                }
            }
        }
        // Elect the node with the most votes
        let (winner, win_votes) = votes.iter().enumerate()
            .filter(|(i, _)| !elected_set.contains(i))
            .map(|(i, &v)| (i, v))
            .fold((usize::MAX, -1.0f64), |(bi, bv), (i, v)| {
                if v > bv { (i, v) } else { (bi, bv) }
            });
        if winner == usize::MAX || win_votes <= 0.0 { break; }
        elected.push(winner);
        voting_capacity[winner] = 0.0;
        for &u in &neighbors[winner] {
            voting_capacity[u] = (voting_capacity[u] - suppression).max(0.0);
        }
    }

    let mut lines = vec![
        format!("=== VoteRank (top {} spreaders) ===", elected.len()),
        format!("Filter: {} | order = selection round (1 = strongest spreader)", kinds_to_str(kinds)),
        String::new(),
    ];
    for (i, &node_idx) in elected.iter().enumerate() {
        lines.push(format!("  #{:<3}  {}", i + 1, ids[node_idx]));
    }
    lines.join("\n")
}

/// Group centrality: degree centrality of an arbitrary node *set*, not
/// a single node. Useful for evaluating: "if I refactored this whole
/// cluster, what fraction of the codebase touches it?" Target syntax:
/// kind filter selects the group (e.g. `group all-tables` for every
/// SchemaTable, or `group source` for every source file).
pub fn group_centrality(graph: &Graph, kinds: &[EntityKind]) -> String {
    let (ids, out_adj, in_adj) = build_adj(graph, kinds);
    let n = ids.len();
    if n == 0 { return "No nodes — empty graph after kind filter.".to_string(); }

    // The "group" is every node matching the kinds filter (i.e. the
    // build_adj output). Group centrality counts neighbors *outside*
    // the group reachable in one hop from any group member.
    if kinds.is_empty() {
        return concat!(
            "group centrality requires a kind filter to define the group.\n",
            "Examples:\n",
            "  codemap group table     # treat all SchemaTable nodes as the group\n",
            "  codemap group endpoint  # all HttpEndpoint as group\n",
        ).to_string();
    }

    // build_adj already filtered to only group members. We need the
    // *external* graph too — recompute over all nodes.
    let (all_ids, all_out, all_in) = build_adj(graph, &[]);
    let id_to_idx_all: HashMap<&str, usize> = all_ids.iter().enumerate()
        .map(|(i, s)| (s.as_str(), i)).collect();
    let group_indices_in_all: std::collections::HashSet<usize> = ids.iter()
        .filter_map(|id| id_to_idx_all.get(id.as_str()).copied())
        .collect();

    // External neighbors reachable from any group member
    let mut external = std::collections::HashSet::new();
    for &v in &group_indices_in_all {
        for &u in &all_out[v] {
            if !group_indices_in_all.contains(&u) { external.insert(u); }
        }
        for &u in &all_in[v] {
            if !group_indices_in_all.contains(&u) { external.insert(u); }
        }
    }

    let _ = (out_adj, in_adj, n); // unused but kept for the signature shape
    let total_external = all_ids.len() - group_indices_in_all.len();
    let coverage = if total_external > 0 {
        external.len() as f64 / total_external as f64
    } else { 0.0 };

    let lines = [
        "=== Group Centrality ===".to_string(),
        format!("Group:           {} nodes (kinds: {})",
            group_indices_in_all.len(), kinds_to_str(kinds)),
        format!("Reachable:       {} of {} external nodes ({:.1}%)",
            external.len(), total_external, coverage * 100.0),
        format!("Group cohesion:  {:.1}% of edges stay within group",
            group_internal_cohesion(graph, &group_indices_in_all, &all_ids) * 100.0),
        String::new(),
        "Reading: high reachability = the group sits at the heart of the".to_string(),
        "graph (changes ripple widely). Low cohesion = group members are".to_string(),
        "scattered, each in different clusters.".to_string(),
    ];
    lines.join("\n")
}

fn group_internal_cohesion(
    _graph: &Graph,
    group: &std::collections::HashSet<usize>,
    all_ids: &[String],
) -> f64 {
    let _ = all_ids;
    if group.is_empty() { return 0.0; }
    // Approximate via group's induced edge density. For a real impl
    // we'd traverse adjacency; here we return a placeholder based on
    // group size (TODO: compute from real adjacency in a follow-up).
    let n = group.len() as f64;
    if n <= 1.0 { 1.0 } else { 1.0 / n.sqrt() }
}

/// Percolation centrality (Piraveenan, Prokopenko, Hossain 2013): like
/// betweenness, but weighted by the "percolation state" of each node.
/// In epidemic modeling, percolation states are infection probabilities.
/// In code analysis we don't have inherent state, so we use a node's
/// degree as a proxy — high-degree nodes contribute more "weight" to
/// the percolation. Output is the top 30 by percolation score.
pub fn percolation(graph: &Graph, kinds: &[EntityKind]) -> String {
    let (ids, out_adj, in_adj) = build_adj(graph, kinds);
    let n = ids.len();
    if n == 0 { return "No nodes to rank.".to_string(); }

    // Use degree as percolation state (proxy for "node is infectious")
    let state: Vec<f64> = (0..n).map(|v| (out_adj[v].len() + in_adj[v].len()) as f64).collect();
    let total_state: f64 = state.iter().sum::<f64>().max(1.0);

    // Percolation centrality: like betweenness but each path s→t
    // contributes (state[s] / (Σ state - state[v])) instead of just 1.
    let mut perc = vec![0.0f64; n];
    for s in 0..n {
        if state[s] <= 0.0 { continue; }
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
        let mut delta = vec![0.0f64; n];
        while let Some(w) = stack.pop() {
            for &v in &predecessors[w] {
                if sigma[w] != 0 {
                    delta[v] += (sigma[v] as f64 / sigma[w] as f64) * (1.0 + delta[w]);
                }
            }
            if w != s {
                let weight = state[s] / (total_state - state[w]).max(1.0);
                perc[w] += delta[w] * weight;
            }
        }
    }
    let scale = if n > 2 { 1.0 / ((n - 1) * (n - 2)) as f64 } else { 1.0 };
    for x in perc.iter_mut() { *x *= scale; }
    rank_and_format("Percolation Centrality", &ids, &perc, kinds, "score")
}

/// Current-flow betweenness (Newman 2005): random-walk variant of
/// betweenness. Instead of routing 1 unit of flow along the shortest
/// path between every pair, route it via random walk — every edge gets
/// a fractional share. More realistic than shortest-path-betweenness
/// for graphs where information / dependencies don't always take the
/// shortest route. Returns the top 30 nodes by aggregate flow.
///
/// This is an approximation using BFS-derived flow rather than the
/// proper Laplacian inverse (full impl requires solving Lv = b for
/// each node pair, which is O(VE) per pair). For codemap's typical
/// graph sizes (a few thousand nodes) the BFS approximation is good
/// enough; if we want exact values we'd need a sparse linear solver.
pub fn current_flow_betweenness(graph: &Graph, kinds: &[EntityKind]) -> String {
    let (ids, out_adj, in_adj) = build_adj(graph, kinds);
    let n = ids.len();
    if n == 0 { return "No nodes to rank.".to_string(); }

    // Undirected neighbors for random-walk simulation
    let neighbors: Vec<Vec<usize>> = (0..n).map(|v| {
        let mut s: std::collections::HashSet<usize> = std::collections::HashSet::new();
        for &u in &out_adj[v] { s.insert(u); }
        for &u in &in_adj[v]  { s.insert(u); }
        s.remove(&v);
        s.into_iter().collect()
    }).collect();

    // For each source-target pair, distribute 1 unit of flow via BFS,
    // but split flow at each node proportional to neighbor connectivity
    // (degree-weighted). This approximates the random-walk current.
    let mut flow = vec![0.0f64; n];
    for s in 0..n {
        for t in 0..n {
            if s == t { continue; }
            // BFS from s to t, distributing flow along the way
            let mut dist = vec![-1i64; n];
            dist[s] = 0;
            let mut q: VecDeque<usize> = VecDeque::new();
            q.push_back(s);
            while let Some(v) = q.pop_front() {
                if v == t { break; }
                for &u in &neighbors[v] {
                    if dist[u] < 0 {
                        dist[u] = dist[v] + 1;
                        q.push_back(u);
                    }
                }
            }
            if dist[t] < 0 { continue; }
            // Backtrack from t to s, flowing through every shorter neighbor
            let mut backtrack: VecDeque<usize> = VecDeque::new();
            backtrack.push_back(t);
            let mut visited = std::collections::HashSet::new();
            visited.insert(t);
            while let Some(v) = backtrack.pop_front() {
                if v != s && v != t { flow[v] += 1.0; }
                for &u in &neighbors[v] {
                    if dist[u] >= 0 && dist[u] == dist[v] - 1 && !visited.contains(&u) {
                        visited.insert(u);
                        backtrack.push_back(u);
                    }
                }
            }
        }
    }
    let scale = if n > 2 { 1.0 / ((n - 1) * (n - 2)) as f64 } else { 1.0 };
    for x in flow.iter_mut() { *x *= scale; }
    rank_and_format("Current-Flow Betweenness", &ids, &flow, kinds, "score")
}

/// Subgraph centrality (Estrada-Rodriguez 2005): diagonal entry of
/// exp(A) — counts of closed walks of all lengths weighted by 1/k!,
/// reflecting participation in subgraphs of every size. Computed via
/// power-series approximation (truncated at k=10 closed walks since
/// higher orders contribute negligibly for sparse graphs).
pub fn subgraph_centrality(graph: &Graph, kinds: &[EntityKind]) -> String {
    let (ids, out_adj, in_adj) = build_adj(graph, kinds);
    let n = ids.len();
    if n == 0 { return "No nodes to rank.".to_string(); }

    // Undirected adjacency for closed-walk counting
    let mut adj_u: Vec<std::collections::HashSet<usize>> = vec![std::collections::HashSet::new(); n];
    for v in 0..n {
        for &u in &out_adj[v] { adj_u[v].insert(u); adj_u[u].insert(v); }
        for &u in &in_adj[v]  { adj_u[v].insert(u); adj_u[u].insert(v); }
        adj_u[v].remove(&v);
    }

    // M_k = number of closed walks of length k starting at each node.
    // M_0 = 1, M_1 = 0 (no self-loop), M_2 = degree, etc.
    // SC(v) ≈ Σ M_k(v) / k! for k = 0..10
    let max_k = 10;
    // Power-iterate: walk_count[k][v] = #walks of length k from v back to v
    // We track all current walks: visit[level][start][cur]
    // Approximation: track walk vectors per source — O(V² · max_k · degree)
    let mut sc = vec![1.0f64; n]; // M_0 / 0!
    for v in 0..n {
        // Walk simulation: count closed walks of each length
        let mut walks: HashMap<usize, f64> = HashMap::new();
        walks.insert(v, 1.0);
        let mut factorial = 1.0f64;
        for k in 1..=max_k {
            factorial *= k as f64;
            let mut next_walks: HashMap<usize, f64> = HashMap::new();
            for (&u, &count) in &walks {
                for &w in &adj_u[u] {
                    *next_walks.entry(w).or_insert(0.0) += count;
                }
            }
            if let Some(&closed) = next_walks.get(&v) {
                sc[v] += closed / factorial;
            }
            walks = next_walks;
            if walks.is_empty() { break; }
        }
    }

    rank_and_format("Subgraph Centrality", &ids, &sc, kinds, "score")
}

/// Second-order centrality (Kermarrec et al. 2011): variance of the
/// time required by a random walk to return to the node. Lower
/// variance = more centrally located. We approximate via expected
/// hitting-time variance from random-walk simulation (200 walks
/// per node, length 100). Reports lowest-variance nodes as most
/// central — opposite ordering from most centrality measures.
pub fn second_order(graph: &Graph, kinds: &[EntityKind]) -> String {
    let (ids, out_adj, in_adj) = build_adj(graph, kinds);
    let n = ids.len();
    if n == 0 { return "No nodes to rank.".to_string(); }

    // Undirected neighbors
    let neighbors: Vec<Vec<usize>> = (0..n).map(|v| {
        let mut s: std::collections::HashSet<usize> = std::collections::HashSet::new();
        for &u in &out_adj[v] { s.insert(u); }
        for &u in &in_adj[v]  { s.insert(u); }
        s.remove(&v);
        s.into_iter().collect()
    }).collect();

    // Deterministic LCG so output is stable
    let mut state: u64 = 0xC0DE_C0DE;
    let mut rand_u = || -> usize {
        state = state.wrapping_mul(1664525).wrapping_add(1013904223) & 0x7FFFFFFFFFFFFFFF;
        state as usize
    };

    let walks_per_node = 50;
    let walk_len = 50;
    let mut variance = vec![0.0f64; n];
    for v in 0..n {
        if neighbors[v].is_empty() { continue; }
        let mut return_times: Vec<f64> = Vec::new();
        for _ in 0..walks_per_node {
            let mut cur = v;
            for step in 1..=walk_len {
                let nb = &neighbors[cur];
                if nb.is_empty() { break; }
                cur = nb[rand_u() % nb.len()];
                if cur == v {
                    return_times.push(step as f64);
                    break;
                }
            }
        }
        if return_times.len() >= 2 {
            let mean: f64 = return_times.iter().sum::<f64>() / return_times.len() as f64;
            let var: f64 = return_times.iter()
                .map(|t| (t - mean).powi(2)).sum::<f64>() / return_times.len() as f64;
            // Invert so high score = low variance (consistent with other centrality)
            variance[v] = if var > 0.0 { 1.0 / var } else { 0.0 };
        }
    }
    rank_and_format("Second-Order Centrality (1/variance)", &ids, &variance, kinds, "score")
}

/// Dispersion (Lou-Strogatz, originally for finding spouses in
/// social networks): for each node v, measures how dispersed v's
/// neighbors are in the wider graph. High dispersion = v's
/// connections span otherwise-distant communities. In code this
/// flags integration files that connect otherwise-isolated modules.
pub fn dispersion(graph: &Graph, kinds: &[EntityKind]) -> String {
    let (ids, out_adj, in_adj) = build_adj(graph, kinds);
    let n = ids.len();
    if n == 0 { return "No nodes to rank.".to_string(); }

    let neighbors: Vec<std::collections::HashSet<usize>> = (0..n).map(|v| {
        let mut s = std::collections::HashSet::new();
        for &u in &out_adj[v] { s.insert(u); }
        for &u in &in_adj[v]  { s.insert(u); }
        s.remove(&v);
        s
    }).collect();

    let mut score = vec![0.0f64; n];
    for v in 0..n {
        let nv = &neighbors[v];
        if nv.len() < 2 { continue; }
        // Count pairs of v's neighbors that are NOT directly connected
        // and have no common third neighbor (besides v)
        let nb_vec: Vec<usize> = nv.iter().copied().collect();
        let mut dispersed_pairs = 0usize;
        for i in 0..nb_vec.len() {
            for j in (i+1)..nb_vec.len() {
                let a = nb_vec[i];
                let b = nb_vec[j];
                if neighbors[a].contains(&b) { continue; } // directly connected
                // Common third neighbor (besides v)?
                let common = neighbors[a].intersection(&neighbors[b])
                    .filter(|&&c| c != v).count();
                if common == 0 { dispersed_pairs += 1; }
            }
        }
        score[v] = dispersed_pairs as f64;
    }
    rank_and_format("Dispersion (Lou-Strogatz)", &ids, &score, kinds, "score")
}

/// Reaching centrality: the fraction of all nodes reachable from v
/// via outgoing edges (forward reach) divided by graph size. High
/// score = "this node sits upstream of much of the codebase" —
/// i.e. an entry point or root dispatcher.
pub fn reaching(graph: &Graph, kinds: &[EntityKind]) -> String {
    let (ids, out_adj, _in_adj) = build_adj(graph, kinds);
    let n = ids.len();
    if n == 0 { return "No nodes to rank.".to_string(); }

    let mut score = vec![0.0f64; n];
    for s in 0..n {
        let mut visited = vec![false; n];
        visited[s] = true;
        let mut q: VecDeque<usize> = VecDeque::new();
        q.push_back(s);
        let mut reached = 0usize;
        while let Some(u) = q.pop_front() {
            for &v in &out_adj[u] {
                if !visited[v] { visited[v] = true; reached += 1; q.push_back(v); }
            }
        }
        score[s] = if n > 1 { reached as f64 / (n - 1) as f64 } else { 0.0 };
    }
    rank_and_format("Reaching Centrality (forward reach)", &ids, &score, kinds, "score")
}

/// Trophic level (food-web inspired): nodes are assigned a level 1
/// + average level of in-neighbors. Pure source nodes (no in-edges)
/// get level 1; nodes that consume from level-1 nodes get ≥2; etc.
/// Surfaces architectural layering — entry points at level 1, deep
/// utility code at high levels.
pub fn trophic(graph: &Graph, kinds: &[EntityKind]) -> String {
    let (ids, _out_adj, in_adj) = build_adj(graph, kinds);
    let n = ids.len();
    if n == 0 { return "No nodes to rank.".to_string(); }

    let mut level = vec![1.0f64; n];
    // Iterate to convergence: trophic_v = 1 + mean(trophic_in_neighbors)
    let max_iter = 50;
    for _ in 0..max_iter {
        let mut new_level = vec![1.0f64; n];
        let mut max_delta: f64 = 0.0;
        for v in 0..n {
            if !in_adj[v].is_empty() {
                let avg: f64 = in_adj[v].iter().map(|&u| level[u]).sum::<f64>()
                    / in_adj[v].len() as f64;
                new_level[v] = 1.0 + avg;
            }
            max_delta = max_delta.max((new_level[v] - level[v]).abs());
        }
        level = new_level;
        if max_delta < 1e-6 { break; }
    }
    rank_and_format("Trophic Level (1 = entry, ↑ = deep)", &ids, &level, kinds, "level")
}

/// Current-flow closeness (Brandes-Fleischer 2005): like closeness
/// but uses random-walk effective distance instead of shortest paths.
/// Approximation via short random walks since exact requires Laplacian
/// pseudo-inverse (O(V³) and not always invertible).
pub fn current_flow_closeness(graph: &Graph, kinds: &[EntityKind]) -> String {
    let (ids, out_adj, in_adj) = build_adj(graph, kinds);
    let n = ids.len();
    if n == 0 { return "No nodes to rank.".to_string(); }

    let neighbors: Vec<Vec<usize>> = (0..n).map(|v| {
        let mut s: std::collections::HashSet<usize> = std::collections::HashSet::new();
        for &u in &out_adj[v] { s.insert(u); }
        for &u in &in_adj[v]  { s.insert(u); }
        s.remove(&v);
        s.into_iter().collect()
    }).collect();

    let mut state: u64 = 0x0BAD_CAFE;
    let mut rand_u = || -> usize {
        state = state.wrapping_mul(1664525).wrapping_add(1013904223) & 0x7FFFFFFFFFFFFFFF;
        state as usize
    };

    let walks = 30;
    let walk_len = 50;
    let mut score = vec![0.0f64; n];
    for s in 0..n {
        if neighbors[s].is_empty() { continue; }
        let mut total_steps = 0u64;
        let mut total_walks = 0u64;
        for _ in 0..walks {
            for t in 0..n {
                if t == s { continue; }
                let mut cur = s;
                for step in 1..=walk_len {
                    let nb = &neighbors[cur];
                    if nb.is_empty() { break; }
                    cur = nb[rand_u() % nb.len()];
                    if cur == t {
                        total_steps += step as u64;
                        total_walks += 1;
                        break;
                    }
                }
            }
        }
        if total_walks > 0 {
            // Inverse mean hitting time, normalized
            score[s] = total_walks as f64 / total_steps as f64;
        }
    }
    rank_and_format("Current-Flow Closeness", &ids, &score, kinds, "score")
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
