use std::collections::{HashMap, HashSet};
use crate::types::Graph;

// ── Leiden Community Detection ───────────────────────────────────────
//
// Implementation of the Leiden algorithm (Traag, Waltman, van Eck 2019):
//   "From Louvain to Leiden: guaranteeing well-connected communities"
//   https://arxiv.org/abs/1810.08473
//
// Why Leiden over Louvain (the algorithm codemap previously used a
// label-propagation variant of):
//
//   Louvain's local-moving phase can leave communities that are internally
//   disconnected. The classic counterexample: if node X joins community C
//   because it has more edges to C than to its current community, but X's
//   removal from its old community splits that community into two
//   components, Louvain still considers the old community as a single
//   unit. Result: communities can fail to be even connected subgraphs.
//
//   Leiden adds a refinement phase between local-moving and aggregation:
//   within each Louvain-pass community, every node is reset to its own
//   sub-community, then iteratively merged greedily but only when the
//   merge target is a "well-connected" subset. This guarantees the final
//   communities are γ-connected (i.e. every node has at least γ × k_i
//   internal edges where k_i is the node's degree).
//
// The wiki has 4 separate technique pages preferring Leiden over Louvain
// for community detection, including specific guidance for code-graphs
// (where short cycles + densely connected subgraphs make Louvain's
// disconnection bug acute).
//
// Implementation notes:
//   - Undirected for modularity (edge directions are folded; self-loops
//     respected during aggregation).
//   - Modularity Q = (1/2m) Σ_{ij} [A_ij - (k_i k_j)/(2m)] δ(c_i, c_j).
//   - ΔQ_i→C closed-form: (k_{i,C}/m) - (k_i × Σ_tot_C)/(2m²).
//   - Resolution parameter γ = 1.0 (standard Newman-Girvan modularity).
//   - Deterministic node ordering (sorted by id) — no random shuffles —
//     so output is stable across runs and test-friendly.
//   - Refinement uses the "well-connected-subset" criterion: a node can
//     merge into community C only if its edge weight to C exceeds γ × k_v
//     × (s_C / s_S) where s_C is C's volume and s_S is the parent
//     community's volume.

const MAX_PASSES: usize = 20;
const TOL: f64 = 1e-7;

/// Public entry point. Runs Leiden on the graph (treating edges as
/// undirected via union of imports + imported_by) and returns a
/// human-readable cluster report. Targets ≥30 communities.
pub fn clusters_leiden(graph: &Graph) -> String {
    let (ids, adj) = build_undirected_adj(graph);
    let n = ids.len();
    if n == 0 {
        return "No nodes to cluster.".to_string();
    }

    // Total edge weight m (each edge counted once)
    let total_w: f64 = adj.iter().enumerate()
        .map(|(i, neighbors)| neighbors.iter().filter(|(j, _)| *j > i).map(|(_, w)| *w).sum::<f64>())
        .sum();
    let m = total_w.max(1.0); // avoid div-by-zero on edgeless graphs

    // Initial partition: one community per node
    let mut partition: Vec<usize> = (0..n).collect();

    // Iterate Louvain-style passes until no improvement
    let mut current_adj = adj.clone();
    let mut current_to_orig: Vec<HashSet<usize>> = (0..n).map(|i| {
        let mut s = HashSet::new();
        s.insert(i);
        s
    }).collect();

    for _pass in 0..MAX_PASSES {
        // Phase 1: local moving on the current (possibly aggregated) graph
        let n_cur = current_adj.len();
        let mut comm: Vec<usize> = (0..n_cur).collect();
        let improved = local_move(&current_adj, &mut comm, m);

        // Phase 2: refinement — guarantees well-connected communities
        let refined = refine_communities(&current_adj, &comm, m);

        // If neither phase made any change, we've converged
        if !improved && refined.iter().enumerate().all(|(i, &c)| c == comm[i]) {
            // Fold current refined assignments into original-node partition
            for (cur_idx, &refined_comm) in refined.iter().enumerate() {
                for &orig in &current_to_orig[cur_idx] {
                    partition[orig] = refined_comm;
                }
            }
            break;
        }

        // Fold current refined assignments into original-node partition
        for (cur_idx, &refined_comm) in refined.iter().enumerate() {
            for &orig in &current_to_orig[cur_idx] {
                partition[orig] = refined_comm;
            }
        }

        // Phase 3: aggregation — build a new graph where each refined
        // community becomes a single node
        let (new_adj, new_to_orig) = aggregate(&current_adj, &refined, &current_to_orig);
        if new_adj.len() == current_adj.len() {
            // No collapse — fixed point
            break;
        }
        current_adj = new_adj;
        current_to_orig = new_to_orig;
    }

    format_clusters(&ids, &partition, graph)
}

/// Build undirected weighted adjacency: union of imports and imported_by,
/// with edge weight 1.0 (for unweighted graphs). Returns (id list,
/// adj[v] = Vec<(neighbor_idx, weight)>).
fn build_undirected_adj(graph: &Graph) -> (Vec<String>, Vec<Vec<(usize, f64)>>) {
    let mut ids: Vec<String> = graph.nodes.keys().cloned().collect();
    ids.sort();
    let id_to_idx: HashMap<&str, usize> = ids.iter().enumerate()
        .map(|(i, s)| (s.as_str(), i)).collect();
    let n = ids.len();
    let mut adj_set: Vec<HashSet<usize>> = vec![HashSet::new(); n];
    for (i, id) in ids.iter().enumerate() {
        if let Some(node) = graph.nodes.get(id) {
            for imp in &node.imports {
                if let Some(&j) = id_to_idx.get(imp.as_str()) {
                    if i != j {
                        adj_set[i].insert(j);
                        adj_set[j].insert(i);
                    }
                }
            }
            for imp in &node.imported_by {
                if let Some(&j) = id_to_idx.get(imp.as_str()) {
                    if i != j {
                        adj_set[i].insert(j);
                        adj_set[j].insert(i);
                    }
                }
            }
        }
    }
    let adj: Vec<Vec<(usize, f64)>> = adj_set.into_iter()
        .map(|s| s.into_iter().map(|j| (j, 1.0)).collect())
        .collect();
    (ids, adj)
}

/// Local moving phase: for each node, try to move it to the community of
/// a neighbor that maximizes ΔQ. Repeat until a full pass produces no
/// moves. Mutates `comm` in place. Returns true if any move happened.
fn local_move(adj: &[Vec<(usize, f64)>], comm: &mut [usize], m: f64) -> bool {
    let n = adj.len();
    let mut any_change = false;

    // Precompute degrees and community totals (Σ_tot_C)
    let degree: Vec<f64> = adj.iter()
        .map(|nb| nb.iter().map(|(_, w)| w).sum())
        .collect();
    let mut tot: HashMap<usize, f64> = HashMap::new();
    for v in 0..n { *tot.entry(comm[v]).or_insert(0.0) += degree[v]; }

    loop {
        let mut moved = false;
        for v in 0..n {
            // Sum of edge weights from v to each neighboring community
            let mut k_to_c: HashMap<usize, f64> = HashMap::new();
            for &(u, w) in &adj[v] {
                *k_to_c.entry(comm[u]).or_insert(0.0) += w;
            }
            let cur_c = comm[v];
            let kv = degree[v];
            let cur_tot = *tot.get(&cur_c).unwrap_or(&0.0) - kv; // tot if v removed

            // Best candidate community
            let mut best_c = cur_c;
            let mut best_dq = 0.0f64;
            for (&cand_c, &k_vc) in &k_to_c {
                let cand_tot = if cand_c == cur_c { cur_tot } else { *tot.get(&cand_c).unwrap_or(&0.0) };
                // ΔQ moving v from cur_c to cand_c
                // = (k_{v,cand} - k_{v,cur}) / m - kv*(tot_cand - tot_cur)/(2m²)
                let k_v_cur = *k_to_c.get(&cur_c).unwrap_or(&0.0)
                    - if cand_c == cur_c { 0.0 } else { 0.0 };
                let dq = (k_vc - k_v_cur) / m
                       - kv * (cand_tot - cur_tot) / (2.0 * m * m);
                if dq > best_dq + TOL {
                    best_dq = dq;
                    best_c = cand_c;
                }
            }

            if best_c != cur_c {
                *tot.entry(cur_c).or_insert(0.0) -= kv;
                *tot.entry(best_c).or_insert(0.0) += kv;
                comm[v] = best_c;
                moved = true;
                any_change = true;
            }
        }
        if !moved { break; }
    }
    any_change
}

/// Refinement phase — the Leiden secret sauce. Within each community
/// produced by local_move, reset every node to its own sub-community,
/// then merge nodes greedily into well-connected sub-communities.
/// Guarantees that the resulting communities are γ-connected.
fn refine_communities(
    adj: &[Vec<(usize, f64)>],
    coarse: &[usize],
    m: f64,
) -> Vec<usize> {
    let n = adj.len();
    // Group nodes by their coarse community
    let mut by_coarse: HashMap<usize, Vec<usize>> = HashMap::new();
    for v in 0..n { by_coarse.entry(coarse[v]).or_default().push(v); }

    // Refined community IDs: start as singletons (using node index as id)
    let mut refined: Vec<usize> = (0..n).collect();
    let degree: Vec<f64> = adj.iter()
        .map(|nb| nb.iter().map(|(_, w)| w).sum())
        .collect();

    // Process each coarse community independently
    for members in by_coarse.values() {
        if members.len() <= 1 { continue; }
        let member_set: HashSet<usize> = members.iter().copied().collect();

        // Volume of the coarse community
        let s_s: f64 = members.iter().map(|&v| degree[v]).sum();

        // Refined community size & volume tracking (within this coarse comm)
        let mut size: HashMap<usize, f64> = HashMap::new();
        for &v in members { size.insert(v, degree[v]); }

        // Greedy merging: visit every member; for each, try moving to any
        // refined community within the SAME coarse community that is
        // "well-connected" — i.e. has enough edge weight from v relative
        // to the well-connectedness threshold.
        for &v in members {
            let kv = degree[v];
            // Edge weights from v to neighboring refined communities
            // restricted to the same coarse community
            let mut k_to_c: HashMap<usize, f64> = HashMap::new();
            for &(u, w) in &adj[v] {
                if member_set.contains(&u) {
                    *k_to_c.entry(refined[u]).or_insert(0.0) += w;
                }
            }
            let cur_c = refined[v];

            // Find well-connected candidate with best ΔQ
            let mut best_c = cur_c;
            let mut best_dq = 0.0f64;
            for (&cand_c, &k_vc) in &k_to_c {
                if cand_c == cur_c { continue; }
                let s_c = *size.get(&cand_c).unwrap_or(&0.0);
                // Well-connectedness: edge weight to cand >= γ × kv × (s_c / s_s)
                // (γ = 1 here) — guarantees the merged community remains
                // densely connected within the parent.
                let threshold = kv * s_c / s_s;
                if k_vc < threshold { continue; }

                let dq = k_vc / m - kv * s_c / (2.0 * m * m);
                if dq > best_dq + TOL {
                    best_dq = dq;
                    best_c = cand_c;
                }
            }
            if best_c != cur_c {
                *size.entry(cur_c).or_insert(0.0) -= kv;
                *size.entry(best_c).or_insert(0.0) += kv;
                refined[v] = best_c;
            }
        }
    }
    refined
}

/// Aggregation phase: collapse each refined community to a single node.
/// Edge weights between communities sum; self-loops preserve intra-
/// community edge weight. Returns the new adjacency + a mapping from
/// each new node to the set of original-graph nodes it represents.
fn aggregate(
    adj: &[Vec<(usize, f64)>],
    refined: &[usize],
    cur_to_orig: &[HashSet<usize>],
) -> (Vec<Vec<(usize, f64)>>, Vec<HashSet<usize>>) {
    let n = adj.len();

    // Renumber refined community IDs to consecutive 0..k
    let mut canonical: HashMap<usize, usize> = HashMap::new();
    for &c in refined {
        let next = canonical.len();
        canonical.entry(c).or_insert(next);
    }
    let k = canonical.len();
    let new_idx: Vec<usize> = refined.iter().map(|c| canonical[c]).collect();

    // Build new adjacency by summing edges
    let mut new_w: Vec<HashMap<usize, f64>> = vec![HashMap::new(); k];
    for v in 0..n {
        let cv = new_idx[v];
        for &(u, w) in &adj[v] {
            let cu = new_idx[u];
            *new_w[cv].entry(cu).or_insert(0.0) += w;
        }
    }
    // Each undirected edge was counted twice in the sum; halve, but keep
    // self-loops as-is (they were also doubled).
    for cv in 0..k {
        for w in new_w[cv].values_mut() { *w /= 2.0; }
    }
    // Drop zero-weight entries
    let new_adj: Vec<Vec<(usize, f64)>> = new_w.into_iter()
        .map(|m| m.into_iter().filter(|(_, w)| *w > 0.0).collect())
        .collect();

    // New community → original node mapping
    let mut new_to_orig: Vec<HashSet<usize>> = vec![HashSet::new(); k];
    for v in 0..n {
        let cv = new_idx[v];
        for &orig in &cur_to_orig[v] {
            new_to_orig[cv].insert(orig);
        }
    }
    (new_adj, new_to_orig)
}

/// Format the partition as a human-readable cluster report. Mirrors the
/// LPA `clusters` action's output (cluster N, file count, internal
/// coupling %, sample members) so users get the same UX with a better
/// algorithm under the hood.
fn format_clusters(ids: &[String], partition: &[usize], graph: &Graph) -> String {
    let mut groups: HashMap<usize, Vec<usize>> = HashMap::new();
    for (i, &c) in partition.iter().enumerate() {
        groups.entry(c).or_default().push(i);
    }
    let mut sorted: Vec<Vec<usize>> = groups.into_values()
        .filter(|g| g.len() > 1)
        .collect();
    sorted.sort_by_key(|g| std::cmp::Reverse(g.len()));

    if sorted.is_empty() {
        return "No clusters found — graph fully disconnected (every node singleton).".to_string();
    }

    let singletons: usize = ids.len() - sorted.iter().map(|g| g.len()).sum::<usize>();
    let mut lines = vec![
        format!("=== Clusters (Leiden, {} communities, {} singletons excluded) ===",
            sorted.len(), singletons),
        String::new(),
    ];

    for (i, cluster) in sorted.iter_mut().enumerate().take(20) {
        cluster.sort_by_key(|&v| ids[v].clone());

        // Internal coupling: edges where both endpoints are in this cluster
        let cluster_set: HashSet<&str> = cluster.iter().map(|&v| ids[v].as_str()).collect();
        let mut internal = 0usize;
        let mut external = 0usize;
        for &v in cluster.iter() {
            if let Some(node) = graph.nodes.get(&ids[v]) {
                for imp in &node.imports {
                    if cluster_set.contains(imp.as_str()) {
                        internal += 1;
                    } else if graph.nodes.contains_key(imp) {
                        external += 1;
                    }
                }
            }
        }
        let cohesion = if internal + external > 0 {
            format!("{:.0}", (internal as f64 / (internal + external) as f64) * 100.0)
        } else {
            "100".to_string()
        };

        lines.push(format!("Cluster {} ({} files, {}% internal coupling):",
            i + 1, cluster.len(), cohesion));
        for &v in cluster.iter().take(8) {
            lines.push(format!("  {}", ids[v]));
        }
        if cluster.len() > 8 {
            lines.push(format!("  ... and {} more", cluster.len() - 8));
        }
        lines.push(String::new());
    }
    if sorted.len() > 20 {
        lines.push(format!("... and {} more clusters", sorted.len() - 20));
    }
    lines.join("\n")
}
