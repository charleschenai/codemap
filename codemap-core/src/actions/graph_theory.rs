use std::collections::{HashMap, HashSet, VecDeque};
use crate::types::Graph;

/// PageRank: 20 iterations, damping=0.85, dangling node redistribution. Top 30, score*1000 with 2 decimal places.
pub fn pagerank(graph: &Graph) -> String {
    let d: f64 = 0.85;
    let iterations = 20;
    let n = graph.nodes.len();
    if n == 0 {
        return "No files to rank.".to_string();
    }

    let ids: Vec<String> = graph.nodes.keys().cloned().collect();
    let mut scores: HashMap<String, f64> = HashMap::new();
    let init = 1.0 / n as f64;
    for id in &ids {
        scores.insert(id.clone(), init);
    }

    for _ in 0..iterations {
        let mut new_scores: HashMap<String, f64> = HashMap::new();

        // Collect dangling node rank mass
        let mut dangling_sum: f64 = 0.0;
        for (id, node) in &graph.nodes {
            let local_imports: Vec<&String> = node.imports.iter()
                .filter(|i| graph.nodes.contains_key(*i))
                .collect();
            if local_imports.is_empty() {
                dangling_sum += scores.get(id).copied().unwrap_or(0.0);
            }
        }

        // Base score: teleportation + dangling redistribution
        let base = (1.0 - d) / n as f64 + d * dangling_sum / n as f64;
        for id in &ids {
            new_scores.insert(id.clone(), base);
        }

        for (id, node) in &graph.nodes {
            let local_imports: Vec<&String> = node.imports.iter()
                .filter(|i| graph.nodes.contains_key(*i))
                .collect();
            if local_imports.is_empty() { continue; }
            let share = scores.get(id).copied().unwrap_or(0.0) / local_imports.len() as f64;
            for imp in local_imports {
                *new_scores.entry(imp.clone()).or_insert(0.0) += d * share;
            }
        }
        scores = new_scores;
    }

    let mut ranked: Vec<(String, f64)> = ids.iter()
        .map(|id| (id.clone(), scores.get(id).copied().unwrap_or(0.0)))
        .collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let top: Vec<&(String, f64)> = ranked.iter().take(30).collect();
    let mut lines = vec![
        format!("=== PageRank (top {} most important files) ===", top.len()),
        String::new(),
    ];
    for r in &top {
        // padStart(7) in TS = right-align in 7 chars
        let score_str = format!("{:.2}", r.1 * 1000.0);
        lines.push(format!("  {:>7} rank  {}", score_str, r.0));
    }
    lines.join("\n")
}

/// HITS algorithm: 20 iterations, Jacobi update, L2 normalize. Top 20 hubs + top 20 authorities.
pub fn hubs(graph: &Graph) -> String {
    let iterations = 20;
    let ids: Vec<String> = graph.nodes.keys().cloned().collect();
    let mut hub_scores: HashMap<String, f64> = HashMap::new();
    let mut auth_scores: HashMap<String, f64> = HashMap::new();
    for id in &ids {
        hub_scores.insert(id.clone(), 1.0);
        auth_scores.insert(id.clone(), 1.0);
    }

    for _ in 0..iterations {
        // Authority = sum of hub scores of nodes pointing to it (from OLD hub scores)
        let mut new_auth: HashMap<String, f64> = HashMap::new();
        for id in &ids {
            new_auth.insert(id.clone(), 0.0);
        }
        for (id, node) in &graph.nodes {
            for imp in &node.imports {
                if graph.nodes.contains_key(imp) {
                    *new_auth.entry(imp.clone()).or_insert(0.0) +=
                        hub_scores.get(id).copied().unwrap_or(0.0);
                }
            }
        }

        // Hub = sum of authority scores of nodes it points to (from OLD auth scores — Jacobi)
        let mut new_hub: HashMap<String, f64> = HashMap::new();
        for (id, node) in &graph.nodes {
            let mut h: f64 = 0.0;
            for imp in &node.imports {
                if graph.nodes.contains_key(imp) {
                    h += auth_scores.get(imp).copied().unwrap_or(0.0); // use OLD authScores
                }
            }
            new_hub.insert(id.clone(), h);
        }

        // Normalize (L2)
        let hub_norm: f64 = {
            let s: f64 = new_hub.values().map(|v| v * v).sum();
            let n = s.sqrt();
            if n == 0.0 { 1.0 } else { n }
        };
        let auth_norm: f64 = {
            let s: f64 = new_auth.values().map(|v| v * v).sum();
            let n = s.sqrt();
            if n == 0.0 { 1.0 } else { n }
        };
        for id in &ids {
            if let Some(v) = new_hub.get_mut(id) { *v /= hub_norm; }
            if let Some(v) = new_auth.get_mut(id) { *v /= auth_norm; }
        }
        hub_scores = new_hub;
        auth_scores = new_auth;
    }

    let mut top_hubs: Vec<(String, f64)> = ids.iter()
        .map(|id| (id.clone(), hub_scores.get(id).copied().unwrap_or(0.0)))
        .collect();
    top_hubs.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let top_hubs: Vec<&(String, f64)> = top_hubs.iter().take(20).collect();

    let mut top_auth: Vec<(String, f64)> = ids.iter()
        .map(|id| (id.clone(), auth_scores.get(id).copied().unwrap_or(0.0)))
        .collect();
    top_auth.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let top_auth: Vec<&(String, f64)> = top_auth.iter().take(20).collect();

    let mut lines = vec![
        "=== Hubs (orchestrators \u{2014} import many things) ===".to_string(),
        String::new(),
    ];
    for h in &top_hubs {
        if h.1 < 0.001 { break; }
        let score_str = format!("{:.2}", h.1 * 100.0);
        lines.push(format!("  {:>7}  {}", score_str, h.0));
    }
    lines.push(String::new());
    lines.push("=== Authorities (core \u{2014} everyone imports them) ===".to_string());
    lines.push(String::new());
    for a in &top_auth {
        if a.1 < 0.001 { break; }
        let score_str = format!("{:.2}", a.1 * 100.0);
        lines.push(format!("  {:>7}  {}", score_str, a.0));
    }
    lines.join("\n")
}

/// Iterative Tarjan's articulation points on undirected adjacency. Ranked by connections.
pub fn bridges(graph: &Graph) -> String {
    let ids: Vec<String> = graph.nodes.keys().cloned().collect();
    let mut disc: HashMap<String, usize> = HashMap::new();
    let mut low: HashMap<String, usize> = HashMap::new();
    let mut parent: HashMap<String, Option<String>> = HashMap::new();
    let mut articulation_points: HashSet<String> = HashSet::new();
    let mut timer: usize = 0;

    // Build undirected adjacency
    let mut adj: HashMap<String, HashSet<String>> = HashMap::new();
    for (id, node) in &graph.nodes {
        adj.entry(id.clone()).or_default();
        for imp in &node.imports {
            if graph.nodes.contains_key(imp) {
                adj.entry(id.clone()).or_default().insert(imp.clone());
                adj.entry(imp.clone()).or_default().insert(id.clone());
            }
        }
    }

    for start_id in &ids {
        if disc.contains_key(start_id) { continue; }

        struct Frame {
            id: String,
            neighbors: Vec<String>,
            neighbor_idx: usize,
            child_count: usize,
        }

        disc.insert(start_id.clone(), timer);
        low.insert(start_id.clone(), timer);
        timer += 1;
        parent.insert(start_id.clone(), None);
        let neighbors: Vec<String> = adj.get(start_id).map(|s| s.iter().cloned().collect()).unwrap_or_default();
        let mut stack: Vec<Frame> = vec![Frame { id: start_id.clone(), neighbors, neighbor_idx: 0, child_count: 0 }];

        while !stack.is_empty() {
            let stack_len = stack.len();
            let frame = &mut stack[stack_len - 1];

            if frame.neighbor_idx < frame.neighbors.len() {
                let v = frame.neighbors[frame.neighbor_idx].clone();
                frame.neighbor_idx += 1;

                if !disc.contains_key(&v) {
                    parent.insert(v.clone(), Some(frame.id.clone()));
                    disc.insert(v.clone(), timer);
                    low.insert(v.clone(), timer);
                    timer += 1;
                    frame.child_count += 1;
                    let v_neighbors: Vec<String> = adj.get(&v).map(|s| s.iter().cloned().collect()).unwrap_or_default();
                    stack.push(Frame { id: v.clone(), neighbors: v_neighbors, neighbor_idx: 0, child_count: 0 });
                } else if parent.get(&frame.id).and_then(|p| p.as_ref()) != Some(&v) {
                    let frame_low = low.get(&frame.id).copied().unwrap_or(0);
                    let v_disc = disc.get(&v).copied().unwrap_or(0);
                    if v_disc < frame_low {
                        low.insert(frame.id.clone(), v_disc);
                    }
                }
            } else {
                let popped_id = frame.id.clone();
                let popped_child_count = frame.child_count;
                let popped_low = low.get(&popped_id).copied().unwrap_or(0);
                stack.pop();

                if let Some(parent_frame) = stack.last() {
                    let parent_id = &parent_frame.id;
                    let parent_low = low.get(parent_id).copied().unwrap_or(0);
                    if popped_low < parent_low {
                        low.insert(parent_id.clone(), popped_low);
                    }

                    let parent_parent = parent.get(parent_id).and_then(|p| p.as_ref());
                    let parent_disc = disc.get(parent_id).copied().unwrap_or(0);
                    if parent_parent.is_some() && popped_low >= parent_disc {
                        articulation_points.insert(parent_id.clone());
                    }
                } else {
                    // Root node
                    if popped_child_count > 1 {
                        articulation_points.insert(popped_id);
                    }
                }
            }
        }
    }

    if articulation_points.is_empty() {
        return "No articulation points found \u{2014} the graph stays connected if any single file is removed.".to_string();
    }

    let mut ranked: Vec<(String, usize)> = articulation_points.iter().map(|id| {
        let node = graph.nodes.get(id).unwrap();
        (id.clone(), node.imports.len() + node.imported_by.len())
    }).collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1));

    let mut lines = vec![
        format!("=== Articulation Points ({} cut vertices) ===", ranked.len()),
        "Removing any of these disconnects parts of the graph:".to_string(),
        String::new(),
    ];
    for r in ranked.iter().take(30) {
        lines.push(format!("  {:>4} connections  {}", r.1, r.0));
    }
    if ranked.len() > 30 {
        lines.push(format!("  ... and {} more", ranked.len() - 30));
    }
    lines.join("\n")
}

/// Label propagation, seeded PRNG (LCG), Fisher-Yates shuffle, 15 iterations.
/// Group by label, filter singletons, show cohesion %.
pub fn clusters(graph: &Graph) -> String {
    let mut labels: HashMap<String, String> = HashMap::new();
    let ids: Vec<String> = graph.nodes.keys().cloned().collect();
    for id in &ids {
        labels.insert(id.clone(), id.clone());
    }

    // Build undirected adjacency (using Sets to prevent duplicate edges)
    let mut adj_sets: HashMap<String, HashSet<String>> = HashMap::new();
    for (id, node) in &graph.nodes {
        adj_sets.entry(id.clone()).or_default();
        for imp in &node.imports {
            if graph.nodes.contains_key(imp) {
                adj_sets.entry(id.clone()).or_default().insert(imp.clone());
                adj_sets.entry(imp.clone()).or_default().insert(id.clone());
            }
        }
    }
    let adj: HashMap<String, Vec<String>> = adj_sets.into_iter()
        .map(|(id, s)| (id, s.into_iter().collect()))
        .collect();

    // Seeded PRNG (LCG)
    let mut seed: u64 = (ids.len() as u64).wrapping_mul(2654435761);
    let mut next_rand = || -> f64 {
        seed = (seed.wrapping_mul(1664525).wrapping_add(1013904223)) & 0x7fffffff;
        seed as f64 / 0x7fffffff_u64 as f64
    };

    for _ in 0..15 {
        let mut changed = false;
        // Fisher-Yates shuffle
        let mut shuffled = ids.clone();
        for i in (1..shuffled.len()).rev() {
            let j = (next_rand() * (i + 1) as f64) as usize;
            shuffled.swap(i, j);
        }

        for id in &shuffled {
            let neighbors = adj.get(id).map(|v| v.as_slice()).unwrap_or(&[]);
            if neighbors.is_empty() { continue; }

            let mut counts: HashMap<&String, usize> = HashMap::new();
            for n in neighbors {
                let l = labels.get(n).unwrap();
                *counts.entry(l).or_insert(0) += 1;
            }

            let mut best_label = labels.get(id).unwrap().clone();
            let mut best_count = 0usize;
            for (l, c) in &counts {
                if *c > best_count {
                    best_count = *c;
                    best_label = (*l).clone();
                }
            }

            if best_label != *labels.get(id).unwrap() {
                labels.insert(id.clone(), best_label);
                changed = true;
            }
        }
        if !changed { break; }
    }

    // Group by label
    let mut groups: HashMap<String, Vec<String>> = HashMap::new();
    for (id, label) in &labels {
        groups.entry(label.clone()).or_default().push(id.clone());
    }

    // Sort by size, filter out singletons
    let mut sorted: Vec<Vec<String>> = groups.into_values()
        .filter(|g| g.len() > 1)
        .collect();
    sorted.sort_by(|a, b| b.len().cmp(&a.len()));

    if sorted.is_empty() {
        return "No clusters found \u{2014} all files are independent.".to_string();
    }

    let singleton_count = ids.len() - sorted.iter().map(|g| g.len()).sum::<usize>();
    let mut lines = vec![
        format!("=== Clusters ({} communities, {} singletons excluded) ===", sorted.len(), singleton_count),
        String::new(),
    ];
    for (i, cluster) in sorted.iter_mut().enumerate().take(20) {
        cluster.sort();

        let cluster_set: HashSet<&String> = cluster.iter().collect();
        let mut internal = 0usize;
        let mut external = 0usize;
        for id in cluster.iter() {
            let node = graph.nodes.get(id).unwrap();
            for imp in &node.imports {
                if cluster_set.contains(imp) {
                    internal += 1;
                } else if graph.nodes.contains_key(imp) {
                    external += 1;
                }
            }
        }
        let cohesion = if internal + external > 0 {
            format!("{:.0}", (internal as f64 / (internal + external) as f64) * 100.0)
        } else {
            "100".to_string()
        };

        lines.push(format!("Cluster {} ({} files, {}% internal coupling):", i + 1, cluster.len(), cohesion));
        for f in cluster.iter().take(8) {
            lines.push(format!("  {}", f));
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

/// BFS connected components, sorted by size desc.
pub fn islands(graph: &Graph) -> String {
    let mut visited: HashSet<String> = HashSet::new();
    let mut components: Vec<Vec<String>> = Vec::new();

    for id in graph.nodes.keys() {
        if visited.contains(id) { continue; }
        let mut component: Vec<String> = Vec::new();
        let mut queue: VecDeque<String> = VecDeque::new();
        visited.insert(id.clone());
        queue.push_back(id.clone());

        while let Some(current) = queue.pop_front() {
            component.push(current.clone());
            if let Some(node) = graph.nodes.get(&current) {
                for imp in &node.imports {
                    if graph.nodes.contains_key(imp) && !visited.contains(imp) {
                        visited.insert(imp.clone());
                        queue.push_back(imp.clone());
                    }
                }
                for imp in &node.imported_by {
                    if !visited.contains(imp) {
                        visited.insert(imp.clone());
                        queue.push_back(imp.clone());
                    }
                }
            }
        }
        components.push(component);
    }

    components.sort_by(|a, b| b.len().cmp(&a.len()));
    let mut lines = vec![
        format!("=== Islands ({} disconnected components) ===", components.len()),
        String::new(),
    ];

    for (i, c) in components.iter_mut().enumerate() {
        c.sort();
        lines.push(format!("Island {} ({} files):", i + 1, c.len()));
        for f in c.iter().take(8) {
            lines.push(format!("  {}", f));
        }
        if c.len() > 8 {
            lines.push(format!("  ... and {} more", c.len() - 8));
        }
        lines.push(String::new());
    }
    lines.join("\n")
}

/// Graphviz DOT output. If target, 2-hop BFS neighborhood. Quote IDs, escape quotes.
pub fn dot(graph: &Graph, target: &str) -> String {
    let nodes: HashMap<&String, &crate::types::GraphNode>;

    if !target.is_empty() {
        let mut seeds: Vec<String> = Vec::new();
        if let Some(node) = graph.find_node(target) {
            seeds.push(node.id.clone());
        } else {
            for id in graph.nodes.keys() {
                if id.contains(target) {
                    seeds.push(id.clone());
                }
            }
        }
        if seeds.is_empty() {
            return format!("No files matching \"{target}\".");
        }

        // BFS 2 hops out
        let mut component: HashSet<String> = seeds.iter().cloned().collect();
        let mut frontier: Vec<String> = seeds;
        for _ in 0..2 {
            let mut next: Vec<String> = Vec::new();
            for id in &frontier {
                if let Some(n) = graph.nodes.get(id) {
                    for imp in &n.imports {
                        if graph.nodes.contains_key(imp) && !component.contains(imp) {
                            component.insert(imp.clone());
                            next.push(imp.clone());
                        }
                    }
                    for imp in &n.imported_by {
                        if !component.contains(imp) {
                            component.insert(imp.clone());
                            next.push(imp.clone());
                        }
                    }
                }
            }
            frontier = next;
        }
        nodes = graph.nodes.iter()
            .filter(|(id, _)| component.contains(*id))
            .collect();
    } else {
        nodes = graph.nodes.iter().collect();
    }

    let dot_id = |s: &str| -> String {
        format!("\"{}\"", s.replace('"', "\\\""))
    };

    let mut lines = vec![
        "digraph codemap {".to_string(),
        "  rankdir=LR;".to_string(),
        "  node [shape=box, fontsize=10];".to_string(),
        String::new(),
    ];
    for (id, node) in &nodes {
        for imp in &node.imports {
            if nodes.contains_key(imp) {
                lines.push(format!("  {} -> {};", dot_id(id), dot_id(imp)));
            }
        }
    }
    lines.push("}".to_string());
    lines.join("\n")
}
