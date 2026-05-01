use std::cmp::Reverse;
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

    // Build index map: id -> index for Vec-based scoring
    let ids: Vec<String> = graph.nodes.keys().cloned().collect();
    let id_to_idx: HashMap<&str, usize> = ids.iter().enumerate().map(|(i, id)| (id.as_str(), i)).collect();

    // Pre-compute local imports as indices for each node
    let import_indices: Vec<Vec<usize>> = ids.iter().map(|id| {
        graph.nodes.get(id).map(|node| {
            node.imports.iter()
                .filter_map(|imp| id_to_idx.get(imp.as_str()).copied())
                .collect()
        }).unwrap_or_default()
    }).collect();

    let init = 1.0 / n as f64;
    let mut scores = vec![init; n];
    let mut new_scores = vec![0.0f64; n];

    for _ in 0..iterations {
        // Collect dangling node rank mass
        let mut dangling_sum: f64 = 0.0;
        for (i, local) in import_indices.iter().enumerate() {
            if local.is_empty() {
                dangling_sum += scores[i];
            }
        }

        // Base score: teleportation + dangling redistribution
        let base = (1.0 - d) / n as f64 + d * dangling_sum / n as f64;
        new_scores.fill(base);

        for (i, local) in import_indices.iter().enumerate() {
            if local.is_empty() { continue; }
            let share = scores[i] / local.len() as f64;
            for &imp_idx in local {
                new_scores[imp_idx] += d * share;
            }
        }
        std::mem::swap(&mut scores, &mut new_scores);
    }

    let mut ranked: Vec<(usize, f64)> = scores.iter().copied().enumerate().collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let top: Vec<&(usize, f64)> = ranked.iter().take(30).collect();
    let mut lines = vec![
        format!("=== PageRank (top {} most important files) ===", top.len()),
        String::new(),
    ];
    for r in &top {
        let score_str = format!("{:.2}", r.1 * 1000.0);
        lines.push(format!("  {:>7} rank  {}", score_str, ids[r.0]));
    }
    lines.join("\n")
}

/// HITS algorithm: 20 iterations, Jacobi update, L2 normalize. Top 20 hubs + top 20 authorities.
pub fn hubs(graph: &Graph) -> String {
    let iterations = 20;
    let ids: Vec<String> = graph.nodes.keys().cloned().collect();
    let n = ids.len();

    // Build index map and pre-compute import indices
    let id_to_idx: HashMap<&str, usize> = ids.iter().enumerate().map(|(i, id)| (id.as_str(), i)).collect();
    let import_indices: Vec<Vec<usize>> = ids.iter().map(|id| {
        graph.nodes.get(id).map(|node| {
            node.imports.iter()
                .filter_map(|imp| id_to_idx.get(imp.as_str()).copied())
                .collect()
        }).unwrap_or_default()
    }).collect();

    // Pre-compute reverse edges: who imports node i?
    let mut imported_by_indices: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, local) in import_indices.iter().enumerate() {
        for &imp_idx in local {
            imported_by_indices[imp_idx].push(i);
        }
    }

    let mut hub_scores = vec![1.0f64; n];
    let mut auth_scores = vec![1.0f64; n];
    let mut new_auth = vec![0.0f64; n];
    let mut new_hub = vec![0.0f64; n];

    for _ in 0..iterations {
        // Authority = sum of hub scores of nodes pointing to it
        new_auth.fill(0.0);
        for (imp_idx, importers) in imported_by_indices.iter().enumerate() {
            let mut sum = 0.0;
            for &src_idx in importers {
                sum += hub_scores[src_idx];
            }
            new_auth[imp_idx] = sum;
        }

        // Hub = sum of authority scores of nodes it points to (using OLD auth_scores -- Jacobi)
        for (i, local) in import_indices.iter().enumerate() {
            let mut h = 0.0;
            for &imp_idx in local {
                h += auth_scores[imp_idx];
            }
            new_hub[i] = h;
        }

        // Normalize (L2)
        let hub_norm = {
            let s: f64 = new_hub.iter().map(|v| v * v).sum();
            let norm = s.sqrt();
            if norm == 0.0 { 1.0 } else { norm }
        };
        let auth_norm = {
            let s: f64 = new_auth.iter().map(|v| v * v).sum();
            let norm = s.sqrt();
            if norm == 0.0 { 1.0 } else { norm }
        };
        for v in new_hub.iter_mut() { *v /= hub_norm; }
        for v in new_auth.iter_mut() { *v /= auth_norm; }

        std::mem::swap(&mut hub_scores, &mut new_hub);
        std::mem::swap(&mut auth_scores, &mut new_auth);
    }

    let mut top_hubs: Vec<(usize, f64)> = hub_scores.iter().copied().enumerate().collect();
    top_hubs.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let top_hubs: Vec<&(usize, f64)> = top_hubs.iter().take(20).collect();

    let mut top_auth: Vec<(usize, f64)> = auth_scores.iter().copied().enumerate().collect();
    top_auth.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let top_auth: Vec<&(usize, f64)> = top_auth.iter().take(20).collect();

    let mut lines = vec![
        "=== Hubs (orchestrators \u{2014} import many things) ===".to_string(),
        String::new(),
    ];
    for h in &top_hubs {
        if h.1 < 0.001 { break; }
        let score_str = format!("{:.2}", h.1 * 100.0);
        lines.push(format!("  {:>7}  {}", score_str, ids[h.0]));
    }
    lines.push(String::new());
    lines.push("=== Authorities (core \u{2014} everyone imports them) ===".to_string());
    lines.push(String::new());
    for a in &top_auth {
        if a.1 < 0.001 { break; }
        let score_str = format!("{:.2}", a.1 * 100.0);
        lines.push(format!("  {:>7}  {}", score_str, ids[a.0]));
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

    let mut ranked: Vec<(String, usize)> = articulation_points.iter().filter_map(|id| {
        graph.nodes.get(id).map(|node| (id.clone(), node.imports.len() + node.imported_by.len()))
    }).collect();
    ranked.sort_by_key(|a| Reverse(a.1));

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
                if let Some(l) = labels.get(n) {
                    *counts.entry(l).or_insert(0) += 1;
                }
            }

            let current_label = match labels.get(id) {
                Some(l) => l.clone(),
                None => continue,
            };
            let mut best_label = current_label.clone();
            let mut best_count = 0usize;
            for (l, c) in &counts {
                if *c > best_count {
                    best_count = *c;
                    best_label = (*l).clone();
                }
            }

            if best_label != current_label {
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
    sorted.sort_by_key(|a| Reverse(a.len()));

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
            let Some(node) = graph.nodes.get(id) else { continue };
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

        let label = lpa_cluster_label(cluster.iter().map(|s| s.as_str()));
        lines.push(format!("Cluster {} {}({} files, {}% internal coupling):", i + 1, label, cluster.len(), cohesion));
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

    components.sort_by_key(|a| Reverse(a.len()));
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
        "  compound=true;".to_string(),  // allow edges between subgraphs
        String::new(),
    ];

    // Group nodes by EntityKind for subgraph clustering — graphviz
    // renders each subgraph as a labeled box that visually groups its
    // members. Big readability win on heterogeneous graphs where you'd
    // otherwise have a tangle of mixed-kind nodes.
    let mut by_kind: std::collections::BTreeMap<&str, Vec<(&String, &crate::types::GraphNode)>> = std::collections::BTreeMap::new();
    for (id, node) in &nodes {
        by_kind.entry(node.kind.as_str()).or_default().push((id, *node));
    }

    for (kind_name, members) in &by_kind {
        // Skip the default SourceFile cluster — usually it's >80% of the
        // graph and clustering it adds noise. Source nodes render at the
        // top level and are visually distinct enough by absence of fill.
        if *kind_name == "source" {
            for (id, node) in members {
                let shape_color = dot_kind_attrs(node.kind);
                if !shape_color.is_empty() {
                    lines.push(format!("  {} [{}];", dot_id(id), shape_color));
                }
            }
            continue;
        }
        lines.push(format!("  subgraph cluster_{} {{", kind_name));
        lines.push(format!("    label=\"{kind_name}\";"));
        lines.push("    style=dashed;".to_string());
        lines.push("    color=gray60;".to_string());
        for (id, node) in members {
            let shape_color = dot_kind_attrs(node.kind);
            if shape_color.is_empty() {
                lines.push(format!("    {};", dot_id(id)));
            } else {
                lines.push(format!("    {} [{}];", dot_id(id), shape_color));
            }
        }
        lines.push("  }".to_string());
    }
    lines.push(String::new());

    // Edges (always at the top level so cross-cluster connections render)
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

fn dot_kind_attrs(kind: crate::types::EntityKind) -> &'static str {
    use crate::types::EntityKind::*;
    match kind {
        SourceFile        => "",
        PeBinary          => "shape=component, fillcolor=\"#e3f2fd\", style=filled",
        ElfBinary         => "shape=component, fillcolor=\"#e8f5e9\", style=filled",
        MachoBinary       => "shape=component, fillcolor=\"#fff3e0\", style=filled",
        JavaClass         => "shape=component, fillcolor=\"#fbe9e7\", style=filled",
        WasmModule        => "shape=component, fillcolor=\"#f3e5f5\", style=filled",
        Dll               => "shape=folder, fillcolor=\"#cfd8dc\", style=filled",
        Symbol            => "shape=oval, fillcolor=\"#fff9c4\", style=filled, fontsize=8",
        HttpEndpoint      => "shape=oval, fillcolor=\"#c8e6c9\", style=filled",
        WebForm           => "shape=parallelogram, fillcolor=\"#dcedc8\", style=filled",
        SchemaTable       => "shape=cylinder, fillcolor=\"#ffe0b2\", style=filled",
        SchemaField       => "shape=note, fillcolor=\"#fff8e1\", style=filled, fontsize=8",
        ProtoMessage      => "shape=tab, fillcolor=\"#e1bee7\", style=filled",
        GraphqlType       => "shape=tab, fillcolor=\"#d1c4e9\", style=filled",
        OpenApiPath       => "shape=oval, fillcolor=\"#b2dfdb\", style=filled",
        DockerService     => "shape=box3d, fillcolor=\"#bbdefb\", style=filled",
        TerraformResource => "shape=box3d, fillcolor=\"#b39ddb\", style=filled",
        MlModel           => "shape=note, fillcolor=\"#ffccbc\", style=filled",
        DotnetAssembly    => "shape=component, fillcolor=\"#e1f5fe\", style=filled",
        DotnetType        => "shape=record, fillcolor=\"#e0f7fa\", style=filled, fontsize=8",
        Compiler          => "shape=hexagon, fillcolor=\"#fce4ec\", style=filled, fontsize=10",
        StringLiteral     => "shape=note, fillcolor=\"#f5f5f5\", style=filled, fontsize=8",
        Overlay           => "shape=cds, fillcolor=\"#ef9a9a\", style=filled, fontsize=9",
        BinaryFunction    => "shape=ellipse, fillcolor=\"#fff9c4\", style=filled, fontsize=9",
        License           => "shape=box, fillcolor=\"#c5e1a5\", style=\"filled,rounded\", fontsize=10",
        Cve               => "shape=octagon, fillcolor=\"#ef5350\", style=filled, fontcolor=white, fontsize=10",
        Cert              => "shape=diamond, fillcolor=\"#90caf9\", style=filled, fontsize=10",
        AndroidPackage    => "shape=component, fillcolor=\"#a5d6a7\", style=filled, fontsize=10",
        Permission        => "shape=parallelogram, fillcolor=\"#ffcc80\", style=filled, fontsize=9",
        Secret            => "shape=doubleoctagon, fillcolor=\"#d32f2f\", style=filled, fontcolor=white, fontsize=10",
        Dependency        => "shape=tab, fillcolor=\"#b3e5fc\", style=filled, fontsize=10",
        MlTensor          => "shape=cylinder, fillcolor=\"#ffe0b2\", style=filled, fontsize=9",
        MlOperator        => "shape=hexagon, fillcolor=\"#ce93d8\", style=filled, fontsize=10",
        BinarySection     => "shape=folder, fillcolor=\"#cfd8dc\", style=filled, fontsize=9",
        AntiAnalysis      => "shape=octagon, fillcolor=\"#ef9a9a\", style=filled, fontsize=10",
        CryptoConstant    => "shape=hexagon, fillcolor=\"#fff59d\", style=filled, fontsize=10",
        CudaKernel        => "shape=trapezium, fillcolor=\"#76b900\", style=filled, fontsize=10",
        SwitchTable       => "shape=invhouse, fillcolor=\"#b39ddb\", style=filled, fontsize=10",
        VTable            => "shape=tab, fillcolor=\"#80cbc4\", style=filled, fontsize=10",
        BinaryFingerprint => "shape=note, fillcolor=\"#f48fb1\", style=filled, fontsize=10",
    }
}

/// Mermaid flowchart: renders dependency graph in Mermaid syntax for GitHub/docs embedding.
pub fn mermaid(graph: &Graph, target: &str) -> String {
    let nodes: HashMap<&String, &crate::types::GraphNode>;

    if !target.is_empty() && target != "." {
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

    // Mermaid node ID: replace non-alphanumeric with underscores
    let mermaid_id = |s: &str| -> String {
        s.chars().map(|c| if c.is_alphanumeric() { c } else { '_' }).collect()
    };

    // Short label: just filename without directory prefix
    let short_label = |s: &str| -> String {
        s.rsplit('/').next().unwrap_or(s).to_string()
    };

    let mut lines = vec![
        "graph LR".to_string(),
    ];

    // Emit kind-aware classDef declarations once at the top so the diagram
    // colors match the dot output.
    lines.push("    classDef pe       fill:#e3f2fd,stroke:#1976d2".to_string());
    lines.push("    classDef elf      fill:#e8f5e9,stroke:#388e3c".to_string());
    lines.push("    classDef macho    fill:#fff3e0,stroke:#f57c00".to_string());
    lines.push("    classDef dll      fill:#cfd8dc,stroke:#455a64".to_string());
    lines.push("    classDef symbol   fill:#fff9c4,stroke:#fbc02d".to_string());
    lines.push("    classDef endpoint fill:#c8e6c9,stroke:#388e3c".to_string());
    lines.push("    classDef form     fill:#dcedc8,stroke:#689f38".to_string());
    lines.push("    classDef table    fill:#ffe0b2,stroke:#ef6c00".to_string());
    lines.push("    classDef field    fill:#fff8e1,stroke:#f9a825".to_string());
    lines.push("    classDef model    fill:#ffccbc,stroke:#bf360c".to_string());
    lines.push("    classDef proto    fill:#e1bee7,stroke:#6a1b9a".to_string());
    lines.push("    classDef gql      fill:#d1c4e9,stroke:#4527a0".to_string());
    lines.push("    classDef docker   fill:#bbdefb,stroke:#1565c0".to_string());
    lines.push("    classDef tf       fill:#b39ddb,stroke:#4527a0".to_string());

    // Emit node declarations with labels (and class assignments per kind)
    let mut sorted_ids: Vec<&&String> = nodes.keys().collect();
    sorted_ids.sort();
    let mut class_assignments: Vec<String> = Vec::new();
    for id in &sorted_ids {
        let label = short_label(id);
        let mid = mermaid_id(id);
        lines.push(format!("    {}[{}]", mid, label));
        if let Some(node) = nodes.get(*id) {
            let cls = mermaid_kind_class(node.kind);
            if !cls.is_empty() {
                class_assignments.push(format!("    class {} {}", mid, cls));
            }
        }
    }
    lines.push(String::new());
    lines.extend(class_assignments);
    lines.push(String::new());

    // Emit edges
    for id in &sorted_ids {
        if let Some(node) = nodes.get(*id) {
            for imp in &node.imports {
                if nodes.contains_key(imp) {
                    lines.push(format!("    {} --> {}", mermaid_id(id), mermaid_id(imp)));
                }
            }
        }
    }

    lines.join("\n")
}

fn mermaid_kind_class(kind: crate::types::EntityKind) -> &'static str {
    use crate::types::EntityKind::*;
    match kind {
        SourceFile        => "",
        PeBinary          => "pe",
        ElfBinary         => "elf",
        MachoBinary       => "macho",
        JavaClass         => "elf",
        WasmModule        => "macho",
        Dll               => "dll",
        Symbol            => "symbol",
        HttpEndpoint      => "endpoint",
        WebForm           => "form",
        SchemaTable       => "table",
        SchemaField       => "field",
        ProtoMessage      => "proto",
        GraphqlType       => "gql",
        OpenApiPath       => "endpoint",
        DockerService     => "docker",
        TerraformResource => "tf",
        MlModel           => "model",
        DotnetAssembly    => "pe",
        DotnetType        => "field",
        Compiler          => "compiler",
        StringLiteral     => "string",
        Overlay           => "overlay",
        BinaryFunction    => "bin_func",
        License           => "license",
        Cve               => "cve",
        Cert              => "cert",
        AndroidPackage    => "apk",
        Permission        => "permission",
        Secret            => "secret",
        Dependency        => "dependency",
        MlTensor          => "tensor",
        MlOperator        => "ml_operator",
        BinarySection     => "section",
        AntiAnalysis      => "anti_tech",
        CryptoConstant    => "crypto",
        CudaKernel        => "cuda_kernel",
        SwitchTable       => "switch_table",
        VTable            => "vtable",
        BinaryFingerprint => "fingerprint",
    }
}

/// LCP-prefix + homogeneous-kind cluster labeler. Same logic as
/// leiden::cluster_label — duplicated to avoid making the leiden
/// module a public API surface for this helper. If both grow we
/// can lift to a shared utility.
fn lpa_cluster_label<'a, I: Iterator<Item = &'a str> + Clone>(members: I) -> String {
    let first = match members.clone().next() {
        Some(s) => s,
        None => return String::new(),
    };

    // Homogeneous-kind cluster: ep:, dll:, etc. all the same prefix.
    let known = ["ep", "dll", "pe", "elf", "macho", "java", "wasm",
        "sym", "form", "table", "field", "model", "proto", "gql",
        "oapi", "docker", "tf", "asm", "schema"];
    let kind_prefix = |id: &str| -> Option<String> {
        let p = id.split(':').next()?;
        if known.contains(&p) { Some(p.to_string()) } else { None }
    };
    if let Some(p) = kind_prefix(first) {
        if members.clone().all(|m| kind_prefix(m).as_deref() == Some(p.as_str())) {
            return format!("[{p} cluster] ");
        }
    }

    if first.contains(':') && !first.contains('/') { return String::new(); }
    let first_segs: Vec<&str> = first.split('/').collect();
    let mut common_depth = first_segs.len();
    for m in members {
        let segs: Vec<&str> = m.split('/').collect();
        let mut shared = 0;
        for (a, b) in first_segs.iter().zip(segs.iter()) {
            if a == b { shared += 1; } else { break; }
        }
        common_depth = common_depth.min(shared);
        if common_depth == 0 { break; }
    }
    if common_depth == 0 { return String::new(); }
    let prefix_segs = &first_segs[..common_depth];
    if prefix_segs.is_empty() { return String::new(); }
    let prefix = prefix_segs.join("/");
    if !prefix.contains('/') && prefix.len() < 4 { return String::new(); }
    format!("[{prefix}/*] ")
}
