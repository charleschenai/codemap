use crate::types::*;
use crate::utils::{truncate, pad_end};
use std::collections::{HashMap, HashSet, VecDeque};

// ── CPG Builder ─────────────────────────────────────────────────────

pub fn ensure_cpg(graph: &mut Graph) -> &CodePropertyGraph {
    if graph.cpg.is_none() {
        let t0 = std::time::Instant::now();
        let cpg = build_cpg(graph);
        eprintln!("CPG: {} nodes, {} edges in {}ms", cpg.nodes.len(), cpg.edges.len(), t0.elapsed().as_millis());
        graph.cpg = Some(cpg);
    }
    graph.cpg.as_ref().unwrap()
}

fn build_cpg(graph: &Graph) -> CodePropertyGraph {
    let mut nodes: HashMap<String, CPGNode> = HashMap::new();
    let mut edges: Vec<CPGEdge> = Vec::new();
    let mut edges_from: HashMap<String, Vec<CPGEdge>> = HashMap::new();
    let mut edges_to: HashMap<String, Vec<CPGEdge>> = HashMap::new();

    let mut add_node = |n: CPGNode| { nodes.insert(n.id.clone(), n); };
    let add_edge = |e: CPGEdge, edges: &mut Vec<CPGEdge>, ef: &mut HashMap<String, Vec<CPGEdge>>, et: &mut HashMap<String, Vec<CPGEdge>>| {
        ef.entry(e.from.clone()).or_default().push(e.clone());
        et.entry(e.to.clone()).or_default().push(e.clone());
        edges.push(e);
    };

    // Build export map: fn name -> Vec<(file, fn)>
    let mut export_map: HashMap<String, Vec<(String, FunctionInfo)>> = HashMap::new();
    for (id, node) in &graph.nodes {
        for func in &node.functions {
            if func.is_exported {
                export_map.entry(func.name.clone()).or_default().push((id.clone(), func.clone()));
            }
        }
    }

    // Phase 1: Create nodes from definitions, params, returns, calls
    for (file_id, g_node) in &graph.nodes {
        let df = match &g_node.data_flow {
            Some(df) => df,
            None => continue,
        };

        for def in &df.definitions {
            add_node(CPGNode {
                id: format!("{file_id}:{}:{}", def.line, def.name),
                kind: NodeKind::Def,
                file: file_id.clone(),
                line: def.line,
                name: def.name.clone(),
                version: None,
                expr: Some(truncate(&def.rhs, 200)),
                scope: Some(def.scope.clone()),
            });
        }

        for func in &g_node.functions {
            if let Some(params) = &func.parameters {
                for p in params {
                    add_node(CPGNode {
                        id: format!("{file_id}:{}:param:{p}", func.start_line),
                        kind: NodeKind::Param,
                        file: file_id.clone(),
                        line: func.start_line,
                        name: p.clone(),
                        version: None,
                        expr: None,
                        scope: Some(func.name.clone()),
                    });
                }
            }
            if let Some(ret_lines) = &func.return_lines {
                for &rl in ret_lines {
                    add_node(CPGNode {
                        id: format!("{file_id}:{rl}:return:{}", func.name),
                        kind: NodeKind::Return,
                        file: file_id.clone(),
                        line: rl,
                        name: func.name.clone(),
                        version: None,
                        expr: None,
                        scope: Some(func.name.clone()),
                    });
                }
            }
        }

        for call in &df.call_args {
            add_node(CPGNode {
                id: format!("{file_id}:{}:call:{}", call.line, call.callee),
                kind: NodeKind::Call,
                file: file_id.clone(),
                line: call.line,
                name: call.callee.clone(),
                version: None,
                expr: None,
                scope: Some(call.scope.clone()),
            });
        }
    }

    // Phase 2: Create edges (def-use, call-param, return-call, property)
    for (file_id, g_node) in &graph.nodes {
        let df = match &g_node.data_flow {
            Some(df) => df,
            None => continue,
        };

        // Build scope-indexed defs for quick lookup
        let mut defs_by_scope: HashMap<String, Vec<&DataFlowDef>> = HashMap::new();
        for def in &df.definitions {
            let key = format!("{}:{}", def.scope, def.name);
            defs_by_scope.entry(key).or_default().push(def);
        }
        for defs in defs_by_scope.values_mut() {
            defs.sort_by_key(|d| d.line);
        }

        let find_def = |name: &str, scope: &str, use_line: usize| -> Option<&DataFlowDef> {
            for s in &[scope, "__module__"] {
                let key = format!("{s}:{name}");
                if let Some(defs) = defs_by_scope.get(&key) {
                    let mut best: Option<&DataFlowDef> = None;
                    for d in defs {
                        if d.line <= use_line {
                            best = Some(d);
                        } else {
                            break;
                        }
                    }
                    if best.is_some() {
                        return best;
                    }
                }
            }
            None
        };

        // Def-use edges
        for u in &df.uses {
            if let Some(def) = find_def(&u.name, &u.scope, u.line) {
                let to_id = format!("{file_id}:{}:use:{}", u.line, u.name);
                if !nodes.contains_key(&to_id) {
                    nodes.insert(to_id.clone(), CPGNode {
                        id: to_id.clone(),
                        kind: NodeKind::Use,
                        file: file_id.clone(),
                        line: u.line,
                        name: u.name.clone(),
                        version: None,
                        expr: None,
                        scope: Some(u.scope.clone()),
                    });
                }
                let from_id = format!("{file_id}:{}:{}", def.line, def.name);
                add_edge(CPGEdge { from: from_id, to: to_id, kind: EdgeKind::Data }, &mut edges, &mut edges_from, &mut edges_to);
            }
        }

        // Intra-file call-param edges
        for call in &df.call_args {
            let cn = call.callee.split('.').last().unwrap_or(&call.callee);
            if let Some(tf) = g_node.functions.iter().find(|f| f.name == cn) {
                if let Some(params) = &tf.parameters {
                    for arg in &call.args {
                        if arg.position < params.len() {
                            let from_id = format!("{file_id}:{}:call:{}", call.line, call.callee);
                            let to_id = format!("{file_id}:{}:param:{}", tf.start_line, params[arg.position]);
                            if nodes.contains_key(&from_id) && nodes.contains_key(&to_id) {
                                add_edge(CPGEdge { from: from_id, to: to_id, kind: EdgeKind::Call }, &mut edges, &mut edges_from, &mut edges_to);
                            }
                        }
                    }
                }
            }
        }

        // Return-call data edges
        for func in &g_node.functions {
            if let Some(ret_lines) = &func.return_lines {
                if ret_lines.is_empty() { continue; }
                for call in &df.call_args {
                    let cn = call.callee.split('.').last().unwrap_or(&call.callee);
                    if cn == func.name {
                        for &rl in ret_lines {
                            let from_id = format!("{file_id}:{rl}:return:{}", func.name);
                            let to_id = format!("{file_id}:{}:call:{}", call.line, call.callee);
                            if nodes.contains_key(&from_id) && nodes.contains_key(&to_id) {
                                add_edge(CPGEdge { from: from_id, to: to_id, kind: EdgeKind::Data }, &mut edges, &mut edges_from, &mut edges_to);
                            }
                        }
                    }
                }
            }
        }

        // Property edges
        for prop in &df.property_accesses {
            let n_id = format!("{file_id}:{}:prop:{}.{}", prop.line, prop.base, prop.property);
            if !nodes.contains_key(&n_id) {
                nodes.insert(n_id.clone(), CPGNode {
                    id: n_id.clone(),
                    kind: NodeKind::Property,
                    file: file_id.clone(),
                    line: prop.line,
                    name: format!("{}.{}", prop.base, prop.property),
                    version: None,
                    expr: None,
                    scope: Some(prop.scope.clone()),
                });
            }
            if let Some(bd) = find_def(&prop.base, &prop.scope, prop.line) {
                let from_id = format!("{file_id}:{}:{}", bd.line, bd.name);
                let edge_kind = if prop.kind == PropertyAccessKind::Read { EdgeKind::PropertyRead } else { EdgeKind::PropertyWrite };
                add_edge(CPGEdge { from: from_id, to: n_id.clone(), kind: edge_kind }, &mut edges, &mut edges_from, &mut edges_to);
            }
        }
    }

    // Phase 3: Cross-file call-param and return-call edges
    for (file_id, g_node) in &graph.nodes {
        let df = match &g_node.data_flow {
            Some(df) => df,
            None => continue,
        };
        let imp_set: HashSet<&str> = g_node.imports.iter()
            .filter(|i| graph.nodes.contains_key(i.as_str()))
            .map(|i| i.as_str())
            .collect();

        for call in &df.call_args {
            let cn = call.callee.split('.').last().unwrap_or(&call.callee);
            if let Some(targets) = export_map.get(cn) {
                for (target_file, target_fn) in targets {
                    if target_file == file_id || !imp_set.contains(target_file.as_str()) {
                        continue;
                    }
                    // Call-param edges
                    if let Some(params) = &target_fn.parameters {
                        for arg in &call.args {
                            if arg.position < params.len() {
                                let from_id = format!("{file_id}:{}:call:{}", call.line, call.callee);
                                let to_id = format!("{target_file}:{}:param:{}", target_fn.start_line, params[arg.position]);
                                if nodes.contains_key(&from_id) && nodes.contains_key(&to_id) {
                                    add_edge(CPGEdge { from: from_id, to: to_id, kind: EdgeKind::Call }, &mut edges, &mut edges_from, &mut edges_to);
                                }
                            }
                        }
                    }
                    // Return-call data edges
                    if let Some(ret_lines) = &target_fn.return_lines {
                        for &rl in ret_lines {
                            let from_id = format!("{target_file}:{rl}:return:{}", target_fn.name);
                            let to_id = format!("{file_id}:{}:call:{}", call.line, call.callee);
                            if nodes.contains_key(&from_id) && nodes.contains_key(&to_id) {
                                add_edge(CPGEdge { from: from_id, to: to_id, kind: EdgeKind::Data }, &mut edges, &mut edges_from, &mut edges_to);
                            }
                        }
                    }
                }
            }
        }
    }

    CodePropertyGraph { nodes, edges, edges_from, edges_to }
}

// ── Query Functions ─────────────────────────────────────────────────

pub fn backward_slice<'a>(cpg: &'a CodePropertyGraph, start_ids: &[String], max_depth: usize) -> Vec<&'a CPGNode> {
    let mut visited: HashSet<&str> = HashSet::new();
    let mut result: Vec<&CPGNode> = Vec::new();
    let mut queue: VecDeque<(&str, usize)> = VecDeque::new();

    for id in start_ids {
        if let Some(node) = cpg.nodes.get(id) {
            visited.insert(&node.id);
            queue.push_back((&node.id, 0));
            result.push(node);
        }
    }

    while let Some((id, d)) = queue.pop_front() {
        if d >= max_depth { continue; }
        if let Some(incoming) = cpg.edges_to.get(id) {
            for e in incoming {
                if !visited.contains(e.from.as_str()) {
                    visited.insert(&e.from);
                    if let Some(n) = cpg.nodes.get(&e.from) {
                        result.push(n);
                        queue.push_back((&n.id, d + 1));
                    }
                }
            }
        }
    }

    result.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
    result
}

pub fn forward_trace<'a>(cpg: &'a CodePropertyGraph, start_ids: &[String], max_depth: usize) -> Vec<&'a CPGNode> {
    let mut visited: HashSet<&str> = HashSet::new();
    let mut result: Vec<&CPGNode> = Vec::new();
    let mut queue: VecDeque<(&str, usize)> = VecDeque::new();

    for id in start_ids {
        if let Some(node) = cpg.nodes.get(id) {
            visited.insert(&node.id);
            queue.push_back((&node.id, 0));
            result.push(node);
        }
    }

    while let Some((id, d)) = queue.pop_front() {
        if d >= max_depth { continue; }
        if let Some(outgoing) = cpg.edges_from.get(id) {
            for e in outgoing {
                if !visited.contains(e.to.as_str()) {
                    visited.insert(&e.to);
                    if let Some(n) = cpg.nodes.get(&e.to) {
                        result.push(n);
                        queue.push_back((&n.id, d + 1));
                    }
                }
            }
        }
    }

    result.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
    result
}

pub fn find_target_nodes<'a>(cpg: &'a CodePropertyGraph, target: &str) -> Vec<&'a CPGNode> {
    let mut results = Vec::new();
    let parts: Vec<&str> = target.splitn(2, ':').collect();

    if parts.len() >= 2 {
        let fp = parts[0];
        let lon = parts[1];
        let ln: Option<usize> = lon.parse().ok();

        for n in cpg.nodes.values() {
            let file_matches = n.file == fp || n.file.ends_with(&format!("/{fp}")) || n.file.ends_with(fp) || n.file.contains(fp);
            if !file_matches { continue; }

            if let Some(line_num) = ln {
                if lon.chars().all(|c| c.is_ascii_digit()) && n.line == line_num {
                    results.push(n);
                }
            } else if n.name == lon || n.name.ends_with(&format!(".{lon}")) || n.name.ends_with(lon) || (n.scope.as_deref() == Some(lon) && n.kind == NodeKind::Return) {
                results.push(n);
            }
        }
    } else {
        for n in cpg.nodes.values() {
            if n.name == target || n.name.ends_with(&format!(".{target}")) {
                results.push(n);
            }
        }
    }

    results
}

pub fn find_sink_nodes<'a>(cpg: &'a CodePropertyGraph, config: &DataFlowConfig, file_filter: Option<&str>) -> Vec<&'a CPGNode> {
    let mut results = Vec::new();
    for n in cpg.nodes.values() {
        if n.kind != NodeKind::Call { continue; }
        if let Some(ff) = file_filter {
            if n.file != ff { continue; }
        }
        for s in &config.sinks {
            if matches_pattern(&n.name, &s.pattern) {
                results.push(n);
                break;
            }
        }
    }
    results.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
    results
}

// ── Tree Builder for --tree mode ────────────────────────────────────

pub struct TreeNode<'a> {
    pub node: &'a CPGNode,
    pub children: Vec<TreeNode<'a>>,
}

pub fn build_tree<'a>(cpg: &'a CodePropertyGraph, root_ids: &[String], dir: &str, max_depth: usize) -> Vec<TreeNode<'a>> {
    let mut visited: HashSet<&str> = HashSet::new();

    fn recurse<'a>(cpg: &'a CodePropertyGraph, node_id: &str, depth: usize, max_depth: usize, dir: &str, visited: &mut HashSet<&'a str>) -> Option<TreeNode<'a>> {
        if depth > max_depth || visited.contains(node_id) { return None; }
        let node = cpg.nodes.get(node_id)?;
        visited.insert(&node.id);
        let mut children = Vec::new();
        let edge_list = if dir == "backward" { cpg.edges_to.get(node_id) } else { cpg.edges_from.get(node_id) };
        if let Some(el) = edge_list {
            for e in el {
                let next = if dir == "backward" { &e.from } else { &e.to };
                if let Some(c) = recurse(cpg, next, depth + 1, max_depth, dir, visited) {
                    children.push(c);
                }
            }
        }
        Some(TreeNode { node, children })
    }

    root_ids.iter()
        .filter_map(|id| recurse(cpg, id, 0, max_depth, dir, &mut visited))
        .collect()
}

pub fn render_tree(trees: &[TreeNode], prefix: &str) -> Vec<String> {
    let mut lines = Vec::new();
    for (i, t) in trees.iter().enumerate() {
        let is_last = i == trees.len() - 1;
        let conn = if prefix.is_empty() { "" } else if is_last { "└── " } else { "├── " };
        let expr_part = match &t.node.expr {
            Some(e) => format!("  {}", truncate(e, 80)),
            None => String::new(),
        };
        lines.push(format!("{prefix}{conn}{}:{}  {}  {}{expr_part}",
            t.node.file, t.node.line,
            pad_end(t.node.kind.as_str(), 6),
            t.node.name,
        ));
        if !t.children.is_empty() {
            let next_prefix = if prefix.is_empty() {
                String::new()
            } else if is_last {
                format!("{prefix}    ")
            } else {
                format!("{prefix}│   ")
            };
            lines.extend(render_tree(&t.children, &next_prefix));
        }
    }
    lines
}

// ── Helpers ─────────────────────────────────────────────────────────
