use crate::cpg;
use crate::types::*;
use crate::utils::{truncate, pad_end};
use std::collections::HashSet;

pub fn data_flow(graph: &mut Graph, target: &str, _tree_mode: bool) -> String {
    if target.is_empty() { return "Usage: codemap data-flow <file> [function]".to_string(); }
    // Ensure CPG is built (mutable borrow), then release it
    cpg::ensure_cpg(graph);

    let parts: Vec<&str> = target.split_whitespace().collect();
    let file_target = parts[0];
    let fn_name = parts.get(1).copied();

    let node = match graph.find_node(file_target) {
        Some(n) => n,
        None => return format!("File not found: {file_target}"),
    };
    let node_id = node.id.clone();
    let df = match &node.data_flow {
        Some(df) => df.clone(),
        None => return format!("No data-flow info for {node_id}"),
    };
    let fns: Vec<FunctionInfo> = if let Some(name) = fn_name {
        let filtered: Vec<FunctionInfo> = node.functions.iter().filter(|f| f.name == name).cloned().collect();
        if filtered.is_empty() { return format!("Function not found: {name} in {node_id}"); }
        filtered
    } else {
        node.functions.iter().cloned().collect()
    };

    // Now get CPG ref immutably (ensure_cpg already built it above)
    let cpg = graph.cpg.as_ref().unwrap();

    let mut lines = vec![
        format!("=== Data Flow: {}{} ===", node_id, fn_name.map(|n| format!(":{n}")).unwrap_or_default()),
        String::new(),
    ];

    for func in &fns {
        let params = func.parameters.as_deref().unwrap_or(&[]);
        lines.push(format!("{}({}):", func.name, params.join(", ")));

        for p in params {
            let param_id = format!("{}:{}:param:{p}", node_id, func.start_line);
            let out = cpg.edges_from.get(&param_id).map(|v| v.as_slice()).unwrap_or(&[]);
            lines.push(format!("  {p} \u{2190} param"));
            for e in out.iter().take(10) {
                if let Some(t) = cpg.nodes.get(&e.to) {
                    lines.push(format!("    \u{2192} used at L{}: {}", t.line, t.name));
                }
            }
        }

        for def in df.definitions.iter().filter(|d| d.scope == func.name) {
            if params.iter().any(|p| p == &def.name) { continue; }
            let def_id = format!("{}:{}:{}", node_id, def.line, def.name);
            let out = cpg.edges_from.get(&def_id).map(|v| v.as_slice()).unwrap_or(&[]);
            let rhs = truncate(&def.rhs, 60);
            lines.push(format!("  L{} {} = {}", def.line, def.name, rhs));
            for e in out.iter().take(5) {
                if let Some(t) = cpg.nodes.get(&e.to) {
                    lines.push(format!("    \u{2192} L{}: {}", t.line, t.name));
                }
            }
        }

        if let Some(ret_lines) = &func.return_lines {
            for &rl in ret_lines {
                let ret_uses: Vec<String> = df.uses.iter()
                    .filter(|u| u.line == rl && u.context == UseContext::Return)
                    .map(|u| u.name.clone())
                    .collect();
                let ret_str = if ret_uses.is_empty() { "...".to_string() } else { ret_uses.join(", ") };
                lines.push(format!("  L{rl} return {ret_str}"));
            }
        }
        lines.push(String::new());
    }
    lines.join("\n")
}

pub fn taint(graph: &mut Graph, args: &str, tree_mode: bool) -> String {
    let scan_dir = graph.scan_dir.clone();
    cpg::ensure_cpg(graph);
    let cpg_ref = graph.cpg.as_ref().unwrap();
    let _config = load_dataflow_config(&scan_dir);
    let parts: Vec<&str> = args.split_whitespace().collect();
    if parts.len() < 2 { return "Usage: codemap taint <source> <sink>".to_string(); }

    let src_nodes = cpg::find_target_nodes(cpg_ref, parts[0]);
    let snk_nodes = cpg::find_target_nodes(cpg_ref, parts[1]);
    if src_nodes.is_empty() { return format!("Source not found: {}", parts[0]); }
    if snk_nodes.is_empty() { return format!("Sink not found: {}", parts[1]); }

    let src_ids: Vec<String> = src_nodes.iter().map(|n| n.id.clone()).collect();
    let snk_ids: Vec<String> = snk_nodes.iter().map(|n| n.id.clone()).collect();

    let fwd_set: HashSet<&str> = cpg::forward_trace(cpg_ref, &src_ids, 20).iter().map(|n| n.id.as_str()).collect();
    let bwd_nodes = cpg::backward_slice(cpg_ref, &snk_ids, 20);
    let path_nodes: Vec<&&CPGNode> = bwd_nodes.iter().filter(|n| fwd_set.contains(n.id.as_str()) || src_nodes.iter().any(|s| s.id == n.id)).collect();

    if path_nodes.is_empty() {
        let uf: HashSet<&str> = bwd_nodes.iter().map(|n| n.file.as_str()).collect();
        let mut lines = vec![
            format!("=== No direct path found: {} \u{2192} {} ===", parts[0], parts[1]),
            String::new(),
            format!("Backward slice from sink ({} nodes across {} files):", bwd_nodes.len(), uf.len()),
            String::new(),
        ];
        if tree_mode {
            let trees = cpg::build_tree(cpg_ref, &snk_ids, "backward", 15);
            lines.extend(cpg::render_tree(&trees, ""));
        } else {
            for n in bwd_nodes.iter().take(30) {
                let expr = n.expr.as_deref().map(|e| format!("  {}", truncate(e, 60))).unwrap_or_default();
                lines.push(format!("  {}:{:>5}  {}  {}{expr}", n.file, n.line, pad_end(n.kind.as_str(), 6), n.name));
            }
            if bwd_nodes.len() > 30 { lines.push(format!("  ... and {} more", bwd_nodes.len() - 30)); }
        }
        return lines.join("\n");
    }

    let uf: HashSet<&str> = path_nodes.iter().map(|n| n.file.as_str()).collect();
    let mut lines = vec![
        format!("=== Data path: {} \u{2192} {} ({} nodes, {} files) ===", parts[0], parts[1], path_nodes.len(), uf.len()),
        String::new(),
    ];
    if tree_mode {
        let trees = cpg::build_tree(cpg_ref, &snk_ids, "backward", 15);
        lines.extend(cpg::render_tree(&trees, ""));
    } else {
        for n in &path_nodes {
            let expr = n.expr.as_deref().map(|e| format!("  {}", truncate(e, 60))).unwrap_or_default();
            lines.push(format!("  {}:{:>5}  {}  {}{expr}", n.file, n.line, pad_end(n.kind.as_str(), 6), n.name));
        }
    }
    lines.join("\n")
}

pub fn slice(graph: &mut Graph, target: &str, tree_mode: bool) -> String {
    if target.is_empty() { return "Usage: codemap slice <file>:<line>".to_string(); }
    cpg::ensure_cpg(graph);
    let cpg_ref = graph.cpg.as_ref().unwrap();

    let mut target_nodes = cpg::find_target_nodes(cpg_ref, target);
    if target_nodes.is_empty() {
        let parts: Vec<&str> = target.splitn(2, ':').collect();
        if parts.len() >= 2 {
            if let Ok(ln) = parts[1].parse::<usize>() {
                for n in cpg_ref.nodes.values() {
                    if (n.file == parts[0] || n.file.ends_with(&format!("/{}", parts[0])) || n.file.ends_with(parts[0])) && n.line == ln {
                        target_nodes.push(n);
                    }
                }
            }
        }
    }
    if target_nodes.is_empty() { return format!("No CPG nodes found for: {target}"); }

    let target_ids: Vec<String> = target_nodes.iter().map(|n| n.id.clone()).collect();
    let slice_nodes = cpg::backward_slice(cpg_ref, &target_ids, 20);
    let uf: HashSet<&str> = slice_nodes.iter().map(|n| n.file.as_str()).collect();
    let td = target_nodes[0];

    let mut lines = vec![
        format!("=== Backward slice from L{}: {} ({}) ===", td.line, td.name, td.file),
        String::new(),
        format!("{} nodes contribute across {} files:", slice_nodes.len(), uf.len()),
        String::new(),
    ];
    if tree_mode {
        let trees = cpg::build_tree(cpg_ref, &target_ids, "backward", 15);
        lines.extend(cpg::render_tree(&trees, ""));
    } else {
        for n in slice_nodes.iter().take(50) {
            let expr = n.expr.as_deref().map(|e| format!("  {}", truncate(e, 60))).unwrap_or_default();
            lines.push(format!("  {}:{:>5}  {}  {}{expr}", n.file, n.line, pad_end(n.kind.as_str(), 6), n.name));
        }
        if slice_nodes.len() > 50 { lines.push(format!("  ... and {} more", slice_nodes.len() - 50)); }
    }
    lines.join("\n")
}

pub fn trace_value(graph: &mut Graph, target: &str, tree_mode: bool) -> String {
    if target.is_empty() { return "Usage: codemap trace-value <file>:<line>:<name>".to_string(); }
    let scan_dir = graph.scan_dir.clone();
    cpg::ensure_cpg(graph);
    let cpg_ref = graph.cpg.as_ref().unwrap();
    let config = load_dataflow_config(&scan_dir);

    let target_nodes = cpg::find_target_nodes(cpg_ref, target);
    if target_nodes.is_empty() { return format!("No CPG nodes found for: {target}"); }

    let target_ids: Vec<String> = target_nodes.iter().map(|n| n.id.clone()).collect();
    let trace = cpg::forward_trace(cpg_ref, &target_ids, 20);

    let mut sink_set: HashSet<&str> = HashSet::new();
    for n in &trace {
        if n.kind == NodeKind::Call {
            for s in &config.sinks {
                if matches_pattern(&n.name, &s.pattern) {
                    sink_set.insert(&n.id);
                    break;
                }
            }
        }
    }

    let uf: HashSet<&str> = trace.iter().map(|n| n.file.as_str()).collect();
    let td = target_nodes[0];
    let mut lines = vec![
        format!("=== Forward trace: {} ({}:{}) ===", td.name, td.file, td.line),
        String::new(),
        format!("{} nodes reached across {} files:", trace.len(), uf.len()),
        String::new(),
    ];
    if tree_mode {
        let trees = cpg::build_tree(cpg_ref, &target_ids, "forward", 15);
        lines.extend(cpg::render_tree(&trees, ""));
    } else {
        for n in trace.iter().take(50) {
            let sink_label = if sink_set.contains(n.id.as_str()) { "  SINK" } else { "" };
            let expr = n.expr.as_deref().map(|e| format!("  {}", truncate(e, 60))).unwrap_or_default();
            lines.push(format!("  {}:{:>5}  {}  {}{sink_label}{expr}", n.file, n.line, pad_end(n.kind.as_str(), 6), n.name));
        }
        if trace.len() > 50 { lines.push(format!("  ... and {} more", trace.len() - 50)); }
    }
    lines.join("\n")
}

pub fn sinks(graph: &mut Graph, target: &str) -> String {
    let scan_dir = graph.scan_dir.clone();
    let file_filter = if target.is_empty() {
        None
    } else {
        match graph.find_node(target) {
            Some(n) => Some(n.id.clone()),
            None => return format!("File not found: {target}"),
        }
    };
    cpg::ensure_cpg(graph);
    let cpg_ref = graph.cpg.as_ref().unwrap();
    let config = load_dataflow_config(&scan_dir);

    let sink_nodes = cpg::find_sink_nodes(cpg_ref, &config, file_filter.as_deref());
    if sink_nodes.is_empty() {
        return if let Some(ff) = &file_filter {
            format!("No sinks found in {ff}.")
        } else {
            "No sinks found in codebase.".to_string()
        };
    }

    let mut by_category: std::collections::HashMap<String, Vec<&CPGNode>> = std::collections::HashMap::new();
    for sink in &sink_nodes {
        for s in &config.sinks {
            if matches_pattern(&sink.name, &s.pattern) {
                by_category.entry(s.category.clone()).or_default().push(sink);
                break;
            }
        }
    }

    let uf: HashSet<&str> = sink_nodes.iter().map(|n| n.file.as_str()).collect();
    let mut lines = vec![
        if let Some(ff) = &file_filter {
            format!("=== Sinks in {ff} ===")
        } else {
            format!("=== All sinks ({} across {} files) ===", sink_nodes.len(), uf.len())
        },
        String::new(),
    ];

    let mut cats: Vec<_> = by_category.iter().collect();
    cats.sort_by_key(|(k, _)| (*k).clone());
    for (cat, nodes) in cats {
        lines.push(format!("{cat} ({}):", nodes.len()));
        for n in nodes.iter().take(20) {
            lines.push(format!("  {}:{:>5}  {}", n.file, n.line, n.name));
        }
        if nodes.len() > 20 { lines.push(format!("  ... and {} more", nodes.len() - 20)); }
        lines.push(String::new());
    }
    lines.join("\n")
}

