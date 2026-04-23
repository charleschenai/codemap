use crate::types::*;

/// Show all cross-language bridges detected in the codebase.
/// If target is provided, filter to that file.
pub fn bridges(graph: &Graph, target: &str) -> String {
    let mut lines = Vec::new();
    let mut total = 0usize;

    let nodes: Vec<&GraphNode> = if target.is_empty() {
        let mut ns: Vec<&GraphNode> = graph.nodes.values().collect();
        ns.sort_by(|a, b| a.id.cmp(&b.id));
        ns
    } else {
        match graph.find_node(target) {
            Some(n) => vec![n],
            None => return format!("File not found: {target}"),
        }
    };

    for node in &nodes {
        if node.bridges.is_empty() {
            continue;
        }
        lines.push(format!("  {}:", node.id));
        for b in &node.bridges {
            let kind = b.kind.as_str();
            let target_str = b.target.as_deref().unwrap_or("-");
            let ns_str = b.namespace.as_ref().map(|n| format!(" ns={n}")).unwrap_or_default();
            lines.push(format!("    L{:<4} [{kind}] {}{ns_str} → {target_str}", b.line, b.name));
            total += 1;
        }
    }

    if total == 0 {
        return "No cross-language bridges detected.".to_string();
    }

    format!("=== Cross-Language Bridges ({total} detected) ===\n\n{}", lines.join("\n"))
}

/// Show all GPU-tagged functions (CUDA kernels, Triton JIT kernels).
pub fn gpu_functions(graph: &Graph) -> String {
    let mut lines = Vec::new();
    let mut total = 0usize;

    let mut nodes: Vec<&GraphNode> = graph.nodes.values().collect();
    nodes.sort_by(|a, b| a.id.cmp(&b.id));

    for node in &nodes {
        let gpu: Vec<&BridgeInfo> = node.bridges.iter()
            .filter(|b| b.kind.is_gpu())
            .collect();
        if gpu.is_empty() {
            continue;
        }
        lines.push(format!("  {}:", node.id));
        for b in &gpu {
            let kind = b.kind.as_str();
            let target_str = b.target.as_deref().unwrap_or(&b.name);
            lines.push(format!("    L{:<4} [{kind}] {target_str}", b.line));
            total += 1;
        }
    }

    if total == 0 {
        return "No GPU functions detected.".to_string();
    }

    format!("=== GPU Functions ({total} detected) ===\n\n{}", lines.join("\n"))
}
