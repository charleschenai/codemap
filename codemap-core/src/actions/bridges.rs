use crate::types::*;

/// Show all cross-language bridges detected in the codebase.
/// If target is provided, filter to that file.
pub fn bridges(graph: &Graph, target: &str) -> String {
    let mut lines = Vec::new();
    let mut total = 0usize;

    let nodes: Vec<&GraphNode> = if target.is_empty() || target == "." {
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

/// Show all module monkey-patches detected.
pub fn monkey_patches(graph: &Graph) -> String {
    let mut lines = Vec::new();
    let mut total = 0usize;

    let mut nodes: Vec<&GraphNode> = graph.nodes.values().collect();
    nodes.sort_by(|a, b| a.id.cmp(&b.id));

    for node in &nodes {
        let patches: Vec<&BridgeInfo> = node.bridges.iter()
            .filter(|b| b.kind == BridgeKind::MonkeyPatch)
            .collect();
        if patches.is_empty() {
            continue;
        }
        lines.push(format!("  {}:", node.id));
        for b in &patches {
            let target = b.target.as_deref().unwrap_or("?");
            let ns = b.namespace.as_deref().unwrap_or("");
            lines.push(format!("    L{:<4} {} → {} (was {})", b.line, ns, target, b.name));
            total += 1;
        }
    }

    if total == 0 {
        return "No monkey-patches detected.".to_string();
    }

    format!("=== Monkey-Patches ({total} detected) ===\n\n{}", lines.join("\n"))
}

/// Show op dispatch map: op name → per-device implementations.
pub fn dispatch_map(graph: &Graph) -> String {
    let mut ops: std::collections::HashMap<String, Vec<(String, String, usize)>> = std::collections::HashMap::new();

    for node in graph.nodes.values() {
        for b in &node.bridges {
            match b.kind {
                BridgeKind::TorchLibrary | BridgeKind::YamlDispatch => {
                    let device = b.namespace.as_deref().unwrap_or("default");
                    let target = b.target.as_deref().unwrap_or(&b.name);
                    ops.entry(b.name.clone())
                        .or_default()
                        .push((device.to_string(), target.to_string(), b.line));
                }
                _ => {}
            }
        }
    }

    if ops.is_empty() {
        return "No dispatch mappings found.".to_string();
    }

    let mut sorted: Vec<_> = ops.into_iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let mut lines = Vec::new();
    for (op, impls) in &sorted {
        lines.push(format!("  {op}:"));
        for (device, target, line) in impls {
            lines.push(format!("    [{device}] → {target} (L{line})"));
        }
    }

    format!("=== Dispatch Map ({} ops) ===\n\n{}", sorted.len(), lines.join("\n"))
}
