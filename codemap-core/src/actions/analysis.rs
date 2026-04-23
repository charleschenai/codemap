use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use regex::Regex;
use crate::types::{Graph, escape_regex};
use crate::utils::format_number;

fn ext_of(path: &str) -> String {
    match path.rfind('.') {
        Some(i) if i < path.len() - 1 => path[i..].to_string(),
        _ => String::new(),
    }
}

fn basename_without_ext(path: &str) -> String {
    let name = match path.rfind('/') {
        Some(i) => &path[i + 1..],
        None => path,
    };
    match name.rfind('.') {
        Some(i) if i > 0 => name[..i].to_string(),
        _ => name.to_string(),
    }
}

// ── 1. stats ────────────────────────────────────────────────────────

pub fn stats(graph: &Graph) -> String {
    let mut total_lines: usize = 0;
    let mut total_imports: usize = 0;
    let mut total_urls: usize = 0;
    let mut total_exports: usize = 0;
    let mut exts: HashMap<String, usize> = HashMap::new();

    for (id, node) in &graph.nodes {
        total_lines += node.lines;
        total_imports += node.imports.len();
        total_urls += node.urls.len();
        total_exports += node.exports.len();
        let ext = ext_of(id);
        *exts.entry(ext).or_insert(0) += 1;
    }

    let mut lines = vec![
        "=== Codemap Stats ===".to_string(),
        format!("Files: {}", graph.nodes.len()),
        format!("Lines: {}", format_number(total_lines)),
        format!("Import edges: {}", total_imports),
        format!("External URLs: {}", total_urls),
        format!("Exports: {}", total_exports),
        String::new(),
        "By extension:".to_string(),
    ];

    let mut ext_vec: Vec<(String, usize)> = exts.into_iter().collect();
    ext_vec.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    for (ext, count) in &ext_vec {
        lines.push(format!("  {}: {}", ext, count));
    }

    lines.join("\n")
}

// ── 2. trace ────────────────────────────────────────────────────────

pub fn trace(graph: &Graph, target: &str) -> String {
    let node = match graph.find_node(target) {
        Some(n) => n,
        None => return format!("File not found: {}", target),
    };

    let mut lines = vec![
        format!("=== {} ({} lines) ===", node.id, node.lines),
        String::new(),
    ];

    if !node.imports.is_empty() {
        lines.push(format!("Imports ({}):", node.imports.len()));
        for imp in &node.imports {
            lines.push(format!("  \u{2192} {}", imp));
        }
        lines.push(String::new());
    }

    if !node.imported_by.is_empty() {
        lines.push(format!("Imported by ({}):", node.imported_by.len()));
        for imp in &node.imported_by {
            lines.push(format!("  \u{2190} {}", imp));
        }
        lines.push(String::new());
    }

    if !node.urls.is_empty() {
        lines.push(format!("URLs ({}):", node.urls.len()));
        for url in &node.urls {
            lines.push(format!("  \u{1f310} {}", url));
        }
        lines.push(String::new());
    }

    if !node.exports.is_empty() {
        lines.push(format!("Exports ({}):", node.exports.len()));
        for exp in &node.exports {
            lines.push(format!("  \u{25b8} {}", exp));
        }
    }

    if node.imports.is_empty() && node.imported_by.is_empty() && node.urls.is_empty() && node.exports.is_empty() {
        lines.push("(isolated file \u{2014} no imports, no importers, no URLs, no exports)".to_string());
    }

    lines.join("\n")
}

// ── 3. blast_radius ─────────────────────────────────────────────────

pub fn blast_radius(graph: &Graph, target: &str) -> String {
    let node = match graph.find_node(target) {
        Some(n) => n,
        None => return format!("File not found: {}", target),
    };

    let start_id = node.id.clone();
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    visited.insert(start_id.clone());
    queue.push_back(start_id.clone());

    while let Some(current) = queue.pop_front() {
        if let Some(n) = graph.nodes.get(&current) {
            for dep in &n.imported_by {
                if !visited.contains(dep) {
                    visited.insert(dep.clone());
                    queue.push_back(dep.clone());
                }
            }
        }
    }

    visited.remove(&start_id);
    let mut sorted: Vec<&String> = visited.iter().collect();
    sorted.sort();

    let mut lines = vec![
        format!("Blast radius for {}: {} files affected", start_id, sorted.len()),
        String::new(),
    ];
    for f in &sorted {
        lines.push(format!("  {}", f));
    }

    lines.join("\n")
}

// ── 4. phone_home ───────────────────────────────────────────────────

pub fn phone_home(graph: &Graph) -> String {
    let mut results: Vec<(String, Vec<String>)> = Vec::new();
    for (id, node) in &graph.nodes {
        if !node.urls.is_empty() {
            results.push((id.clone(), node.urls.clone()));
        }
    }

    if results.is_empty() {
        return "No external URLs found in codebase.".to_string();
    }

    results.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
    let mut lines = vec![
        format!("{} files with external URLs:", results.len()),
        String::new(),
    ];
    for r in &results {
        lines.push(format!("{} ({} URLs):", r.0, r.1.len()));
        for url in &r.1 {
            lines.push(format!("  {}", url));
        }
        lines.push(String::new());
    }

    lines.join("\n")
}

// ── 5. coupling ─────────────────────────────────────────────────────

pub fn coupling(graph: &Graph, target: &str) -> String {
    let mut results: Vec<String> = Vec::new();
    for (id, node) in &graph.nodes {
        if node.imports.iter().any(|imp| imp.contains(target)) {
            results.push(id.clone());
        }
    }

    if results.is_empty() {
        return format!("No files import \"{}\".", target);
    }
    results.sort();
    let mut lines = vec![
        format!("{} files coupled to \"{}\":", results.len(), target),
        String::new(),
    ];
    for f in &results {
        lines.push(format!("  {}", f));
    }

    lines.join("\n")
}

// ── 6. dead_files ───────────────────────────────────────────────────

pub fn dead_files(graph: &Graph) -> String {
    let entry_names: HashSet<&str> = ["index", "main", "cli", "app", "server", "entry"].iter().copied().collect();

    let mut dead: Vec<String> = Vec::new();
    for (id, node) in &graph.nodes {
        if node.imported_by.is_empty() {
            let base = basename_without_ext(id);
            if !entry_names.contains(base.as_str()) {
                dead.push(id.clone());
            }
        }
    }

    if dead.is_empty() {
        return "No dead files found (all files are imported by something).".to_string();
    }
    dead.sort();
    // Match TS: show entry names in insertion order
    let entry_list = ["index", "main", "cli", "app", "server", "entry"].join(", ");
    let mut lines = vec![
        format!("{} files with zero importers (excluding entry points: {}):", dead.len(), entry_list),
        String::new(),
    ];
    for f in &dead {
        lines.push(format!("  {}", f));
    }

    lines.join("\n")
}

// ── 7. circular ─────────────────────────────────────────────────────

pub fn circular(graph: &Graph) -> String {
    let mut cycles: Vec<Vec<String>> = Vec::new();
    let mut fully_processed: HashSet<String> = HashSet::new();
    let mut on_stack: HashSet<String> = HashSet::new();

    fn dfs(
        id: &str,
        path: &mut Vec<String>,
        graph: &Graph,
        cycles: &mut Vec<Vec<String>>,
        fully_processed: &mut HashSet<String>,
        on_stack: &mut HashSet<String>,
    ) {
        if fully_processed.contains(id) {
            return;
        }
        if on_stack.contains(id) {
            if let Some(cycle_start) = path.iter().position(|x| x == id) {
                cycles.push(path[cycle_start..].to_vec());
            }
            return;
        }
        on_stack.insert(id.to_string());
        path.push(id.to_string());

        if let Some(node) = graph.nodes.get(id) {
            for imp in &node.imports {
                if graph.nodes.contains_key(imp) {
                    dfs(imp, path, graph, cycles, fully_processed, on_stack);
                }
            }
        }

        path.pop();
        on_stack.remove(id);
        fully_processed.insert(id.to_string());
    }

    // Iterate in consistent order
    let mut all_ids: Vec<String> = graph.nodes.keys().cloned().collect();
    all_ids.sort();
    for id in &all_ids {
        if !fully_processed.contains(id) {
            dfs(id, &mut Vec::new(), graph, &mut cycles, &mut fully_processed, &mut on_stack);
        }
    }

    // Deduplicate cycles by canonical rotation
    let mut seen = HashSet::new();
    let mut unique: Vec<Vec<String>> = Vec::new();
    for cycle in &cycles {
        let mut min_idx = 0;
        for i in 1..cycle.len() {
            if cycle[i] < cycle[min_idx] {
                min_idx = i;
            }
        }
        let mut canonical = Vec::with_capacity(cycle.len());
        for i in 0..cycle.len() {
            canonical.push(cycle[(min_idx + i) % cycle.len()].as_str());
        }
        let key = canonical.join("\0");
        if !seen.contains(&key) {
            seen.insert(key);
            unique.push(cycle.clone());
        }
    }

    if unique.is_empty() {
        return "No circular dependencies found.".to_string();
    }
    let mut lines = vec![
        format!("{} circular dependencies:", unique.len()),
        String::new(),
    ];
    for cycle in unique.iter().take(20) {
        lines.push(format!("  {} \u{2192} {}", cycle.join(" \u{2192} "), cycle[0]));
    }
    if unique.len() > 20 {
        lines.push(format!("  ... and {} more", unique.len() - 20));
    }

    lines.join("\n")
}

// ── 8. list_exports ─────────────────────────────────────────────────

pub fn list_exports(graph: &Graph, target: &str) -> String {
    let node = match graph.find_node(target) {
        Some(n) => n,
        None => return format!("File not found: {}", target),
    };

    if node.exports.is_empty() {
        return format!("No exports found in {}", node.id);
    }

    let mut lines = vec![
        format!("Exports in {} ({}):", node.id, node.exports.len()),
        String::new(),
    ];
    for exp in &node.exports {
        lines.push(format!("  \u{25b8} {}", exp));
    }

    lines.join("\n")
}

// ── 9. callers ──────────────────────────────────────────────────────

pub fn callers(graph: &Graph, target: &str) -> String {
    let dir = &graph.scan_dir;
    let pattern = format!(r"\b{}\b", escape_regex(target));
    let re = match Regex::new(&pattern) {
        Ok(r) => r,
        Err(_) => return format!("Invalid regex for target: {}", target),
    };

    let mut results: Vec<(String, usize, String)> = Vec::new();
    let export_check = format!("export ");
    let fn_check = format!("function {}", target);

    let mut ids: Vec<String> = graph.nodes.keys().cloned().collect();
    ids.sort();

    'outer: for id in &ids {
        let path = Path::new(dir).join(id);
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for (i, line) in content.lines().enumerate() {
            if re.is_match(line) && !line.contains(&export_check) && !line.contains(&fn_check) {
                let text = line.trim();
                let text = if text.len() > 100 { &text[..100] } else { text };
                results.push((id.clone(), i + 1, text.to_string()));
                if results.len() >= 5000 {
                    break 'outer;
                }
            }
        }
    }

    if results.is_empty() {
        return format!("\"{}\" not found in any file.", target);
    }
    results.sort_by(|a, b| a.0.cmp(&b.0));
    let mut lines = vec![
        format!("\"{}\" found in {} locations:", target, results.len()),
        String::new(),
    ];
    for r in &results {
        lines.push(format!("  {}:{}  {}", r.0, r.1, r.2));
    }
    if results.len() >= 5000 {
        lines.push("  ... results capped at 5000".to_string());
    }

    lines.join("\n")
}

// ── 10. hotspots ────────────────────────────────────────────────────

pub fn hotspots(graph: &Graph) -> String {
    let mut scored: Vec<(String, usize, usize, usize)> = Vec::new();
    for (id, node) in &graph.nodes {
        let total = node.imports.len() + node.imported_by.len();
        if total > 0 {
            scored.push((id.clone(), node.imports.len(), node.imported_by.len(), total));
        }
    }
    scored.sort_by(|a, b| b.3.cmp(&a.3).then_with(|| a.0.cmp(&b.0)));
    let top: Vec<_> = scored.iter().take(30).collect();

    if top.is_empty() {
        return "No coupling found in codebase.".to_string();
    }
    let mut lines = vec![
        format!("=== Hotspots (top {} most coupled files) ===", top.len()),
        String::new(),
    ];
    for s in &top {
        lines.push(format!(
            "  {:>4} coupling  {}  ({}\u{2192} {}\u{2190})",
            s.3, s.0, s.1, s.2
        ));
    }

    lines.join("\n")
}

// ── 11. size ────────────────────────────────────────────────────────

pub fn size(graph: &Graph) -> String {
    let mut files: Vec<(String, usize)> = graph
        .nodes
        .iter()
        .map(|(id, node)| (id.clone(), node.lines))
        .collect();
    files.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let top: Vec<_> = files.iter().take(30).collect();
    if top.is_empty() {
        return "No files found.".to_string();
    }
    let total: usize = files.iter().map(|f| f.1).sum();
    let mut lines = vec![
        format!("=== File Size Ranking (top {} of {}) ===", top.len(), files.len()),
        format!("Total: {} lines", format_number(total)),
        String::new(),
    ];
    for f in &top {
        let pct = if total > 0 {
            (f.1 as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        lines.push(format!("  {:>6} lines  ({:>5.1}%)  {}", f.1, pct, f.0));
    }

    lines.join("\n")
}

// ── 12. layers ──────────────────────────────────────────────────────

pub fn layers(graph: &Graph) -> String {
    let mut roots: Vec<String> = Vec::new();
    for (id, node) in &graph.nodes {
        if node.imported_by.is_empty() {
            roots.push(id.clone());
        }
    }

    let mut depth: HashMap<String, i32> = HashMap::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<(String, i32)> = VecDeque::new();
    for r in &roots {
        queue.push_back((r.clone(), 0));
    }

    while let Some((id, d)) = queue.pop_front() {
        if visited.contains(&id) {
            continue;
        }
        visited.insert(id.clone());
        depth.insert(id.clone(), d);
        if let Some(node) = graph.nodes.get(&id) {
            for imp in &node.imports {
                if graph.nodes.contains_key(imp) && !visited.contains(imp) {
                    queue.push_back((imp.clone(), d + 1));
                }
            }
        }
    }

    // Files in cycles not reachable from roots get a special "cycle" marker
    for id in graph.nodes.keys() {
        if !depth.contains_key(id) {
            depth.insert(id.clone(), -1);
        }
    }

    // Group by depth
    let mut layer_map: HashMap<i32, Vec<String>> = HashMap::new();
    for (id, d) in &depth {
        layer_map.entry(*d).or_default().push(id.clone());
    }

    let mut sorted_layers: Vec<(i32, Vec<String>)> = layer_map.into_iter().collect();
    sorted_layers.sort_by_key(|(d, _)| *d);

    let max_depth = sorted_layers
        .iter()
        .map(|(d, _)| *d)
        .filter(|d| *d >= 0)
        .max()
        .unwrap_or(0);

    let label_guess = |d: i32, max: i32| -> &'static str {
        if d == -1 { return "cycle members"; }
        if d == 0 { return "entry points"; }
        if d == max { return "leaf modules"; }
        if d as f64 <= max as f64 * 0.3 { return "orchestration"; }
        if d as f64 <= max as f64 * 0.6 { return "services"; }
        "utilities"
    };

    let mut lines = vec![
        format!("=== Architecture Layers ({} levels) ===", sorted_layers.len()),
        String::new(),
    ];

    for (d, ref mut files) in &mut sorted_layers {
        files.sort();
        let label = if *d == -1 {
            "Cycle".to_string()
        } else {
            format!("Layer {}", d)
        };
        lines.push(format!(
            "{} \u{2014} {} ({} files):",
            label,
            label_guess(*d, max_depth),
            files.len()
        ));
        for f in files.iter().take(10) {
            lines.push(format!("  {}", f));
        }
        if files.len() > 10 {
            lines.push(format!("  ... and {} more", files.len() - 10));
        }
        lines.push(String::new());
    }

    // Check for cross-layer violations (deeper importing shallower)
    let mut violations: Vec<String> = Vec::new();
    for (id, node) in &graph.nodes {
        let my_depth = *depth.get(id).unwrap_or(&0);
        if my_depth < 0 {
            continue;
        }
        for imp in &node.imports {
            if let Some(&imp_depth) = depth.get(imp) {
                if imp_depth >= 0 && imp_depth < my_depth && (my_depth - imp_depth) > 1 {
                    violations.push(format!(
                        "  {} (L{}) \u{2192} {} (L{})",
                        id, my_depth, imp, imp_depth
                    ));
                }
            }
        }
    }
    if !violations.is_empty() {
        lines.push(format!(
            "Cross-layer imports ({} \u{2014} deeper importing shallower, skipping layers):",
            violations.len()
        ));
        for v in violations.iter().take(20) {
            lines.push(v.clone());
        }
        if violations.len() > 20 {
            lines.push(format!("  ... and {} more", violations.len() - 20));
        }
    }

    lines.join("\n")
}

// ── 13. diff ────────────────────────────────────────────────────────

pub fn diff(graph: &Graph, target: &str) -> String {
    let git_ref = target;
    if git_ref.is_empty() {
        return "Usage: codemap diff <git-ref>  (e.g. codemap diff HEAD~3, codemap diff main)".to_string();
    }

    // Reject refs starting with -
    if git_ref.starts_with('-') {
        return format!("Invalid git ref: \"{}\"", git_ref);
    }

    let output = match std::process::Command::new("git")
        .args(["diff", "--name-only", "--", git_ref])
        .current_dir(&graph.scan_dir)
        .output()
    {
        Ok(o) => o,
        Err(_) => {
            return format!(
                "Failed to run git diff against \"{}\". Make sure you're in a git repo.",
                git_ref
            );
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let msg = if stderr.is_empty() { "unknown error".to_string() } else { stderr };
        return format!("git error: {}", msg);
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        return format!("No files changed since {}.", git_ref);
    }

    let changed_files: Vec<String> = stdout.lines().filter(|f| !f.trim().is_empty()).map(|s| s.to_string()).collect();

    // Filter to files we scanned
    let relevant: Vec<String> = changed_files.iter().filter(|f| graph.nodes.contains_key(*f)).cloned().collect();
    if relevant.is_empty() {
        return format!(
            "{} files changed since {}, but none are in the scanned source.",
            changed_files.len(),
            git_ref
        );
    }

    // Compute combined blast radius
    let mut all_affected: HashSet<String> = HashSet::new();
    for file in &relevant {
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue = VecDeque::new();
        visited.insert(file.clone());
        queue.push_back(file.clone());
        while let Some(current) = queue.pop_front() {
            if let Some(n) = graph.nodes.get(&current) {
                for dep in &n.imported_by {
                    if !visited.contains(dep) {
                        visited.insert(dep.clone());
                        queue.push_back(dep.clone());
                    }
                }
            }
        }
        visited.remove(file);
        for v in visited {
            all_affected.insert(v);
        }
    }

    let mut lines = vec![
        format!("=== Diff Analysis: {} ===", git_ref),
        format!("Changed source files: {}", relevant.len()),
        format!("Total blast radius: {} additional files affected", all_affected.len()),
        String::new(),
        "Changed files:".to_string(),
    ];
    let mut relevant_sorted = relevant.clone();
    relevant_sorted.sort();
    for f in &relevant_sorted {
        lines.push(format!("  * {}", f));
    }

    if !all_affected.is_empty() {
        lines.push(String::new());
        lines.push("Affected by changes:".to_string());
        let mut affected_sorted: Vec<&String> = all_affected.iter().collect();
        affected_sorted.sort();
        for f in &affected_sorted {
            lines.push(format!("  {}", f));
        }
    }

    lines.join("\n")
}

// ── 14. orphan_exports ──────────────────────────────────────────────

pub fn orphan_exports(graph: &Graph) -> String {
    let dir = &graph.scan_dir;
    let mut orphans: Vec<(String, String)> = Vec::new();
    let mut content_cache: HashMap<String, String> = HashMap::new();

    let get_content = |id: &str, cache: &mut HashMap<String, String>| -> String {
        if let Some(c) = cache.get(id) {
            return c.clone();
        }
        let path = Path::new(dir).join(id);
        let content = std::fs::read_to_string(&path).unwrap_or_default();
        cache.insert(id.to_string(), content.clone());
        content
    };

    let mut ids: Vec<String> = graph.nodes.keys().cloned().collect();
    ids.sort();

    for id in &ids {
        let node = &graph.nodes[id];
        if node.exports.is_empty() {
            continue;
        }

        for exp in &node.exports {
            let pattern = format!(r"\b{}\b", escape_regex(exp));
            let re = match Regex::new(&pattern) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let mut found = false;
            for (other_id, other_node) in &graph.nodes {
                if other_id == id {
                    continue;
                }
                // Only check files that import this file
                if !other_node.imports.contains(id) {
                    continue;
                }
                let other_content = get_content(other_id, &mut content_cache);
                if !other_content.is_empty() && re.is_match(&other_content) {
                    found = true;
                    break;
                }
            }
            if !found {
                orphans.push((id.clone(), exp.clone()));
            }
        }
    }

    if orphans.is_empty() {
        return "No orphan exports found \u{2014} all exports are used somewhere.".to_string();
    }
    orphans.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let mut lines = vec![
        format!("{} orphan exports (exported but never imported):", orphans.len()),
        String::new(),
    ];
    let mut last_file = "";
    for o in orphans.iter().take(100) {
        if o.0 != last_file {
            lines.push(format!("  {}:", o.0));
            last_file = &o.0;
        }
        lines.push(format!("    \u{25b8} {}", o.1));
    }
    if orphans.len() > 100 {
        lines.push(format!("  ... and {} more", orphans.len() - 100));
    }

    lines.join("\n")
}
