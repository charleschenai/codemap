use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::process::Command;

use regex::Regex;

use crate::types::Graph;

// ── call_graph ──────────────────────────────────────────────────────

pub fn call_graph(graph: &Graph, target: &str) -> String {
    // Build export map: fn name → vec of file ids that export it
    let mut export_map: HashMap<&str, Vec<&str>> = HashMap::new();
    for node in graph.nodes.values() {
        for f in &node.functions {
            if f.is_exported {
                export_map.entry(f.name.as_str()).or_default().push(node.id.as_str());
            }
        }
    }

    // Determine which files to scan
    let files_to_scan: Vec<&str> = if !target.is_empty() {
        match graph.find_node(target) {
            Some(n) => vec![n.id.as_str()],
            None => return format!("No cross-function calls found in {target}."),
        }
    } else {
        graph.nodes.keys().map(|k| k.as_str()).collect()
    };

    struct Edge {
        from: String,
        from_func: String,
        to: String,
        to_func: String,
    }

    let mut edges: Vec<Edge> = Vec::new();

    for file_id in &files_to_scan {
        let node = match graph.nodes.get(*file_id) {
            Some(n) => n,
            None => continue,
        };

        for f in &node.functions {
            for call_name in &f.calls {
                let imported_files: HashSet<&str> = node
                    .imports
                    .iter()
                    .filter(|i| graph.nodes.contains_key(i.as_str()))
                    .map(|i| i.as_str())
                    .collect();

                let targets = match export_map.get(call_name.as_str()) {
                    Some(t) => t,
                    None => continue,
                };

                for target_file in targets {
                    if imported_files.contains(target_file) || *target_file == *file_id {
                        edges.push(Edge {
                            from: file_id.to_string(),
                            from_func: f.name.clone(),
                            to: target_file.to_string(),
                            to_func: call_name.clone(),
                        });
                    }
                }
            }
        }
    }

    if edges.is_empty() {
        return if !target.is_empty() {
            format!("No cross-function calls found in {target}.")
        } else {
            "No cross-file function calls found.".to_string()
        };
    }

    // Group by source:func
    let mut grouped: HashMap<String, Vec<&Edge>> = HashMap::new();
    for e in &edges {
        let key = format!("{}:{}", e.from, e.from_func);
        grouped.entry(key).or_default().push(e);
    }

    let mut sorted: Vec<(String, Vec<&Edge>)> = grouped.into_iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let header = if !target.is_empty() {
        format!("=== Call Graph for {target} ({} cross-function calls) ===", edges.len())
    } else {
        format!("=== Call Graph ({} cross-function calls) ===", edges.len())
    };

    let mut lines = vec![header, String::new()];
    for (source, calls) in sorted.iter().take(50) {
        lines.push(format!("  {source}:"));
        for c in calls {
            lines.push(format!("    \u{2192} {}:{}", c.to, c.to_func));
        }
    }
    if sorted.len() > 50 {
        lines.push(format!("  ... and {} more", sorted.len() - 50));
    }
    lines.join("\n")
}

// ── dead_functions ──────────────────────────────────────────────────

pub fn dead_functions(graph: &Graph) -> String {
    // Build map: fn name → set of file ids that call it
    let mut all_calls: HashMap<&str, HashSet<&str>> = HashMap::new();
    for node in graph.nodes.values() {
        for f in &node.functions {
            for call_name in &f.calls {
                all_calls
                    .entry(call_name.as_str())
                    .or_default()
                    .insert(node.id.as_str());
            }
        }
    }

    struct DeadFn {
        file: String,
        name: String,
        line: usize,
    }

    let mut dead: Vec<DeadFn> = Vec::new();

    for node in graph.nodes.values() {
        for f in &node.functions {
            if !f.is_exported {
                continue;
            }
            let called_externally = match all_calls.get(f.name.as_str()) {
                Some(caller_set) => caller_set.iter().any(|caller_id| *caller_id != node.id),
                None => false,
            };
            if !called_externally {
                dead.push(DeadFn {
                    file: node.id.clone(),
                    name: f.name.clone(),
                    line: f.start_line,
                });
            }
        }
    }

    if dead.is_empty() {
        return "No dead exported functions found.".to_string();
    }

    dead.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));

    let mut lines = vec![
        format!("{} exported functions with no external callers:", dead.len()),
        String::new(),
    ];
    let mut last_file = "";
    for d in dead.iter().take(100) {
        if d.file != last_file {
            lines.push(format!("  {}:", d.file));
            last_file = &d.file;
        }
        lines.push(format!("    L{}  {}()", d.line, d.name));
    }
    if dead.len() > 100 {
        lines.push(format!("  ... and {} more", dead.len() - 100));
    }
    lines.join("\n")
}

// ── fn_info ─────────────────────────────────────────────────────────

pub fn fn_info(graph: &Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap fn-info <file>".to_string();
    }
    let node = match graph.find_node(target) {
        Some(n) => n,
        None => return format!("File not found: {target}"),
    };

    if node.functions.is_empty() {
        return format!("No functions found in {}", node.id);
    }

    let mut lines = vec![
        format!("=== Functions in {} ({}) ===", node.id, node.functions.len()),
        String::new(),
    ];
    for f in &node.functions {
        let exported = if f.is_exported { " [exported]" } else { "" };
        let call_list = if !f.calls.is_empty() {
            format!(" \u{2192} calls: {}", f.calls.join(", "))
        } else {
            String::new()
        };
        lines.push(format!(
            "  L{}-{}  {}(){exported}{call_list}",
            f.start_line, f.end_line, f.name
        ));
    }
    lines.join("\n")
}

// ── diff_functions ──────────────────────────────────────────────────

pub fn diff_functions(graph: &Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap diff-functions <git-ref>".to_string();
    }
    if target.starts_with('-') {
        return format!("Invalid git ref: \"{target}\"");
    }

    let changed_files = match git_diff_name_only(graph, target) {
        GitDiffResult::Ok(files) => files,
        GitDiffResult::Error(e) => return e,
        GitDiffResult::Empty => return format!("No files changed since {target}."),
    };

    let relevant: Vec<&str> = changed_files
        .iter()
        .filter(|f| graph.nodes.contains_key(f.as_str()))
        .map(|f| f.as_str())
        .collect();

    if relevant.is_empty() {
        return format!(
            "{} files changed but none in scanned source.",
            changed_files.len()
        );
    }

    struct FnChange {
        file: String,
        name: String,
    }

    let mut added: Vec<FnChange> = Vec::new();
    let mut removed: Vec<FnChange> = Vec::new();
    let mut modified: Vec<FnChange> = Vec::new();

    let func_re =
        Regex::new(r"(?:export\s+)?(?:async\s+)?(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\()").unwrap();

    for file_id in &relevant {
        let current_node = match graph.nodes.get(*file_id) {
            Some(n) => n,
            None => continue,
        };

        let current_funcs: HashMap<&str, &crate::types::FunctionInfo> =
            current_node.functions.iter().map(|f| (f.name.as_str(), f)).collect();

        let old_content = match git_show(graph, target, file_id) {
            GitShowResult::Ok(content) => content,
            GitShowResult::NotFound => {
                // File didn't exist — all functions are new
                for name in current_funcs.keys() {
                    added.push(FnChange { file: file_id.to_string(), name: name.to_string() });
                }
                continue;
            }
            GitShowResult::Error => continue,
        };

        // Parse old version for function names
        let mut old_func_names: HashSet<String> = HashSet::new();
        for caps in func_re.captures_iter(&old_content) {
            let name = caps.get(1).or_else(|| caps.get(2));
            if let Some(m) = name {
                old_func_names.insert(m.as_str().to_string());
            }
        }

        for name in current_funcs.keys() {
            if !old_func_names.contains(*name) {
                added.push(FnChange { file: file_id.to_string(), name: name.to_string() });
            }
        }
        for name in &old_func_names {
            if !current_funcs.contains_key(name.as_str()) {
                removed.push(FnChange { file: file_id.to_string(), name: name.clone() });
            } else {
                modified.push(FnChange { file: file_id.to_string(), name: name.clone() });
            }
        }
    }

    let mut lines = vec![
        format!("=== Function Changes: {target} ==="),
        format!("Files changed: {}", relevant.len()),
        String::new(),
    ];

    if !added.is_empty() {
        lines.push(format!("Added functions ({}):", added.len()));
        for f in &added {
            lines.push(format!("  + {}:{}()", f.file, f.name));
        }
        lines.push(String::new());
    }
    if !removed.is_empty() {
        lines.push(format!("Removed functions ({}):", removed.len()));
        for f in &removed {
            lines.push(format!("  - {}:{}()", f.file, f.name));
        }
        lines.push(String::new());
    }
    if !modified.is_empty() {
        lines.push(format!(
            "Possibly modified ({} \u{2014} present in both versions):",
            modified.len()
        ));
        for f in modified.iter().take(30) {
            lines.push(format!("  ~ {}:{}()", f.file, f.name));
        }
        if modified.len() > 30 {
            lines.push(format!("  ... and {} more", modified.len() - 30));
        }
    }
    if added.is_empty() && removed.is_empty() && modified.is_empty() {
        lines.push("No function-level changes detected.".to_string());
    }
    lines.join("\n")
}

// ── complexity ──────────────────────────────────────────────────────

pub fn complexity(graph: &Graph, target: &str) -> String {
    let files_to_check: Vec<&str> = if !target.is_empty() {
        match graph.find_node(target) {
            Some(n) => vec![n.id.as_str()],
            None => return format!("No functions found in {target}."),
        }
    } else {
        graph.nodes.keys().map(|k| k.as_str()).collect()
    };

    struct ComplexityResult {
        file: String,
        name: String,
        complexity: usize,
        line: usize,
    }

    let mut results: Vec<ComplexityResult> = Vec::new();

    // Cache file contents, read each file once
    let mut content_cache: HashMap<&str, Vec<String>> = HashMap::new();

    let branch_re =
        Regex::new(r"\b(if|else if|for|while|do|switch|case|catch)\b|\?\?|&&|\|\||\?(?=[^?.])")
            .unwrap();

    for file_id in &files_to_check {
        let node = match graph.nodes.get(*file_id) {
            Some(n) => n,
            None => continue,
        };

        let file_lines = content_cache.entry(file_id).or_insert_with(|| {
            let path = Path::new(&graph.scan_dir).join(file_id);
            match std::fs::read_to_string(&path) {
                Ok(content) => content.split('\n').map(|s| s.to_string()).collect(),
                Err(_) => Vec::new(),
            }
        });

        if file_lines.is_empty() {
            continue;
        }

        for f in &node.functions {
            let mut cc: usize = 1;
            let start = if f.start_line > 0 { f.start_line - 1 } else { 0 };
            let end = f.end_line.min(file_lines.len());
            for line in &file_lines[start..end] {
                for _ in branch_re.find_iter(line) {
                    cc += 1;
                }
            }
            results.push(ComplexityResult {
                file: file_id.to_string(),
                name: f.name.clone(),
                complexity: cc,
                line: f.start_line,
            });
        }
    }

    results.sort_by(|a, b| b.complexity.cmp(&a.complexity));

    let top: &[ComplexityResult] = if !target.is_empty() {
        &results
    } else {
        if results.len() > 30 { &results[..30] } else { &results }
    };

    if top.is_empty() {
        return if !target.is_empty() {
            format!("No functions found in {target}.")
        } else {
            "No functions found.".to_string()
        };
    }

    let header = if !target.is_empty() {
        format!("=== Cyclomatic Complexity \u{2014} {target} ===")
    } else {
        "=== Cyclomatic Complexity (top 30) ===".to_string()
    };

    let mut lines = vec![header, String::new()];
    for r in top {
        let label = if r.complexity > 10 {
            " [HIGH]"
        } else if r.complexity > 5 {
            " [moderate]"
        } else {
            ""
        };
        lines.push(format!(
            "  {:>3} complexity  {}:{}() L{}{label}",
            r.complexity, r.file, r.name, r.line
        ));
    }
    lines.join("\n")
}

// ── import_cost ─────────────────────────────────────────────────────

pub fn import_cost(graph: &Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap import-cost <file>".to_string();
    }
    let node = match graph.find_node(target) {
        Some(n) => n,
        None => return format!("File not found: {target}"),
    };

    // BFS transitive imports
    let mut visited: HashSet<&str> = HashSet::new();
    visited.insert(node.id.as_str());
    let mut queue: VecDeque<&str> = VecDeque::new();
    queue.push_back(node.id.as_str());
    let mut total_lines: usize = 0;
    let mut total_files: usize = 0;

    while let Some(current) = queue.pop_front() {
        let n = match graph.nodes.get(current) {
            Some(n) => n,
            None => continue,
        };
        total_lines += n.lines;
        total_files += 1;
        for imp in &n.imports {
            if graph.nodes.contains_key(imp.as_str()) && !visited.contains(imp.as_str()) {
                visited.insert(imp.as_str());
                queue.push_back(imp.as_str());
            }
        }
    }

    let direct_imports = node
        .imports
        .iter()
        .filter(|i| graph.nodes.contains_key(i.as_str()))
        .count();

    let mut lines = vec![
        format!("=== Import Cost: {} ===", node.id),
        String::new(),
        format!("Direct imports: {direct_imports}"),
        format!("Transitive imports: {} files", total_files - 1),
        format!("Total lines pulled in: {}", format_number(total_lines)),
        String::new(),
        "Heaviest transitive deps:".to_string(),
    ];

    let mut deps: Vec<(&str, usize)> = visited
        .iter()
        .filter(|id| **id != node.id)
        .map(|id| (*id, graph.nodes.get(*id).map(|n| n.lines).unwrap_or(0)))
        .collect();
    deps.sort_by(|a, b| b.1.cmp(&a.1));

    for d in deps.iter().take(15) {
        lines.push(format!("  {:>6} lines  {}", d.1, d.0));
    }
    if deps.len() > 15 {
        lines.push(format!("  ... and {} more", deps.len() - 15));
    }
    lines.join("\n")
}

// ── churn ───────────────────────────────────────────────────────────

pub fn churn(graph: &Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap churn <git-ref>  (e.g. codemap churn HEAD~50)".to_string();
    }
    if target.starts_with('-') {
        return format!("Invalid git ref: \"{target}\"");
    }

    let log_output = match Command::new("git")
        .args(["log", "--format=", "--name-only", "--", &format!("{target}..HEAD")])
        .current_dir(&graph.scan_dir)
        .output()
    {
        Ok(result) => {
            if !result.status.success() {
                let stderr = String::from_utf8_lossy(&result.stderr).trim().to_string();
                return format!("git error: {stderr}");
            }
            String::from_utf8_lossy(&result.stdout).to_string()
        }
        Err(_) => return "Failed to run git log.".to_string(),
    };

    let mut change_counts: HashMap<&str, usize> = HashMap::new();
    for line in log_output.lines() {
        let file = line.trim();
        if !file.is_empty() && graph.nodes.contains_key(file) {
            *change_counts.entry(file).or_insert(0) += 1;
        }
    }

    if change_counts.is_empty() {
        return format!("No source file changes found since {target}.");
    }

    struct RiskEntry {
        id: String,
        changes: usize,
        coupling: usize,
        risk: usize,
    }

    let mut risks: Vec<RiskEntry> = Vec::new();
    for (id, changes) in &change_counts {
        let node = match graph.nodes.get(*id) {
            Some(n) => n,
            None => continue,
        };
        let coupling = node.imports.len() + node.imported_by.len();
        risks.push(RiskEntry {
            id: id.to_string(),
            changes: *changes,
            coupling,
            risk: changes * coupling,
        });
    }
    risks.sort_by(|a, b| b.risk.cmp(&a.risk));

    let mut lines = vec![
        format!("=== Churn Risk: {target}..HEAD ==="),
        format!("Files changed: {}", change_counts.len()),
        String::new(),
        "  Risk  Changes  Coupling  File".to_string(),
    ];
    for r in risks.iter().take(30) {
        lines.push(format!(
            "  {:>5}  {:>7}  {:>8}  {}",
            r.risk, r.changes, r.coupling, r.id
        ));
    }
    if risks.len() > 30 {
        lines.push(format!("  ... and {} more", risks.len() - 30));
    }
    lines.join("\n")
}

// ── api_diff ────────────────────────────────────────────────────────

pub fn api_diff(graph: &Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap api-diff <git-ref>".to_string();
    }
    if target.starts_with('-') {
        return format!("Invalid git ref: \"{target}\"");
    }

    let changed_files = match git_diff_name_only(graph, target) {
        GitDiffResult::Ok(files) => files,
        GitDiffResult::Error(e) => return e,
        GitDiffResult::Empty => return format!("No files changed since {target}."),
    };

    let relevant: Vec<&str> = changed_files
        .iter()
        .filter(|f| graph.nodes.contains_key(f.as_str()))
        .map(|f| f.as_str())
        .collect();

    if relevant.is_empty() {
        return "No source files changed.".to_string();
    }

    struct ExportChange {
        file: String,
        name: String,
    }

    let mut added: Vec<ExportChange> = Vec::new();
    let mut removed: Vec<ExportChange> = Vec::new();

    let export_re = Regex::new(
        r"export\s+(?:const|let|var|function|async\s+function|class|type|interface|enum)\s+(\w+)",
    )
    .unwrap();

    for file_id in &relevant {
        let current_node = match graph.nodes.get(*file_id) {
            Some(n) => n,
            None => continue,
        };
        let current_exports: HashSet<&str> = current_node.exports.iter().map(|e| e.as_str()).collect();

        let old_content = match git_show(graph, target, file_id) {
            GitShowResult::Ok(content) => content,
            GitShowResult::NotFound => {
                // File didn't exist before — all exports are new
                for name in &current_exports {
                    added.push(ExportChange { file: file_id.to_string(), name: name.to_string() });
                }
                continue;
            }
            GitShowResult::Error => continue,
        };

        let mut old_exports: HashSet<String> = HashSet::new();
        for caps in export_re.captures_iter(&old_content) {
            if let Some(m) = caps.get(1) {
                old_exports.insert(m.as_str().to_string());
            }
        }

        for name in &current_exports {
            if !old_exports.contains(*name) {
                added.push(ExportChange { file: file_id.to_string(), name: name.to_string() });
            }
        }
        for name in &old_exports {
            if !current_exports.contains(name.as_str()) {
                removed.push(ExportChange { file: file_id.to_string(), name: name.clone() });
            }
        }
    }

    let mut lines = vec![
        format!("=== API Diff: {target} ==="),
        format!("Files with export changes: {}", relevant.len()),
        String::new(),
    ];

    if !added.is_empty() {
        lines.push(format!("Added exports ({}):", added.len()));
        for e in &added {
            lines.push(format!("  + {}:{}", e.file, e.name));
        }
        lines.push(String::new());
    }
    if !removed.is_empty() {
        lines.push(format!("Removed exports ({}):", removed.len()));
        for e in &removed {
            lines.push(format!("  - {}:{}", e.file, e.name));
        }
    }
    if added.is_empty() && removed.is_empty() {
        lines.push("No export changes detected.".to_string());
    }
    lines.join("\n")
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Format a number with locale-style thousands separators (commas).
fn format_number(n: usize) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len <= 3 {
        return s;
    }
    let mut result = String::with_capacity(len + len / 3);
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            result.push(',');
        }
        result.push(b as char);
    }
    result
}

enum GitDiffResult {
    Ok(Vec<String>),
    Error(String),
    Empty,
}

/// Run `git diff --name-only -- <ref>` and return changed files.
fn git_diff_name_only(graph: &Graph, git_ref: &str) -> GitDiffResult {
    match Command::new("git")
        .args(["diff", "--name-only", "--", git_ref])
        .current_dir(&graph.scan_dir)
        .output()
    {
        Ok(result) => {
            if !result.status.success() {
                let stderr = String::from_utf8_lossy(&result.stderr).trim().to_string();
                return GitDiffResult::Error(format!("git error: {stderr}"));
            }
            let output = String::from_utf8_lossy(&result.stdout).trim().to_string();
            if output.is_empty() {
                return GitDiffResult::Empty;
            }
            let files: Vec<String> = output
                .lines()
                .filter(|f| !f.trim().is_empty())
                .map(|f| f.to_string())
                .collect();
            GitDiffResult::Ok(files)
        }
        Err(_) => GitDiffResult::Error(format!("Failed to run git diff against \"{git_ref}\".")),
    }
}

enum GitShowResult {
    Ok(String),
    NotFound,
    Error,
}

/// Run `git show <ref>:<file>` and return file content.
fn git_show(graph: &Graph, git_ref: &str, file_id: &str) -> GitShowResult {
    match Command::new("git")
        .args(["show", "--", &format!("{git_ref}:{file_id}")])
        .current_dir(&graph.scan_dir)
        .output()
    {
        Ok(result) => {
            if !result.status.success() {
                // File didn't exist at that ref
                return GitShowResult::NotFound;
            }
            GitShowResult::Ok(String::from_utf8_lossy(&result.stdout).to_string())
        }
        Err(_) => GitShowResult::Error,
    }
}
