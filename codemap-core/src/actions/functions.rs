use std::cmp::Reverse;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::process::Command;

use regex::Regex;

use crate::types::Graph;
use crate::utils::format_number;

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
    let files_to_scan: Vec<&str> = if !target.is_empty() && target != "." {
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

    // Match function definitions across languages:
    // JS/TS: function foo, const foo = (, export async function foo
    // Rust: fn foo, pub fn foo, pub async fn foo
    // Python: def foo
    // Go: func foo
    // Ruby: def foo
    // Java/PHP: public function foo, private function foo, protected function foo
    let func_re = Regex::new(concat!(
        r"(?:export\s+)?(?:async\s+)?(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\()",
        r"|(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)",
        r"|def\s+(\w+)",
        r"|func\s+(\w+)",
        r"|(?:public|private|protected|static|\s)+\s+function\s+(\w+)",
    )).unwrap();

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
            let name = caps.get(1)
                .or_else(|| caps.get(2))
                .or_else(|| caps.get(3))
                .or_else(|| caps.get(4))
                .or_else(|| caps.get(5))
                .or_else(|| caps.get(6));
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
    let files_to_check: Vec<&str> = if !target.is_empty() && target != "." {
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

    // Rust regex doesn't support lookahead, so we use two regexes
    let keyword_re = Regex::new(r"\b(if|else if|for|while|do|switch|case|catch)\b").unwrap();
    let operator_re = Regex::new(r"\?\?|&&|\|\|").unwrap();
    // For ternary ?, we count ? that aren't ?? or ?. (optional chaining)
    let ternary_re = Regex::new(r"\?[^?.]").unwrap();

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
                for _ in keyword_re.find_iter(line).chain(operator_re.find_iter(line)).chain(ternary_re.find_iter(line)) {
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

    results.sort_by_key(|a| Reverse(a.complexity));

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
    deps.sort_by_key(|a| Reverse(a.1));

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
        .args(["log", "--format=", "--name-only", &format!("{target}..HEAD")])
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
    risks.sort_by_key(|a| Reverse(a.risk));

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

enum GitDiffResult {
    Ok(Vec<String>),
    Error(String),
    Empty,
}

/// Run `git diff --name-only -- <ref>` and return changed files.
fn git_diff_name_only(graph: &Graph, git_ref: &str) -> GitDiffResult {
    match Command::new("git")
        .args(["diff", "--name-only", git_ref])
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
        .args(["show", &format!("{git_ref}:{file_id}")])
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

// ── diff-impact ────────────────────────────────────────────────────

pub fn diff_impact(graph: &Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap diff-impact <git-ref>  (e.g. codemap diff-impact HEAD~3)".to_string();
    }
    if target.starts_with('-') {
        return format!("Invalid git ref: \"{target}\"");
    }

    let changed_files = match git_diff_name_only(graph, target) {
        GitDiffResult::Ok(files) => files,
        GitDiffResult::Error(e) => return e,
        GitDiffResult::Empty => return format!("No files changed since {target}."),
    };

    let relevant: Vec<String> = changed_files.iter()
        .filter(|f| graph.nodes.contains_key(f.as_str()))
        .cloned()
        .collect();

    if relevant.is_empty() {
        return format!("{} files changed but none in scanned source.", changed_files.len());
    }

    // BFS blast radius per file
    let mut all_affected: HashMap<String, Vec<String>> = HashMap::new(); // affected -> vec of sources
    for file in &relevant {
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue = VecDeque::new();
        visited.insert(file.clone());
        queue.push_back(file.clone());
        while let Some(current) = queue.pop_front() {
            if let Some(n) = graph.nodes.get(&current) {
                for dep in &n.imported_by {
                    if !visited.contains(dep) && !relevant.contains(dep) {
                        visited.insert(dep.clone());
                        queue.push_back(dep.clone());
                        all_affected.entry(dep.clone()).or_default().push(file.clone());
                    }
                }
            }
        }
    }

    // Function-level changes
    let func_re = Regex::new(concat!(
        r"(?:export\s+)?(?:async\s+)?(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\()",
        r"|(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)",
        r"|def\s+(\w+)",
        r"|func\s+(\w+)",
    )).unwrap();

    let mut changed_fns: Vec<(String, String)> = Vec::new();
    for file in &relevant {
        if let Some(node) = graph.nodes.get(file) {
            let old_content = match git_show(graph, target, file) {
                GitShowResult::Ok(c) => c,
                _ => { // New file — all functions are new
                    for f in &node.functions {
                        changed_fns.push((file.clone(), format!("+ {}()", f.name)));
                    }
                    continue;
                }
            };
            let mut old_fns: HashSet<String> = HashSet::new();
            for caps in func_re.captures_iter(&old_content) {
                let name = caps.get(1).or(caps.get(2)).or(caps.get(3)).or(caps.get(4)).or(caps.get(5));
                if let Some(m) = name { old_fns.insert(m.as_str().to_string()); }
            }
            let cur_fns: HashSet<String> = node.functions.iter().map(|f| f.name.clone()).collect();
            for name in cur_fns.difference(&old_fns) {
                changed_fns.push((file.clone(), format!("+ {}()", name)));
            }
            for name in old_fns.difference(&cur_fns) {
                changed_fns.push((file.clone(), format!("- {}()", name)));
            }
            for name in cur_fns.intersection(&old_fns) {
                changed_fns.push((file.clone(), format!("~ {}()", name)));
            }
        }
    }

    let mut lines = vec![
        format!("=== Diff Impact: {} ===", target),
        format!("{} files changed, {} functions affected, {} files in blast radius",
            relevant.len(), changed_fns.len(), all_affected.len()),
        String::new(),
        "Changed files:".to_string(),
    ];

    let mut sorted = relevant.clone();
    sorted.sort();
    for f in &sorted {
        let fn_changes: Vec<&str> = changed_fns.iter()
            .filter(|(file, _)| file == f)
            .map(|(_, change)| change.as_str())
            .collect();
        let coupling = graph.nodes.get(f).map(|n| n.imports.len() + n.imported_by.len()).unwrap_or(0);
        lines.push(format!("  * {} (coupling: {})", f, coupling));
        for fc in fn_changes.iter().take(10) {
            lines.push(format!("      {}", fc));
        }
        if fn_changes.len() > 10 {
            lines.push(format!("      ... and {} more", fn_changes.len() - 10));
        }
    }

    if !all_affected.is_empty() {
        lines.push(String::new());
        lines.push(format!("Blast radius ({} files):", all_affected.len()));
        let mut affected_sorted: Vec<(&String, &Vec<String>)> = all_affected.iter().collect();
        affected_sorted.sort_by_key(|(id, _)| *id);
        for (id, sources) in affected_sorted.iter().take(20) {
            let short_sources: Vec<&str> = sources.iter()
                .map(|s| s.rsplit('/').next().unwrap_or(s))
                .collect();
            lines.push(format!("    {} (via {})", id, short_sources.join(", ")));
        }
        if all_affected.len() > 20 {
            lines.push(format!("    ... and {} more", all_affected.len() - 20));
        }
    }

    lines.join("\n")
}

// ── risk ───────────────────────────────────────────────────────────

pub fn risk(graph: &Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap risk <git-ref>  (e.g. codemap risk HEAD~1, codemap risk main)".to_string();
    }
    if target.starts_with('-') {
        return format!("Invalid git ref: \"{target}\"");
    }

    let changed_files = match git_diff_name_only(graph, target) {
        GitDiffResult::Ok(files) => files,
        GitDiffResult::Error(e) => return e,
        GitDiffResult::Empty => return format!("No files changed since {target}."),
    };

    let relevant: Vec<String> = changed_files.iter()
        .filter(|f| graph.nodes.contains_key(f.as_str()))
        .cloned()
        .collect();

    if relevant.is_empty() {
        return format!("{} files changed but none in scanned source.", changed_files.len());
    }

    // --- Factor 1: Blast radius (0-30) ---
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
        for v in visited { all_affected.insert(v); }
    }
    let blast_pct = if graph.nodes.len() > 1 {
        all_affected.len() as f64 / (graph.nodes.len() - relevant.len()).max(1) as f64
    } else { 0.0 };
    let blast_score = if blast_pct <= 0.05 { 0 }
        else if blast_pct <= 0.15 { 5 }
        else if blast_pct <= 0.30 { 10 }
        else if blast_pct <= 0.50 { 20 }
        else { 30 };

    // --- Factor 2: Coupling (0-30) ---
    let total_coupling: usize = relevant.iter()
        .filter_map(|f| graph.nodes.get(f))
        .map(|n| n.imports.len() + n.imported_by.len())
        .sum();
    let avg_coupling = total_coupling as f64 / relevant.len().max(1) as f64;
    let coupling_score = if avg_coupling <= 1.0 { 0 }
        else if avg_coupling <= 3.0 { 5 }
        else if avg_coupling <= 5.0 { 10 }
        else if avg_coupling <= 8.0 { 20 }
        else { 30 };

    // --- Factor 3: Complexity of changed code (0-20) ---
    let mut high_complexity = 0usize;
    let mut total_fns = 0usize;
    for file in &relevant {
        if let Some(node) = graph.nodes.get(file) {
            for f in &node.functions {
                total_fns += 1;
                if f.calls.len() > 15 { high_complexity += 1; }
            }
        }
    }
    let complexity_ratio = if total_fns > 0 { high_complexity as f64 / total_fns as f64 } else { 0.0 };
    let complexity_score = if complexity_ratio <= 0.05 { 0 }
        else if complexity_ratio <= 0.15 { 5 }
        else if complexity_ratio <= 0.30 { 10 }
        else { 20 };

    // --- Factor 4: File count (0-20) ---
    let file_score = match relevant.len() {
        0..=2 => 0,
        3..=5 => 5,
        6..=10 => 10,
        11..=20 => 15,
        _ => 20,
    };

    let total_risk = blast_score + coupling_score + complexity_score + file_score;
    let level = match total_risk {
        0..=15 => "LOW",
        16..=35 => "MEDIUM",
        36..=60 => "HIGH",
        _ => "CRITICAL",
    };

    let bar = |score: usize, max: usize| -> String {
        let filled = (score * 15) / max;
        let empty = 15 - filled;
        format!("[{}{}] {}/{}", "\u{2588}".repeat(filled), "\u{2591}".repeat(empty), score, max)
    };

    let mut lines = vec![
        format!("=== Risk Assessment: {} — {}/100 ({}) ===", target, total_risk, level),
        String::new(),
        format!("  Blast radius    {}  {:.0}% of codebase affected", bar(blast_score, 30), blast_pct * 100.0),
        format!("  Coupling        {}  avg {:.1} connections/file", bar(coupling_score, 30), avg_coupling),
        format!("  Complexity      {}  {:.0}% high-complexity fns", bar(complexity_score, 20), complexity_ratio * 100.0),
        format!("  Scope           {}  {} files changed", bar(file_score, 20), relevant.len()),
        String::new(),
        "Changed files:".to_string(),
    ];
    let mut sorted = relevant.clone();
    sorted.sort();
    for f in &sorted {
        let coupling = graph.nodes.get(f).map(|n| n.imports.len() + n.imported_by.len()).unwrap_or(0);
        lines.push(format!("  {} (coupling: {})", f, coupling));
    }

    if !all_affected.is_empty() {
        lines.push(String::new());
        lines.push(format!("Blast radius: {} additional files affected", all_affected.len()));
    }

    lines.join("\n")
}

// ── git-coupling ───────────────────────────────────────────────────

pub fn git_coupling(graph: &Graph, target: &str) -> String {
    // How many commits to look back
    let commit_count = target.parse::<usize>().unwrap_or(200);

    let log_output = match Command::new("git")
        .args(["log", "--format=%H", "--name-only", &format!("-{}", commit_count)])
        .current_dir(&graph.scan_dir)
        .output()
    {
        Ok(r) if r.status.success() => String::from_utf8_lossy(&r.stdout).to_string(),
        _ => return "Failed to run git log. Make sure you're in a git repo.".to_string(),
    };

    // Parse: group files by commit hash
    let mut commits: Vec<Vec<String>> = Vec::new();
    let mut current: Vec<String> = Vec::new();

    for line in log_output.lines() {
        let line = line.trim();
        let is_separator = line.is_empty() || (line.len() == 40 && line.chars().all(|c| c.is_ascii_hexdigit()));
        if is_separator {
            if !current.is_empty() {
                commits.push(std::mem::take(&mut current));
            }
        } else if graph.nodes.contains_key(line) {
            current.push(line.to_string());
        }
    }
    if !current.is_empty() {
        commits.push(current);
    }

    if commits.is_empty() {
        return "No commits with source file changes found.".to_string();
    }

    // Count co-changes: for each commit, every pair of files changed together
    let mut pair_counts: HashMap<(String, String), usize> = HashMap::new();
    let mut file_counts: HashMap<String, usize> = HashMap::new();

    for commit_files in &commits {
        if commit_files.len() < 2 || commit_files.len() > 30 {
            // Skip single-file commits and huge merge commits
            continue;
        }
        for f in commit_files {
            *file_counts.entry(f.clone()).or_insert(0) += 1;
        }
        for i in 0..commit_files.len() {
            for j in (i + 1)..commit_files.len() {
                let a = &commit_files[i];
                let b = &commit_files[j];
                let key = if a < b { (a.clone(), b.clone()) } else { (b.clone(), a.clone()) };
                *pair_counts.entry(key).or_insert(0) += 1;
            }
        }
    }

    if pair_counts.is_empty() {
        return "No file co-changes found in recent history.".to_string();
    }

    // Calculate coupling strength: co_changes / min(changes_a, changes_b)
    struct CouplingResult {
        file_a: String,
        file_b: String,
        co_changes: usize,
        strength: f64,
    }

    let mut results: Vec<CouplingResult> = Vec::new();
    for ((a, b), co) in &pair_counts {
        if *co < 2 { continue; } // Need at least 2 co-changes
        let count_a = file_counts.get(a).copied().unwrap_or(1);
        let count_b = file_counts.get(b).copied().unwrap_or(1);
        let strength = *co as f64 / count_a.min(count_b) as f64;
        results.push(CouplingResult {
            file_a: a.clone(),
            file_b: b.clone(),
            co_changes: *co,
            strength,
        });
    }

    results.sort_by(|a, b| b.strength.partial_cmp(&a.strength).unwrap_or(std::cmp::Ordering::Equal));

    if results.is_empty() {
        return "No significant co-change patterns found.".to_string();
    }

    // Check which pairs are NOT connected by imports (hidden dependencies)
    let mut lines = vec![
        format!("=== Git Coupling: last {} commits ===", commit_count),
        format!("Commits analyzed: {}", commits.len()),
        String::new(),
        "  Strength  Co-changes  Link     Files".to_string(),
    ];

    for r in results.iter().take(25) {
        let short_a = r.file_a.rsplit('/').next().unwrap_or(&r.file_a);
        let short_b = r.file_b.rsplit('/').next().unwrap_or(&r.file_b);

        // Check if there's an import link between them
        let has_import = graph.nodes.get(&r.file_a)
            .map(|n| n.imports.contains(&r.file_b) || n.imported_by.contains(&r.file_b))
            .unwrap_or(false);
        let link = if has_import { "import" } else { "HIDDEN" };

        lines.push(format!(
            "    {:>4.0}%  {:>10}  {:>6}   {} <-> {}",
            r.strength * 100.0, r.co_changes, link, short_a, short_b,
        ));
    }

    if results.len() > 25 {
        lines.push(format!("  ... and {} more pairs", results.len() - 25));
    }

    let hidden_count = results.iter().take(25).filter(|r| {
        !graph.nodes.get(&r.file_a)
            .map(|n| n.imports.contains(&r.file_b) || n.imported_by.contains(&r.file_b))
            .unwrap_or(false)
    }).count();

    if hidden_count > 0 {
        lines.push(String::new());
        lines.push(format!("  {} HIDDEN dependencies — files co-change but have no import link.", hidden_count));
        lines.push("  These are the most dangerous: changes in one silently require changes in the other.".to_string());
    }

    lines.join("\n")
}

// ── clones ─────────────────────────────────────────────────────────

pub fn clones(graph: &Graph, _target: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // Fingerprint: (line_count, call_count, param_count, is_exported)
    // Group functions with identical fingerprints as structural clones
    let mut groups: HashMap<u64, Vec<(String, String, usize, usize)>> = HashMap::new();

    for (file_id, node) in &graph.nodes {
        for f in &node.functions {
            let line_count = if f.end_line > f.start_line { f.end_line - f.start_line + 1 } else { 1 };
            // Skip trivial functions (< 3 lines)
            if line_count < 3 { continue; }

            let param_count = f.parameters.as_ref().map(|p| p.len()).unwrap_or(0);
            let call_count = f.calls.len();

            let mut hasher = DefaultHasher::new();
            line_count.hash(&mut hasher);
            call_count.hash(&mut hasher);
            param_count.hash(&mut hasher);
            f.is_exported.hash(&mut hasher);
            let fingerprint = hasher.finish();

            groups.entry(fingerprint).or_default().push((
                file_id.clone(),
                f.name.clone(),
                f.start_line,
                line_count,
            ));
        }
    }

    // Filter to groups with 2+ members (actual clones)
    let mut clone_groups: Vec<Vec<(String, String, usize, usize)>> = groups
        .into_values()
        .filter(|g| g.len() >= 2)
        .collect();

    if clone_groups.is_empty() {
        return "No structural clones found.".to_string();
    }

    // Sort groups by size (largest clone groups first), then by line count
    clone_groups.sort_by(|a, b| {
        b.len().cmp(&a.len())
            .then_with(|| b[0].3.cmp(&a[0].3))
    });

    let total_clones: usize = clone_groups.iter().map(|g| g.len()).sum();
    let mut lines = vec![
        format!("=== Structural Clones: {} functions in {} groups ===", total_clones, clone_groups.len()),
        String::new(),
    ];

    for (i, group) in clone_groups.iter().take(20).enumerate() {
        let sample = &group[0];
        lines.push(format!(
            "  Group {} ({} clones, ~{} lines each):",
            i + 1, group.len(), sample.3,
        ));
        let mut sorted = group.clone();
        sorted.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.2.cmp(&b.2)));
        for (file, name, line, _) in sorted.iter().take(8) {
            let short = file.rsplit('/').next().unwrap_or(file);
            lines.push(format!("    {}:{}() L{}", short, name, line));
        }
        if group.len() > 8 {
            lines.push(format!("    ... and {} more", group.len() - 8));
        }
        lines.push(String::new());
    }
    if clone_groups.len() > 20 {
        lines.push(format!("  ... and {} more groups", clone_groups.len() - 20));
    }

    lines.join("\n")
}
