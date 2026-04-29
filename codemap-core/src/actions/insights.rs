use std::cmp::Reverse;
use std::collections::HashMap;
use std::path::Path;
use std::sync::LazyLock;
use regex::Regex;
use crate::types::{Graph, escape_regex};
use crate::utils::format_number;
use super::analysis::{circular, health};

// ── Static Regex Compilation ───────────────────────────────────────

static PY_TS_DECORATOR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"@(\w[\w.]*(?:\([^)]*\))?)").unwrap()
});
static RUST_ATTR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"#\[(\w[\w:]*(?:\([^)]*\))?)\]").unwrap()
});
static NEXT_DEF_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:pub\s+)?(?:async\s+)?(?:fn|def|function|class|struct|enum|interface|const)\s+(\w+)").unwrap()
});

// ── summary ────────────────────────────────────────────────────────

pub fn summary(graph: &mut Graph) -> String {
    let file_count = graph.nodes.len();
    if file_count == 0 {
        return "No files to analyze.".to_string();
    }

    let mut total_lines: usize = 0;
    let mut total_functions: usize = 0;
    let mut total_exports: usize = 0;
    let mut exts: HashMap<String, usize> = HashMap::new();
    for (id, node) in &graph.nodes {
        total_lines += node.lines;
        total_functions += node.functions.len();
        total_exports += node.exports.len();
        let ext = match id.rfind('.') {
            Some(i) if i < id.len() - 1 => id[i..].to_string(),
            _ => String::new(),
        };
        *exts.entry(ext).or_insert(0) += 1;
    }
    let mut ext_vec: Vec<(String, usize)> = exts.into_iter().collect();
    ext_vec.sort_by_key(|a| Reverse(a.1));
    let lang_summary: String = ext_vec.iter().take(5)
        .map(|(e, c)| format!("{} {}", c, e))
        .collect::<Vec<_>>()
        .join(", ");

    let health_text = health(graph);
    let score_line = health_text.lines().next().unwrap_or("");

    let mut complex: Vec<(String, String, usize)> = Vec::new();
    for node in graph.nodes.values() {
        for f in &node.functions {
            complex.push((node.id.clone(), f.name.clone(), f.calls.len()));
        }
    }
    complex.sort_by_key(|a| Reverse(a.2));

    let circ_text = circular(graph);
    let circ_count = if circ_text.starts_with("No circular") { 0usize }
        else { circ_text.lines().next().and_then(|l| l.split_whitespace().next()).and_then(|n| n.parse().ok()).unwrap_or(0) };

    let mut coupling: Vec<(&String, usize)> = graph.nodes.iter()
        .map(|(id, n)| (id, n.imports.len() + n.imported_by.len()))
        .collect();
    coupling.sort_by_key(|a| Reverse(a.1));

    let mut lines = vec![
        format!("\u{250c}\u{2500}\u{2500} {} \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}", score_line.replace("=== ", "").replace(" ===", "")),
        "\u{2502}".to_string(),
        format!("\u{2502}  {} files, {} lines, {} functions, {} exports", format_number(file_count), format_number(total_lines), format_number(total_functions), total_exports),
        format!("\u{2502}  Languages: {}", lang_summary),
        format!("\u{2502}  Circular deps: {}", circ_count),
        "\u{2502}".to_string(),
    ];

    lines.push("\u{2502}  \u{2500}\u{2500} Hottest files (most coupled) \u{2500}\u{2500}".to_string());
    for (id, c) in coupling.iter().take(5) {
        lines.push(format!("\u{2502}    {:>3} connections  {}", c, id));
    }
    lines.push("\u{2502}".to_string());

    lines.push("\u{2502}  \u{2500}\u{2500} Most complex functions \u{2500}\u{2500}".to_string());
    for (file, name, calls) in complex.iter().take(5) {
        let short = file.rsplit('/').next().unwrap_or(file);
        lines.push(format!("\u{2502}    {:>3} calls  {}:{}", calls, short, name));
    }

    lines.push("\u{2502}".to_string());
    lines.push("\u{2514}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}".to_string());

    lines.join("\n")
}

// ── decorators ─────────────────────────────────────────────────────

pub fn decorators(graph: &Graph, target: &str) -> String {
    if target.is_empty() {
        return "Usage: codemap decorators <pattern>  (e.g. codemap decorators test, codemap decorators route)".to_string();
    }

    let dir = &graph.scan_dir;
    let pattern = target.to_lowercase();


    struct Hit { file: String, line: usize, decorator: String, symbol: String }

    let mut hits: Vec<Hit> = Vec::new();
    let mut ids: Vec<String> = graph.nodes.keys().cloned().collect();
    ids.sort();

    for id in &ids {
        let path = Path::new(dir).join(id);
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let lines_vec: Vec<&str> = content.lines().collect();

        for (i, line) in lines_vec.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with('@') {
                if let Some(caps) = PY_TS_DECORATOR_RE.captures(trimmed) {
                    let dec = caps[1].to_string();
                    if !dec.to_lowercase().contains(&pattern) { continue; }
                    let mut sym = String::new();
                    for next_line in lines_vec.iter().skip(i + 1).take(4) {
                        if let Some(sc) = NEXT_DEF_RE.captures(next_line) {
                            sym = sc[1].to_string();
                            break;
                        }
                    }
                    hits.push(Hit { file: id.clone(), line: i + 1, decorator: format!("@{}", dec),
                        symbol: if sym.is_empty() { "?".into() } else { sym } });
                }
            }

            if trimmed.starts_with("#[") {
                if let Some(caps) = RUST_ATTR_RE.captures(trimmed) {
                    let attr = caps[1].to_string();
                    if !attr.to_lowercase().contains(&pattern) { continue; }
                    let mut sym = String::new();
                    for next_line in lines_vec.iter().skip(i + 1).take(4) {
                        if let Some(sc) = NEXT_DEF_RE.captures(next_line) {
                            sym = sc[1].to_string();
                            break;
                        }
                    }
                    hits.push(Hit { file: id.clone(), line: i + 1, decorator: format!("#[{}]", attr),
                        symbol: if sym.is_empty() { "?".into() } else { sym } });
                }
            }
        }
    }

    if hits.is_empty() {
        return format!("No decorators matching \"{}\" found.", target);
    }

    let mut out = vec![
        format!("=== Decorators matching \"{}\" ({} found) ===", target, hits.len()),
        String::new(),
    ];
    let mut last_file = "";
    for h in &hits {
        if h.file != last_file {
            out.push(format!("  {}:", h.file));
            last_file = &h.file;
        }
        out.push(format!("    L{}  {} on {}()", h.line, h.decorator, h.symbol));
    }
    out.join("\n")
}

// ── rename ─────────────────────────────────────────────────────────

pub fn rename(graph: &Graph, target: &str) -> String {
    let parts: Vec<&str> = target.split_whitespace().collect();
    if parts.len() < 2 {
        return "Usage: codemap rename <old_name> <new_name>".to_string();
    }
    let (old_name, new_name) = (parts[0], parts[1]);

    let dir = &graph.scan_dir;
    let pattern = format!(r"\b{}\b", escape_regex(old_name));
    let re = match Regex::new(&pattern) {
        Ok(r) => r,
        Err(_) => return format!("Invalid symbol name: {}", old_name),
    };

    struct RenameHit { file: String, line: usize, before: String, after: String }

    let mut hits: Vec<RenameHit> = Vec::new();
    let mut file_count = 0usize;
    let mut ids: Vec<String> = graph.nodes.keys().cloned().collect();
    ids.sort();

    for id in &ids {
        let path = Path::new(dir).join(id);
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let mut file_had_hit = false;
        for (i, line) in content.lines().enumerate() {
            if re.is_match(line) {
                let before = line.trim().to_string();
                let after = re.replace_all(line.trim(), new_name).to_string();
                if before != after {
                    if !file_had_hit { file_count += 1; file_had_hit = true; }
                    hits.push(RenameHit {
                        file: id.clone(), line: i + 1,
                        before: if before.len() > 80 { format!("{}...", &before[..77]) } else { before },
                        after: if after.len() > 80 { format!("{}...", &after[..77]) } else { after },
                    });
                }
            }
        }
    }

    if hits.is_empty() {
        return format!("\"{}\" not found in any scanned file.", old_name);
    }

    let mut out = vec![
        format!("=== Rename Preview: {} \u{2192} {} ===", old_name, new_name),
        format!("{} occurrences in {} files", hits.len(), file_count),
        String::new(),
    ];

    let mut last_file = "";
    for h in hits.iter().take(50) {
        if h.file != last_file {
            out.push(format!("  {}:", h.file));
            last_file = &h.file;
        }
        out.push(format!("    L{:<4} - {}", h.line, h.before));
        out.push(format!("    L{:<4} + {}", h.line, h.after));
    }
    if hits.len() > 50 {
        out.push(format!("  ... and {} more occurrences", hits.len() - 50));
    }

    out.push(String::new());
    out.push("This is a preview only \u{2014} no files were modified.".to_string());
    out.join("\n")
}

// ── context ────────────────────────────────────────────────────────

pub fn context(graph: &Graph, target: &str) -> String {
    let budget: usize = if target.is_empty() {
        8000
    } else if let Some(k) = target.strip_suffix('k') {
        k.parse::<usize>().unwrap_or(8) * 1000
    } else {
        target.parse().unwrap_or(8000)
    };

    if graph.nodes.is_empty() {
        return "No files to map.".to_string();
    }

    // PageRank
    let d: f64 = 0.85;
    let n = graph.nodes.len();
    let ids: Vec<String> = graph.nodes.keys().cloned().collect();
    let mut scores: HashMap<String, f64> = HashMap::new();
    let init = 1.0 / n as f64;
    for id in &ids { scores.insert(id.clone(), init); }

    for _ in 0..20 {
        let mut new_scores: HashMap<String, f64> = HashMap::new();
        let mut dangling_sum: f64 = 0.0;
        for (id, node) in &graph.nodes {
            if node.imports.iter().all(|i| !graph.nodes.contains_key(i)) {
                dangling_sum += scores.get(id).copied().unwrap_or(0.0);
            }
        }
        let base = (1.0 - d) / n as f64 + d * dangling_sum / n as f64;
        for id in &ids { new_scores.insert(id.clone(), base); }
        for (id, node) in &graph.nodes {
            let local: Vec<&String> = node.imports.iter().filter(|i| graph.nodes.contains_key(*i)).collect();
            if local.is_empty() { continue; }
            let share = scores.get(id).copied().unwrap_or(0.0) / local.len() as f64;
            for imp in local { *new_scores.entry(imp.clone()).or_insert(0.0) += d * share; }
        }
        scores = new_scores;
    }

    let mut ranked: Vec<(String, f64)> = ids.iter()
        .map(|id| (id.clone(), scores.get(id).copied().unwrap_or(0.0)))
        .collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    // Build context fitting within token budget (1 token ≈ 4 chars)
    let mut out = Vec::new();
    let mut chars_used: usize = 0;
    let char_budget = budget * 4;
    let mut files_included = 0usize;
    let mut fns_included = 0usize;

    for (file_id, _score) in &ranked {
        let node = match graph.nodes.get(file_id) {
            Some(n) => n,
            None => continue,
        };

        let imports_str = if node.imports.is_empty() {
            String::new()
        } else {
            let short_imports: Vec<&str> = node.imports.iter()
                .filter(|i| graph.nodes.contains_key(*i))
                .map(|i| i.rsplit('/').next().unwrap_or(i))
                .collect();
            if short_imports.is_empty() { String::new() }
            else { format!(" \u{2192} {}", short_imports.join(", ")) }
        };

        let header = format!("{}  ({} lines{})", file_id, node.lines, imports_str);
        if chars_used + header.len() + 1 > char_budget { break; }
        out.push(header.clone());
        chars_used += header.len() + 1;
        files_included += 1;

        let mut fns = node.functions.clone();
        fns.sort_by_key(|f| f.start_line);
        for f in &fns {
            let params = f.parameters.as_ref().map(|p| p.join(", ")).unwrap_or_default();
            let vis = if f.is_exported { "pub " } else { "" };
            let sig = format!("  L{} {}{}({})", f.start_line, vis, f.name, params);
            if chars_used + sig.len() + 1 > char_budget { break; }
            out.push(sig.clone());
            chars_used += sig.len() + 1;
            fns_included += 1;
        }
    }

    let tokens_est = chars_used / 4;
    let mut result = vec![
        format!("// codemap context: {} files, {} functions, ~{} tokens (budget: {})",
            files_included, fns_included, tokens_est, budget),
    ];
    result.extend(out);
    result.join("\n")
}
